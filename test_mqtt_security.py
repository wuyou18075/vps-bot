import base64
import hashlib
import hmac
import io
import json
import os
import subprocess
import tempfile
import time
import unittest
from unittest import mock

import mqtt_agent
import mqtt_master


class MqttSecurityTest(unittest.TestCase):
  def test_totp_verification_accepts_current_code(self):
    secret = mqtt_master.generate_totp_secret()
    now = 1800000000
    code = mqtt_master.generate_totp_code(secret, now=now)

    self.assertTrue(mqtt_master.verify_totp(secret, code, now=now))
    self.assertFalse(mqtt_master.verify_totp(secret, "000000", now=now))

  def test_password_hash_does_not_store_plaintext(self):
    encoded = mqtt_master.hash_password("correct horse battery staple", salt=b"1" * 16)

    self.assertNotIn("correct", encoded)
    self.assertTrue(mqtt_master.verify_password("correct horse battery staple", encoded))
    self.assertFalse(mqtt_master.verify_password("wrong", encoded))

  def test_login_rate_limiter_locks_after_five_failures(self):
    limiter = mqtt_master.LoginRateLimiter(limit=5, window_seconds=900)
    for _ in range(5):
      self.assertTrue(limiter.allow("1.2.3.4", "admin"))
      limiter.record_failure("1.2.3.4", "admin")

    self.assertFalse(limiter.allow("1.2.3.4", "admin"))
    self.assertTrue(limiter.allow("1.2.3.5", "admin"))

  def test_registration_token_is_one_time_and_expires(self):
    store = mqtt_master.RegistrationStore()
    token = store.create_token(ttl_seconds=60, now=1000)

    self.assertTrue(store.consume_token(token, now=1020))
    self.assertFalse(store.consume_token(token, now=1021))

    expired = store.create_token(ttl_seconds=10, now=1000)
    self.assertFalse(store.consume_token(expired, now=1011))

  def test_registration_token_can_be_retried_after_backend_failure(self):
    with tempfile.TemporaryDirectory() as temp_dir:
      db = mqtt_master.MasterDatabase(os.path.join(temp_dir, "master.db"))
      token = db.create_registration_token()

      self.assertTrue(db.consume_registration_token(token))
      db.release_registration_token(token)

      self.assertTrue(db.consume_registration_token(token))

  def test_registration_token_stays_used_after_success(self):
    with tempfile.TemporaryDirectory() as temp_dir:
      db = mqtt_master.MasterDatabase(os.path.join(temp_dir, "master.db"))
      token = db.create_registration_token()

      self.assertTrue(db.consume_registration_token(token))

      self.assertFalse(db.consume_registration_token(token))

  def test_acl_limits_agent_to_own_topics(self):
    acl = mqtt_master.render_mosquitto_acl("vps-bot", [
      {"node_id": "node-a", "mqtt_username": "vps_node_a"},
      {"node_id": "node-b", "mqtt_username": "vps_node_b"},
    ])

    self.assertIn("user vps_node_a", acl)
    self.assertIn("topic read vps-bot/commands/node-a", acl)
    self.assertIn("topic write vps-bot/nodes/node-a/status", acl)
    self.assertIn("topic write vps-bot/results/node-a", acl)
    self.assertIn("topic write vps-bot/health/node-a", acl)
    self.assertNotIn("topic read vps-bot/commands/node-b\nuser vps_node_a", acl)
    self.assertIn("user vps_master", acl)
    self.assertIn("topic readwrite vps-bot/#", acl)

  def test_agent_rejects_unsigned_or_tampered_commands(self):
    secret = base64.urlsafe_b64encode(b"node command secret").decode("ascii")
    payload = {
      "id": "cmd-1",
      "command": "/status",
      "ts": 1800000000,
    }
    signed = mqtt_master.sign_command(payload, secret)

    self.assertTrue(mqtt_agent.verify_command_signature(signed, secret, now=1800000010))

    tampered = dict(signed)
    tampered["command"] = "/speed"
    self.assertFalse(mqtt_agent.verify_command_signature(tampered, secret, now=1800000010))

    old = dict(signed)
    old["ts"] = 1700000000
    old["sig"] = mqtt_master.command_signature(old, secret)
    self.assertFalse(mqtt_agent.verify_command_signature(old, secret, now=1800000010))

  def test_agent_allows_only_whitelisted_commands(self):
    self.assertEqual(["status", []], mqtt_agent.parse_allowed_command("/status"))
    self.assertEqual(["ping", ["1.1.1.1"]], mqtt_agent.parse_allowed_command("/ping 1.1.1.1"))

    with self.assertRaises(ValueError):
      mqtt_agent.parse_allowed_command("/reboot")
    with self.assertRaises(ValueError):
      mqtt_agent.parse_allowed_command("rm -rf /")

  def test_master_database_registers_node_with_unique_credentials(self):
    with tempfile.TemporaryDirectory() as temp_dir:
      db_path = os.path.join(temp_dir, "master.db")
      db = mqtt_master.MasterDatabase(db_path)
      first = db.register_node("test7")
      second = db.register_node("taiwan")

    self.assertNotEqual(first["node_id"], second["node_id"])
    self.assertNotEqual(first["mqtt_username"], second["mqtt_username"])
    self.assertNotEqual(first["mqtt_password"], second["mqtt_password"])
    self.assertNotEqual(first["command_secret"], second["command_secret"])

  def test_create_admin_user_stores_hashed_password(self):
    with tempfile.TemporaryDirectory() as temp_dir:
      db_path = os.path.join(temp_dir, "master.db")
      mqtt_master.create_admin_user(db_path, "admin", "pw")
      db = mqtt_master.MasterDatabase(db_path)
      user = db.get_user("admin")

    self.assertIsNotNone(user)
    self.assertNotEqual("pw", user["password_hash"])
    self.assertTrue(mqtt_master.verify_password("pw", user["password_hash"]))

  def test_create_admin_user_updates_existing_password(self):
    with tempfile.TemporaryDirectory() as temp_dir:
      db_path = os.path.join(temp_dir, "master.db")
      mqtt_master.create_admin_user(db_path, "admin", "old")
      mqtt_master.create_admin_user(db_path, "admin", "new")
      db = mqtt_master.MasterDatabase(db_path)
      user = db.get_user("admin")

    self.assertFalse(mqtt_master.verify_password("old", user["password_hash"]))
    self.assertTrue(mqtt_master.verify_password("new", user["password_hash"]))

  def test_create_admin_user_rejects_one_character_password(self):
    with tempfile.TemporaryDirectory() as temp_dir:
      db_path = os.path.join(temp_dir, "master.db")

      with self.assertRaises(ValueError):
        mqtt_master.create_admin_user(db_path, "admin", "p")

  def test_mqtt_script_restarts_and_checks_mosquitto_after_master_setup(self):
    with open("mqtt.sh", "r", encoding="utf-8") as file:
      script = file.read()

    setup_body = script.split("setup_master() {", 1)[1].split("deploy_web()", 1)[0]

    self.assertIn("systemctl restart mosquitto", setup_body)
    self.assertIn("check_mqtt_health", setup_body)

  def test_mqtt_script_stops_old_agent_before_reinstalling(self):
    with open("mqtt.sh", "r", encoding="utf-8") as file:
      script = file.read()

    register_body = script.split("register_agent() {", 1)[1].split("handle_choice()", 1)[0]

    self.assertLess(register_body.index("systemctl stop"), register_body.index("install_project_files"))

  def test_save_runtime_settings_to_database(self):
    with tempfile.TemporaryDirectory() as temp_dir:
      db_path = os.path.join(temp_dir, "master.db")
      mqtt_master.save_runtime_settings(db_path, {
        "PUBLIC_URL": "http://1.2.3.4:8088",
        "WEB_PORT": "8088",
      })
      db = mqtt_master.MasterDatabase(db_path)

      self.assertEqual("http://1.2.3.4:8088", db.get_setting("PUBLIC_URL"))
      self.assertEqual("8088", db.get_setting("WEB_PORT"))

  def test_telegram_nodes_lists_registered_vps(self):
    with tempfile.TemporaryDirectory() as temp_dir:
      db = mqtt_master.MasterDatabase(os.path.join(temp_dir, "master.db"))
      db.register_node("test7")

      response = mqtt_master.handle_telegram_text(db, {}, "/nodes")

    self.assertIn("test7", response)

  def test_telegram_select_updates_scope(self):
    with tempfile.TemporaryDirectory() as temp_dir:
      db = mqtt_master.MasterDatabase(os.path.join(temp_dir, "master.db"))
      db.register_node("test7")
      db.register_node("taiwan")

      menu = mqtt_master.handle_telegram_text(db, {}, "/select")
      response = mqtt_master.handle_telegram_text(db, {}, "1")

    self.assertIn("1 test7", menu)
    self.assertEqual("已选择: test7", response)

  def test_telegram_command_dispatches_to_selected_nodes(self):
    with tempfile.TemporaryDirectory() as temp_dir:
      db = mqtt_master.MasterDatabase(os.path.join(temp_dir, "master.db"))
      first = db.register_node("test7")
      db.register_node("taiwan")
      db.set_setting("telegram_selected_nodes", first["node_id"])

      with mock.patch("mqtt_master.publish_mqtt") as publish:
        response = mqtt_master.handle_telegram_text(db, {
          "MQTT_HOST": "127.0.0.1",
          "MQTT_MASTER_PASSWORD": "secret",
          "MQTT_TOPIC_PREFIX": "vps-bot",
        }, "/status")

    self.assertEqual("已发送 /status 到: test7", response)
    self.assertEqual(1, publish.call_count)
    self.assertIn(f"vps-bot/commands/{first['node_id']}", publish.call_args.args[1])

  def test_response_version_string_does_not_crash(self):
    handler = object.__new__(mqtt_master.MasterRequestHandler)

    version = handler.version_string()

    self.assertIn("VpsMqttMaster", version)

  def test_session_cookie_omits_secure_on_plain_http(self):
    handler = object.__new__(mqtt_master.MasterRequestHandler)
    handler.headers = {"X-Forwarded-Proto": "http"}

    cookie = handler.build_session_cookie("session-token")

    self.assertIn("HttpOnly", cookie)
    self.assertNotIn("; Secure", cookie)

  def test_session_cookie_keeps_secure_on_https(self):
    handler = object.__new__(mqtt_master.MasterRequestHandler)
    handler.headers = {"X-Forwarded-Proto": "https"}

    cookie = handler.build_session_cookie("session-token")

    self.assertIn("; Secure", cookie)

  def test_totp_page_contains_local_qr_image(self):
    handler = object.__new__(mqtt_master.MasterRequestHandler)

    with mock.patch("mqtt_master.generate_totp_secret", return_value="ABCDEF234567"):
      with mock.patch("mqtt_master.qr_svg_data_uri", return_value="data:image/svg+xml;base64,abc"):
        html = handler.render_totp("cj")

    self.assertIn("data:image/svg+xml;base64,abc", html)
    self.assertIn("otpauth://totp/vps-mqtt:cj", html)
    self.assertNotIn("chart.googleapis.com", html)
    self.assertNotIn("api.qrserver.com", html)

  def test_qr_svg_data_uri_uses_local_qrencode(self):
    svg = b"<svg></svg>"
    with mock.patch("mqtt_master.subprocess.run") as run:
      run.return_value = type("Result", (), {
        "returncode": 0,
        "stdout": svg,
      })()

      uri = mqtt_master.qr_svg_data_uri("otpauth://example")

    self.assertTrue(uri.startswith("data:image/svg+xml;base64,"))
    self.assertIn("qrencode", run.call_args.args[0][0])

  def test_telegram_save_requires_current_password(self):
    with tempfile.TemporaryDirectory() as temp_dir:
      db = mqtt_master.MasterDatabase(os.path.join(temp_dir, "master.db"))
      db.create_admin("admin", "pw")

      ok, message = mqtt_master.save_telegram_settings(
        db,
        "admin",
        {
          "token": "123:abc",
          "chat_id": "456",
          "current_password": "bad",
        },
      )

    self.assertFalse(ok)
    self.assertIn("登录密码错误", message)

  def test_telegram_save_sends_test_message_and_persists(self):
    with tempfile.TemporaryDirectory() as temp_dir:
      db = mqtt_master.MasterDatabase(os.path.join(temp_dir, "master.db"))
      db.create_admin("admin", "pw")

      with mock.patch("mqtt_master.send_telegram_test", return_value=True) as send:
        ok, message = mqtt_master.save_telegram_settings(
          db,
          "admin",
          {
            "token": "123:abc",
            "chat_id": "456",
            "current_password": "pw",
          },
        )

      self.assertTrue(ok)
      self.assertIn("Telegram 绑定成功", message)
      self.assertEqual("123:abc", db.get_setting("telegram_token"))
      self.assertEqual("456", db.get_setting("telegram_chat_id"))
      send.assert_called_once_with("123:abc", "456")

  def test_create_registration_command_for_web_uses_db_token(self):
    with tempfile.TemporaryDirectory() as temp_dir:
      db = mqtt_master.MasterDatabase(os.path.join(temp_dir, "master.db"))
      command = mqtt_master.create_registration_command_for_web(
        db,
        {
          "PUBLIC_URL": "http://1.2.3.4:8088",
          "RAW_BASE_URL": "https://raw.example.com",
        },
        "hk",
      )

    self.assertIn("mqtt.sh", command)
    self.assertIn("--master-url 'http://1.2.3.4:8088'", command)
    self.assertIn("--node-name 'hk'", command)

  def test_node_actions_can_mark_offline_and_delete(self):
    with tempfile.TemporaryDirectory() as temp_dir:
      db = mqtt_master.MasterDatabase(os.path.join(temp_dir, "master.db"))
      node = db.register_node("test7")

      message = mqtt_master.handle_node_action(db, {}, node["node_id"], "offline")
      self.assertIn("已标记离线", message)
      self.assertEqual("offline", db.list_nodes()[0]["status"])

      message = mqtt_master.handle_node_action(db, {}, node["node_id"], "delete")
      self.assertIn("已删除", message)
      self.assertEqual([], db.list_nodes())

  def test_theme_setting_accepts_supported_themes_only(self):
    with tempfile.TemporaryDirectory() as temp_dir:
      db = mqtt_master.MasterDatabase(os.path.join(temp_dir, "master.db"))

      self.assertTrue(mqtt_master.save_theme(db, "dark"))
      self.assertFalse(mqtt_master.save_theme(db, "pink"))

      self.assertEqual("dark", db.get_setting("web_theme"))

  def test_telegram_delete_requires_current_password(self):
    with tempfile.TemporaryDirectory() as temp_dir:
      db = mqtt_master.MasterDatabase(os.path.join(temp_dir, "master.db"))
      db.create_admin("admin", "pw")
      db.set_setting("telegram_token", "123:abc")
      db.set_setting("telegram_chat_id", "456")

      ok, message = mqtt_master.delete_telegram_settings(db, "admin", "bad")

      self.assertFalse(ok)
      self.assertIn("登录密码错误", message)
      self.assertEqual("123:abc", db.get_setting("telegram_token"))

  def test_telegram_delete_clears_binding_after_password_check(self):
    with tempfile.TemporaryDirectory() as temp_dir:
      db = mqtt_master.MasterDatabase(os.path.join(temp_dir, "master.db"))
      db.create_admin("admin", "pw")
      db.set_setting("telegram_token", "123:abc")
      db.set_setting("telegram_chat_id", "456")

      ok, message = mqtt_master.delete_telegram_settings(db, "admin", "pw")

      self.assertTrue(ok)
      self.assertIn("已删除", message)
      self.assertEqual("", db.get_setting("telegram_token"))
      self.assertEqual("", db.get_setting("telegram_chat_id"))

  def test_node_profile_edit_persists_monitoring_fields(self):
    with tempfile.TemporaryDirectory() as temp_dir:
      db = mqtt_master.MasterDatabase(os.path.join(temp_dir, "master.db"))
      node = db.register_node("test7")

      ok, message = mqtt_master.update_node_profile(db, node["node_id"], {
        "name": "台湾",
        "group_name": "asia",
        "sort_order": "7",
        "traffic_total_gb": "500",
        "traffic_alert_percent": "80",
        "daily_report_time": "22:00:00",
        "monthly_report_time": "01 00:00:00",
      })

      self.assertTrue(ok)
      self.assertIn("已保存", message)
      saved = db.list_nodes()[0]
      self.assertEqual("台湾", saved["name"])
      self.assertEqual("asia", saved["group_name"])
      self.assertEqual(7, saved["sort_order"])
      self.assertEqual(500.0, saved["traffic_total_gb"])
      self.assertEqual(80.0, saved["traffic_alert_percent"])
      self.assertEqual("22:00:00", saved["daily_report_time"])
      self.assertEqual("01 00:00:00", saved["monthly_report_time"])

  def test_store_command_result_persists_snapshot_metrics(self):
    with tempfile.TemporaryDirectory() as temp_dir:
      db = mqtt_master.MasterDatabase(os.path.join(temp_dir, "master.db"))
      node = db.register_node("test7")

      db.store_command_result({
        "id": "cmd-1",
        "node_id": node["node_id"],
        "name": "test7",
        "command": "snapshot",
        "ok": True,
        "text": "ok",
        "metrics": {
          "monthly_used_gb": 12.5,
          "daily_used_gb": 1.25,
          "network_rx_mbps": 8.1,
          "network_tx_mbps": 2.4,
          "cpu_percent": 13.2,
          "memory_percent": 44.1,
          "latency_ms": 31.0,
        },
        "ts": 1800000000,
      })

      snapshot = db.latest_node_snapshots()[0]

    self.assertEqual("test7", snapshot["name"])
    self.assertEqual(12.5, snapshot["monthly_used_gb"])
    self.assertEqual(1.25, snapshot["daily_used_gb"])
    self.assertEqual(31.0, snapshot["latency_ms"])

  def test_store_command_result_marks_node_online(self):
    with tempfile.TemporaryDirectory() as temp_dir:
      db = mqtt_master.MasterDatabase(os.path.join(temp_dir, "master.db"))
      node = db.register_node("test7")

      db.store_command_result({
        "id": "cmd-1",
        "node_id": node["node_id"],
        "command": "status",
        "ok": True,
        "text": "ok",
        "ts": 1800000000,
      })
      updated = db.list_nodes()[0]

    self.assertEqual("online", updated["status"])
    self.assertEqual(1800000000, updated["last_seen"])

  def test_request_snapshot_dispatches_to_online_nodes_only(self):
    with tempfile.TemporaryDirectory() as temp_dir:
      db = mqtt_master.MasterDatabase(os.path.join(temp_dir, "master.db"))
      first = db.register_node("online")
      second = db.register_node("offline")
      db.update_node_status(first["node_id"], "online", "1.1.1.1")
      db.update_node_status(second["node_id"], "offline", "2.2.2.2")

      with mock.patch("mqtt_master.dispatch_command") as dispatch:
        message = mqtt_master.request_snapshot(db, {}, online_only=True)

    self.assertIn("1 台", message)
    dispatch.assert_called_once_with(db, {}, first["node_id"], "/snapshot")

  def test_request_snapshot_can_dispatch_to_all_nodes_for_recovery(self):
    with tempfile.TemporaryDirectory() as temp_dir:
      db = mqtt_master.MasterDatabase(os.path.join(temp_dir, "master.db"))
      first = db.register_node("online")
      second = db.register_node("offline")
      db.update_node_status(first["node_id"], "online", "1.1.1.1")
      db.update_node_status(second["node_id"], "offline", "2.2.2.2")

      with mock.patch("mqtt_master.dispatch_command") as dispatch:
        message = mqtt_master.request_snapshot(db, {}, online_only=False)

    self.assertIn("2 台", message)
    self.assertEqual(2, dispatch.call_count)

  def test_monitor_page_shows_online_nodes_without_snapshot(self):
    with tempfile.TemporaryDirectory() as temp_dir:
      db = mqtt_master.MasterDatabase(os.path.join(temp_dir, "master.db"))
      node = db.register_node("online")
      db.update_node_status(node["node_id"], "online", "1.1.1.1")
      handler = object.__new__(mqtt_master.MasterRequestHandler)
      handler.server = type("Server", (), {"db": db, "config": {}})()

      html = handler.render_monitor("admin")

    self.assertIn("online", html)
    self.assertIn("暂无", html)

  def test_monitor_page_shows_offline_registered_nodes_for_diagnostics(self):
    with tempfile.TemporaryDirectory() as temp_dir:
      db = mqtt_master.MasterDatabase(os.path.join(temp_dir, "master.db"))
      node = db.register_node("offline")
      db.update_node_status(node["node_id"], "offline", "")
      handler = object.__new__(mqtt_master.MasterRequestHandler)
      handler.server = type("Server", (), {"db": db, "config": {}})()

      html = handler.render_monitor("admin")

    self.assertIn("offline", html)
    self.assertIn("暂无", html)

  def test_monitor_page_uses_websocket_realtime_only(self):
    with tempfile.TemporaryDirectory() as temp_dir:
      db = mqtt_master.MasterDatabase(os.path.join(temp_dir, "master.db"))
      handler = object.__new__(mqtt_master.MasterRequestHandler)
      handler.server = type("Server", (), {"db": db, "config": {}})()

      html = handler.render_monitor("admin")

    self.assertIn("WebSocket", html)
    self.assertIn("/ws/monitor", html)
    self.assertIn("ws-state", html)
    self.assertIn("last-refresh", html)
    self.assertIn('value="3"', html)
    self.assertIn("实时监控", html)
    self.assertNotIn("获取快照", html)
    self.assertNotIn('action="/snapshot"', html)

  def test_monitor_page_shows_data_and_heartbeat_times(self):
    with tempfile.TemporaryDirectory() as temp_dir:
      db = mqtt_master.MasterDatabase(os.path.join(temp_dir, "master.db"))
      node = db.register_node("test7")
      db.update_node_status(node["node_id"], "online", "1.1.1.1")
      handler = object.__new__(mqtt_master.MasterRequestHandler)
      handler.server = type("Server", (), {"db": db, "config": {}})()

      html = handler.render_monitor("admin")

    self.assertIn("数据", html)
    self.assertIn("心跳", html)

  def test_monitor_page_uses_remembered_minutes(self):
    with tempfile.TemporaryDirectory() as temp_dir:
      db = mqtt_master.MasterDatabase(os.path.join(temp_dir, "master.db"))
      db.set_setting("monitor_minutes", "7")
      handler = object.__new__(mqtt_master.MasterRequestHandler)
      handler.server = type("Server", (), {"db": db, "config": {}})()

      html = handler.render_monitor("admin")

    self.assertIn('value="7"', html)

  def test_monitor_payload_contains_nodes_and_state(self):
    with tempfile.TemporaryDirectory() as temp_dir:
      db = mqtt_master.MasterDatabase(os.path.join(temp_dir, "master.db"))
      node = db.register_node("test7")
      db.update_node_status(node["node_id"], "online", "1.1.1.1")
      db.store_command_result({
        "id": "cmd-1",
        "node_id": node["node_id"],
        "command": "snapshot",
        "ok": True,
        "text": "ok",
        "metrics": {
          "monthly_used_gb": 2,
          "daily_used_gb": 0.2,
          "network_rx_mbps": 3,
          "network_tx_mbps": 1,
          "cpu_percent": 20,
          "memory_percent": 30,
          "latency_ms": 40,
        },
        "ts": 1800000000,
      })

      payload = mqtt_master.monitor_payload(db)

    self.assertEqual("未运行", payload["monitor_state"])
    self.assertEqual("test7", payload["nodes"][0]["name"])
    self.assertEqual("online", payload["nodes"][0]["status"])
    self.assertEqual("1.1.1.1", payload["nodes"][0]["public_ip"])
    self.assertGreater(payload["nodes"][0]["last_seen"], 0)
    self.assertEqual(2.0, payload["nodes"][0]["monthly_used_gb"])

  def test_register_replaces_existing_node_from_same_agent(self):
    with tempfile.TemporaryDirectory() as temp_dir:
      db = mqtt_master.MasterDatabase(os.path.join(temp_dir, "master.db"))
      old = db.register_node("old")

      with mock.patch("mqtt_master.refresh_mqtt_auth", return_value=(True, "")):
        with mock.patch("mqtt_master.verify_node_mqtt_auth", return_value=(True, "")):
          new = mqtt_master.register_node_from_agent(db, {}, {
            "name": "new",
            "existing_node_id": old["node_id"],
          })

      nodes = db.list_nodes()

    self.assertEqual([new["node_id"]], [node["node_id"] for node in nodes])
    self.assertEqual("new", nodes[0]["name"])

  def test_register_node_fails_when_mqtt_refresh_fails(self):
    with tempfile.TemporaryDirectory() as temp_dir:
      db = mqtt_master.MasterDatabase(os.path.join(temp_dir, "master.db"))

      with mock.patch("mqtt_master.refresh_mqtt_auth", return_value=(False, "boom")):
        with self.assertRaises(RuntimeError):
          mqtt_master.register_node_from_agent(db, {}, {"name": "broken"})
      nodes = db.list_nodes()

    self.assertEqual([], nodes)

  def test_register_node_verifies_mqtt_credentials(self):
    with tempfile.TemporaryDirectory() as temp_dir:
      db = mqtt_master.MasterDatabase(os.path.join(temp_dir, "master.db"))

      with mock.patch("mqtt_master.refresh_mqtt_auth", return_value=(True, "")):
        with mock.patch("mqtt_master.verify_node_mqtt_auth", return_value=(False, "not authorised")) as verify:
          with self.assertRaisesRegex(RuntimeError, "not authorised"):
            mqtt_master.register_node_from_agent(db, {}, {"name": "broken"})
      nodes = db.list_nodes()

    verify.assert_called_once()
    self.assertEqual([], nodes)

  def test_verify_node_mqtt_auth_uses_health_topic(self):
    node = {
      "node_id": "node-a",
      "mqtt_username": "u",
      "mqtt_password": "p",
    }

    with mock.patch("mqtt_master.subprocess.run") as run:
      run.return_value.returncode = 0
      ok, detail = mqtt_master.verify_node_mqtt_auth({
        "MQTT_TOPIC_PREFIX": "vps-bot",
        "MQTT_PORT": "1883",
      }, node)

    command = run.call_args.args[0]
    self.assertTrue(ok)
    self.assertEqual("", detail)
    self.assertIn("vps-bot/health/node-a", command)
    self.assertIn("u", command)

  def test_verify_node_mqtt_auth_returns_failure_detail(self):
    node = {
      "node_id": "node-a",
      "mqtt_username": "u",
      "mqtt_password": "p",
    }
    result = subprocess.CompletedProcess(
      args=["mosquitto_pub"],
      returncode=5,
      stdout="",
      stderr="Connection Refused: not authorised.",
    )

    with mock.patch("mqtt_master.subprocess.run", return_value=result):
      ok, detail = mqtt_master.verify_node_mqtt_auth({}, node, attempts=1)

    self.assertFalse(ok)
    self.assertIn("not authorised", detail)

  def test_refresh_mqtt_auth_writes_node_credentials(self):
    with tempfile.TemporaryDirectory() as temp_dir:
      acl = os.path.join(temp_dir, "acl")
      passwd = os.path.join(temp_dir, "passwd")
      db = mqtt_master.MasterDatabase(os.path.join(temp_dir, "master.db"))
      node = db.register_node("test7")

      with mock.patch("mqtt_master.subprocess.run") as run:
        mqtt_master.refresh_mqtt_auth(db, {
          "MQTT_TOPIC_PREFIX": "vps-bot",
          "MQTT_MASTER_USER": "vps_master",
          "MQTT_MASTER_PASSWORD": "master-pw",
          "MOSQUITTO_ACL": acl,
          "MOSQUITTO_PASSWD": passwd,
        })

      with open(acl, "r", encoding="utf-8") as file:
        acl_text = file.read()

    self.assertIn(f"topic read vps-bot/commands/{node['node_id']}", acl_text)
    called_users = [call.args[0][-2] for call in run.call_args_list]
    self.assertIn("vps_master", called_users)
    self.assertIn(node["mqtt_username"], called_users)
    self.assertIn("-c", run.call_args_list[0].args[0])
    self.assertNotIn("-c", run.call_args_list[1].args[0])

  def test_refresh_mqtt_auth_fails_when_passwd_command_fails(self):
    with tempfile.TemporaryDirectory() as temp_dir:
      db = mqtt_master.MasterDatabase(os.path.join(temp_dir, "master.db"))

      with mock.patch("mqtt_master.subprocess.run") as run:
        run.return_value.returncode = 1
        ok, detail = mqtt_master.refresh_mqtt_auth(db, {
          "MOSQUITTO_ACL": os.path.join(temp_dir, "acl"),
          "MOSQUITTO_PASSWD": os.path.join(temp_dir, "passwd"),
        })

    self.assertFalse(ok)
    self.assertIn("mosquitto_passwd", detail)

  def test_refresh_mqtt_auth_restarts_mosquitto_after_credentials_change(self):
    with tempfile.TemporaryDirectory() as temp_dir:
      db = mqtt_master.MasterDatabase(os.path.join(temp_dir, "master.db"))

      with mock.patch("mqtt_master.subprocess.run") as run:
        mqtt_master.refresh_mqtt_auth(db, {
          "MOSQUITTO_ACL": os.path.join(temp_dir, "acl"),
          "MOSQUITTO_PASSWD": os.path.join(temp_dir, "passwd"),
        })

    commands = [call.args[0] for call in run.call_args_list]
    self.assertIn(["systemctl", "restart", "mosquitto"], commands)

  def test_refresh_mqtt_auth_uses_default_paths_for_upgraded_installs(self):
    with tempfile.TemporaryDirectory() as temp_dir:
      db = mqtt_master.MasterDatabase(os.path.join(temp_dir, "master.db"))
      node = db.register_node("test7")
      acl = os.path.join(temp_dir, "vps-mqtt.acl")
      passwd = os.path.join(temp_dir, "vps-mqtt.passwd")

      with mock.patch.object(mqtt_master, "DEFAULT_MOSQUITTO_ACL", acl):
        with mock.patch.object(mqtt_master, "DEFAULT_MOSQUITTO_PASSWD", passwd):
          with mock.patch("mqtt_master.subprocess.run"):
            refreshed, detail = mqtt_master.refresh_mqtt_auth(db, {})

      with open(acl, "r", encoding="utf-8") as file:
        acl_text = file.read()

    self.assertTrue(refreshed)
    self.assertEqual("", detail)
    self.assertIn(f"topic read vps-bot/commands/{node['node_id']}", acl_text)

  def test_runtime_config_merges_persisted_settings(self):
    with tempfile.TemporaryDirectory() as temp_dir:
      db = mqtt_master.MasterDatabase(os.path.join(temp_dir, "master.db"))
      db.set_setting("MQTT_MASTER_PASSWORD", "persisted")
      db.set_setting("MQTT_HOST", "10.0.0.1")
      db.set_setting("MQTT_LOCAL_HOST", "127.0.0.1")

      config = mqtt_master.runtime_config(db, {"MQTT_HOST": "127.0.0.1"})

    self.assertEqual("127.0.0.1", config["MQTT_HOST"])
    self.assertEqual("127.0.0.1", config["MQTT_LOCAL_HOST"])
    self.assertEqual("persisted", config["MQTT_MASTER_PASSWORD"])

  def test_master_mqtt_clients_use_loopback_by_default(self):
    args = mqtt_master.mqtt_base_args({
      "MQTT_HOST": "15.165.22.159",
      "MQTT_PORT": "1883",
      "MQTT_MASTER_USER": "vps_master",
      "MQTT_MASTER_PASSWORD": "secret",
    })

    self.assertIn("127.0.0.1", args)
    self.assertNotIn("15.165.22.159", args)

  def test_master_mqtt_clients_allow_local_host_override(self):
    args = mqtt_master.mqtt_base_args({
      "MQTT_LOCAL_HOST": "10.0.0.10",
      "MQTT_HOST": "15.165.22.159",
    })

    self.assertIn("10.0.0.10", args)

  def test_start_dynamic_monitor_defaults_to_three_minutes_and_remembers_value(self):
    with tempfile.TemporaryDirectory() as temp_dir:
      db = mqtt_master.MasterDatabase(os.path.join(temp_dir, "master.db"))

      with mock.patch("mqtt_master.time.time", return_value=1800000000):
        with mock.patch("mqtt_master.threading.Thread") as thread:
          minutes = mqtt_master.start_dynamic_monitor(db, {}, "")

      args = thread.call_args.kwargs["args"]
      remembered = db.get_setting("monitor_minutes")
      monitor_until = db.get_setting("monitor_until")

    self.assertEqual(3, minutes)
    self.assertEqual("3", remembered)
    self.assertEqual(1800000180, int(monitor_until))
    self.assertEqual(mqtt_master.REALTIME_MONITOR_INTERVAL_SECONDS, args[3])

  def test_start_dynamic_monitor_uses_remembered_minutes_when_empty(self):
    with tempfile.TemporaryDirectory() as temp_dir:
      db = mqtt_master.MasterDatabase(os.path.join(temp_dir, "master.db"))
      db.set_setting("monitor_minutes", "9")

      with mock.patch("mqtt_master.threading.Thread"):
        minutes = mqtt_master.start_dynamic_monitor(db, {}, "")

    self.assertEqual(9, minutes)

  def test_delete_node_dispatches_uninstall_before_removing_record(self):
    with tempfile.TemporaryDirectory() as temp_dir:
      db = mqtt_master.MasterDatabase(os.path.join(temp_dir, "master.db"))
      node = db.register_node("test7")

      with mock.patch("mqtt_master.publish_mqtt") as publish:
        with mock.patch("mqtt_master.refresh_mqtt_auth", return_value=(True, "")):
          message = mqtt_master.handle_node_action(db, {}, node["node_id"], "delete")

      self.assertIn("卸载", message)
      self.assertEqual([], db.list_nodes())
      payload = json.loads(publish.call_args.args[2])
      self.assertEqual("/uninstall-agent", payload["command"])

  def test_agent_snapshot_command_returns_structured_metrics(self):
    with mock.patch("mqtt_agent.collect_snapshot_metrics") as collect:
      collect.return_value = {
        "monthly_used_gb": 1.0,
        "daily_used_gb": 0.2,
        "network_rx_mbps": 5.0,
        "network_tx_mbps": 1.0,
        "cpu_percent": 9.0,
        "memory_percent": 30.0,
        "latency_ms": 20.0,
      }

      result = mqtt_agent.execute_allowed_command({"NODE_NAME": "test7"}, "/snapshot")

    self.assertEqual("snapshot", result["command"])
    self.assertEqual(1.0, result["metrics"]["monthly_used_gb"])

  def test_agent_registration_sends_existing_node_id(self):
    with tempfile.TemporaryDirectory() as temp_dir:
      config = os.path.join(temp_dir, "agent.env")
      mqtt_agent.write_env(config, {"NODE_ID": "old-node"})

      with mock.patch("mqtt_agent.get_public_ip", return_value=""):
        with mock.patch("mqtt_agent.local_ip_addresses", return_value={"127.0.0.1"}):
          with mock.patch("mqtt_agent.urllib.request.urlopen") as open_url:
            open_url.return_value.__enter__.return_value.read.return_value = json.dumps({
              "node_id": "new-node",
              "name": "new",
              "mqtt_host": "127.0.0.1",
              "mqtt_port": "1883",
              "mqtt_username": "u",
              "mqtt_password": "p",
              "topic_prefix": "vps-bot",
              "command_secret": "s",
            }).encode("utf-8")
            mqtt_agent.register_agent("http://master", "token", "new", config)

      body = open_url.call_args.args[0].data.decode("utf-8")

    self.assertIn("existing_node_id=old-node", body)

  def test_agent_registration_uses_loopback_mqtt_for_self_master(self):
    with tempfile.TemporaryDirectory() as temp_dir:
      config = os.path.join(temp_dir, "agent.env")

      with mock.patch("mqtt_agent.get_public_ip", return_value="15.165.22.159"):
        with mock.patch("mqtt_agent.local_ip_addresses", return_value={"10.0.0.1"}):
          with mock.patch("mqtt_agent.urllib.request.urlopen") as open_url:
            open_url.return_value.__enter__.return_value.read.return_value = json.dumps({
              "node_id": "node",
              "name": "self",
              "mqtt_host": "15.165.22.159",
              "mqtt_port": "1883",
              "mqtt_username": "u",
              "mqtt_password": "p",
              "topic_prefix": "vps-bot",
              "command_secret": "s",
            }).encode("utf-8")
            mqtt_agent.register_agent("http://15.165.22.159:8088", "token", "self", config)

      saved = mqtt_agent.load_env(config)

    self.assertEqual("127.0.0.1", saved["MQTT_HOST"])

  def test_agent_registration_surfaces_master_error_message(self):
    body = io.BytesIO(json.dumps({"error": "MQTT 节点账号验证失败"}).encode("utf-8"))
    error = mqtt_agent.urllib.error.HTTPError(
      "http://master/api/register",
      503,
      "Service Unavailable",
      {},
      body,
    )

    with mock.patch("mqtt_agent.urllib.request.urlopen", side_effect=error):
      try:
        with self.assertRaisesRegex(RuntimeError, "MQTT 节点账号验证失败"):
          mqtt_agent.register_agent("http://master", "token", "new", "/tmp/agent.env")
      finally:
        error.close()

  def test_agent_registration_surfaces_invalid_token_message(self):
    body = io.BytesIO(json.dumps({"error": "注册码无效、已过期或已使用"}).encode("utf-8"))
    error = mqtt_agent.urllib.error.HTTPError(
      "http://master/api/register",
      403,
      "Forbidden",
      {},
      body,
    )

    with mock.patch("mqtt_agent.urllib.request.urlopen", side_effect=error):
      try:
        with self.assertRaisesRegex(RuntimeError, "注册码无效、已过期或已使用"):
          mqtt_agent.register_agent("http://master", "token", "new", "/tmp/agent.env")
      finally:
        error.close()

  def test_agent_listen_starts_periodic_status_heartbeat(self):
    config = {
      "NODE_ID": "node",
      "MQTT_HOST": "127.0.0.1",
      "MQTT_USERNAME": "u",
      "MQTT_PASSWORD": "p",
      "COMMAND_SECRET": "s",
    }

    with mock.patch("mqtt_agent.threading.Thread") as thread:
      mqtt_agent.start_status_heartbeat(config)

    self.assertTrue(thread.call_args.kwargs["daemon"])

  def test_agent_publish_startup_snapshot_sends_status_and_metrics(self):
    config = {
      "NODE_ID": "node",
      "NODE_NAME": "test7",
      "MQTT_HOST": "127.0.0.1",
      "MQTT_USERNAME": "u",
      "MQTT_PASSWORD": "p",
      "COMMAND_SECRET": "s",
    }

    with mock.patch("mqtt_agent.collect_snapshot_metrics") as collect:
      collect.return_value = {
        "monthly_used_gb": 1.0,
        "daily_used_gb": 0.1,
        "network_rx_mbps": 2.0,
        "network_tx_mbps": 3.0,
        "cpu_percent": 4.0,
        "memory_percent": 5.0,
        "latency_ms": 6.0,
      }
      with mock.patch("mqtt_agent.mqtt_publish", return_value=True) as publish:
        ok = mqtt_agent.publish_startup_snapshot(config)

    self.assertTrue(ok)
    self.assertEqual(2, publish.call_count)
    self.assertIn("nodes/node/status", publish.call_args_list[0].args[1])
    self.assertIn("results/node", publish.call_args_list[1].args[1])

  def test_agent_startup_snapshot_retries_transient_mqtt_failures(self):
    config = {
      "NODE_ID": "node",
      "NODE_NAME": "test7",
      "MQTT_HOST": "127.0.0.1",
      "MQTT_USERNAME": "u",
      "MQTT_PASSWORD": "p",
      "COMMAND_SECRET": "s",
    }

    with mock.patch("mqtt_agent.collect_snapshot_metrics") as collect:
      collect.return_value = {
        "monthly_used_gb": 1.0,
        "daily_used_gb": 0.1,
        "network_rx_mbps": 2.0,
        "network_tx_mbps": 3.0,
        "cpu_percent": 4.0,
        "memory_percent": 5.0,
        "latency_ms": 6.0,
      }
      with mock.patch("mqtt_agent.mqtt_publish", side_effect=[False, False, True, True]) as publish:
        with mock.patch("mqtt_agent.time.sleep") as sleep:
          ok = mqtt_agent.publish_startup_snapshot(config, attempts=2, delay_seconds=1)

    self.assertTrue(ok)
    self.assertEqual(4, publish.call_count)
    sleep.assert_called_once_with(1)

  def test_mqtt_publish_records_failure_details(self):
    result = subprocess.CompletedProcess(
      args=["mosquitto_pub"],
      returncode=5,
      stdout="",
      stderr="Connection Refused: not authorised.",
    )

    with mock.patch("mqtt_agent.subprocess.run", return_value=result):
      ok = mqtt_agent.mqtt_publish({}, "topic", "payload")

    self.assertFalse(ok)
    self.assertIn("not authorised", mqtt_agent.mqtt_publish_error())

  def test_agent_ignores_non_json_mqtt_payloads(self):
    result = mqtt_agent.handle_payload({
      "NODE_ID": "node-1",
      "NODE_NAME": "test7",
      "COMMAND_SECRET": "secret",
    }, "Connection Refused: not authorised.")

    self.assertIsNone(result)

  def test_agent_ignores_non_json_mqtt_sub_lines(self):
    config = {
      "NODE_ID": "node-1",
      "MQTT_HOST": "127.0.0.1",
      "MQTT_USERNAME": "u",
      "MQTT_PASSWORD": "p",
      "COMMAND_SECRET": "secret",
    }
    process = mock.Mock()
    process.stdout = iter(["Connection Refused: not authorised.\n"])
    process.poll.return_value = 0

    with mock.patch("mqtt_agent.load_env", return_value=config):
      with mock.patch("mqtt_agent.start_status_heartbeat"):
        with mock.patch("mqtt_agent.subprocess.Popen", return_value=process):
          with mock.patch("mqtt_agent.time.sleep", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
              mqtt_agent.listen("agent.env")

    process.kill.assert_called_once()

  def test_agent_uninstall_command_schedules_cleanup(self):
    with mock.patch("mqtt_agent.delayed_cleanup_agent") as cleanup:
      payload = mqtt_master.sign_command({
        "id": "cmd-1",
        "command": "/uninstall-agent",
        "ts": 1800000000,
      }, "secret")

      with mock.patch("mqtt_agent.time.time", return_value=1800000000):
        result = mqtt_agent.handle_payload({
          "NODE_ID": "node-1",
          "NODE_NAME": "test7",
          "COMMAND_SECRET": "secret",
        }, json.dumps(payload))

    data = json.loads(result)
    self.assertEqual("uninstall-agent", data["command"])
    cleanup.assert_called_once()

  def test_login_trims_username_and_sets_session_cookie(self):
    with tempfile.TemporaryDirectory() as temp_dir:
      db = mqtt_master.MasterDatabase(os.path.join(temp_dir, "master.db"))
      db.create_admin("dajiab", "pw")
      handler = object.__new__(mqtt_master.MasterRequestHandler)
      handler.headers = {"X-Forwarded-Proto": "http"}
      handler.client_address = ("127.0.0.1", 12345)
      handler.rate_limiter = mqtt_master.LoginRateLimiter()
      handler.read_form = lambda: {
        "username": " dajiab ",
        "password": "pw",
        "totp": "",
      }
      handler.server = type("Server", (), {"db": db})()
      sent = []
      handler.send_response = lambda status: sent.append(("status", status))
      handler.send_header = lambda key, value: sent.append((key, value))
      handler.end_headers = lambda: sent.append(("end", ""))

      handler.handle_login()

    self.assertIn(("status", 303), sent)
    cookie = next(value for key, value in sent if key == "Set-Cookie")
    self.assertIn("session=", cookie)
    self.assertNotIn("; Secure", cookie)

  def test_login_without_totp_enabled_ignores_empty_totp(self):
    with tempfile.TemporaryDirectory() as temp_dir:
      db = mqtt_master.MasterDatabase(os.path.join(temp_dir, "master.db"))
      db.create_admin("admin", "pw")
      handler = object.__new__(mqtt_master.MasterRequestHandler)
      handler.headers = {"X-Forwarded-Proto": "http"}
      handler.client_address = ("127.0.0.1", 12345)
      handler.rate_limiter = mqtt_master.LoginRateLimiter()
      handler.read_form = lambda: {
        "username": "admin",
        "password": "pw",
        "totp": "",
      }
      handler.server = type("Server", (), {"db": db})()
      sent = []
      handler.send_response = lambda status: sent.append(("status", status))
      handler.send_header = lambda key, value: sent.append((key, value))
      handler.end_headers = lambda: sent.append(("end", ""))

      handler.handle_login()

    self.assertIn(("status", 303), sent)


if __name__ == "__main__":
  unittest.main()

import base64
import hashlib
import hmac
import json
import os
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

  def test_acl_limits_agent_to_own_topics(self):
    acl = mqtt_master.render_mosquitto_acl("vps-bot", [
      {"node_id": "node-a", "mqtt_username": "vps_node_a"},
      {"node_id": "node-b", "mqtt_username": "vps_node_b"},
    ])

    self.assertIn("user vps_node_a", acl)
    self.assertIn("topic read vps-bot/commands/node-a", acl)
    self.assertIn("topic write vps-bot/results/node-a", acl)
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


if __name__ == "__main__":
  unittest.main()

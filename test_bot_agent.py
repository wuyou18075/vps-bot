import json
import os
import unittest
from unittest import mock

import bot_agent


class TrafficUsageTest(unittest.TestCase):
  def test_reads_vnstat_month_json_from_interface_list(self):
    output = json.dumps({
      "interfaces": [{
        "name": "eth0",
        "traffic": {
          "month": [{
            "date": {"year": 2026, "month": 7},
            "rx": 1024,
            "tx": 2048,
          }],
          "day": [{
            "date": {"year": 2026, "month": 7, "day": 6},
            "rx": 512,
            "tx": 512,
          }],
        },
      }],
    })

    with mock.patch("bot_agent.shutil.which", return_value="/usr/bin/vnstat"), \
        mock.patch("bot_agent.run_command", return_value=(0, output, "")):
      result = bot_agent.get_traffic_usage({
        "INTERFACE": "eth0",
        "TOTAL_TRAFFIC_GB": "1",
      })

    self.assertIn("本月已用: 3.00 KB", result)
    self.assertIn("今日已用: 1.00 KB", result)

  def test_reads_vnstat_month_json_from_single_interface_object(self):
    output = json.dumps({
      "interface": "eth0",
      "traffic": {
        "month": [{
          "date": {"year": 2026, "month": 7},
          "rx": 1024,
          "tx": 2048,
        }],
        "day": [{
          "date": {"year": 2026, "month": 7, "day": 6},
          "rx": 512,
          "tx": 512,
        }],
      },
    })

    with mock.patch("bot_agent.shutil.which", return_value="/usr/bin/vnstat"), \
        mock.patch("bot_agent.run_command", return_value=(0, output, "")):
      result = bot_agent.get_traffic_usage({
        "INTERFACE": "eth0",
        "TOTAL_TRAFFIC_GB": "1",
      })

    self.assertIn("本月已用: 3.00 KB", result)
    self.assertIn("今日已用: 1.00 KB", result)


class TelegramCommandTest(unittest.TestCase):
  def setUp(self):
    bot_agent.STATE_DIR = "/tmp"
    bot_agent.PENDING_SELECT_FILE = "/tmp/bot-panel-test-pending-select"
    bot_agent.SELECTED_NODES_FILE = "/tmp/bot-panel-test-selected-nodes"
    for path in [bot_agent.PENDING_SELECT_FILE, bot_agent.SELECTED_NODES_FILE]:
      try:
        os.remove(path)
      except FileNotFoundError:
        pass

  def test_start_returns_helpful_command_list(self):
    result = bot_agent.handle_command({"NODE_NAME": "vps-1"}, "/start")

    self.assertIn("支持命令", result)
    self.assertIn("/ping", result)
    self.assertIn("/select", result)
    self.assertIn("/services", result)
    self.assertIn("使用方式:", result)
    self.assertNotIn("/1", result)
    self.assertNotIn("/2", result)

  def test_ping_with_host_argument_runs_on_current_node(self):
    with mock.patch("bot_agent.run_ping", return_value="1.1.1.1: avg 10 ms"):
      result = bot_agent.handle_command({"NODE_NAME": "vps-1"}, "/ping 1.1.1.1")

    self.assertEqual("[vps-1] Ping 结果\n1.1.1.1: avg 10 ms", result)

  def test_numeric_shortcuts_are_removed(self):
    one = bot_agent.handle_command({"NODE_NAME": "vps-1"}, "/1")
    two = bot_agent.handle_command({"NODE_NAME": "vps-1"}, "/2")

    self.assertIsNone(one)
    self.assertIsNone(two)

  def test_use_returns_traffic_usage_only(self):
    with mock.patch("bot_agent.get_traffic_usage", return_value="本月已用: 3.00 GB\n今日已用: 1.00 GB"):
      result = bot_agent.handle_command({"NODE_NAME": "vps-1"}, "/use")

    self.assertEqual("[vps-1] 流量使用情况\n本月已用: 3.00 GB\n今日已用: 1.00 GB", result)

  def test_select_menu_is_returned_by_control_node(self):
    result = bot_agent.handle_command({
      "NODE_NAME": "vps1",
      "NODE_LIST": "vps1,vps2,vps3",
      "CONTROL_NODE": "vps1",
    }, "/select")

    self.assertIn("当前选择: 全部", result)
    self.assertIn("0 清空", result)
    self.assertIn("2 vps2", result)
    self.assertIn("99 所有", result)

  def test_select_menu_is_silent_on_non_control_node(self):
    result = bot_agent.handle_command({
      "NODE_NAME": "vps2",
      "NODE_LIST": "vps1,vps2,vps3",
      "CONTROL_NODE": "vps1",
    }, "/select")

    self.assertIsNone(result)

  def test_select_menu_is_silent_without_explicit_control_node(self):
    result = bot_agent.handle_command({
      "NODE_NAME": "vps2",
      "NODE_LIST": "vps2",
    }, "/select")

    self.assertIsNone(result)

  def test_numeric_selection_reply_updates_scope(self):
    config = {
      "NODE_NAME": "vps1",
      "NODE_LIST": "vps1,vps2,vps3",
      "CONTROL_NODE": "vps1",
    }
    bot_agent.handle_command(config, "/select")

    result = bot_agent.handle_text(config, "2,3")

    self.assertEqual("已选择: vps2,vps3", result)
    self.assertEqual(["vps2", "vps3"], bot_agent.read_selected_nodes())

  def test_selected_scope_filters_commands(self):
    bot_agent.write_selected_nodes(["vps2", "vps3"])

    selected = bot_agent.handle_command({"NODE_NAME": "vps2"}, "/status")
    skipped = bot_agent.handle_command({"NODE_NAME": "vps1"}, "/status")

    self.assertIsNotNone(selected)
    self.assertIsNone(skipped)

  def test_status_commands_ignore_selection_when_all_selected(self):
    bot_agent.write_selected_nodes(["all"])

    with mock.patch("bot_agent.build_report", return_value="[vps1] 状态"):
      result = bot_agent.handle_command({"NODE_NAME": "vps1"}, "/status")

    self.assertEqual("[vps1] 状态", result)

  def test_disk_top_uptime_and_services_commands(self):
    commands = {
      "/disk": "磁盘详情",
      "/top": "高占用进程",
      "/uptime": "运行时间",
      "/services": "服务状态",
    }
    for command, title in commands.items():
      with self.subTest(command=command), mock.patch("bot_agent.run_command", return_value=(0, "ok", "")):
        result = bot_agent.handle_command({"NODE_NAME": "vps-1"}, command)

      self.assertIn(f"[vps-1] {title}", result)

  def test_configure_bot_commands_registers_slash_menu(self):
    with mock.patch("bot_agent.telegram_api") as telegram_api:
      bot_agent.configure_bot_commands({"BOT_TOKEN": "token"})

    method = telegram_api.call_args.args[1]
    payload = telegram_api.call_args.args[2]
    commands = json.loads(payload["commands"])

    self.assertEqual("setMyCommands", method)
    self.assertIn({"command": "select", "description": "选择 VPS 范围"}, commands)
    self.assertIn({"command": "ping", "description": "Ping 默认目标"}, commands)
    self.assertIn({"command": "use", "description": "查看流量使用"}, commands)
    self.assertIn({"command": "disk", "description": "查看磁盘详情"}, commands)
    self.assertIn({"command": "top", "description": "查看高占用进程"}, commands)
    self.assertIn({"command": "uptime", "description": "查看运行时间"}, commands)
    self.assertIn({"command": "services", "description": "查看关键服务"}, commands)
    self.assertNotIn({"command": "1", "description": "查看节点状态"}, commands)
    self.assertNotIn({"command": "2", "description": "查看流量汇报"}, commands)

  def test_prepare_listener_deletes_webhook_and_registers_commands(self):
    with mock.patch("bot_agent.telegram_api") as telegram_api:
      bot_agent.prepare_listener({"BOT_TOKEN": "token"})

    methods = [call.args[1] for call in telegram_api.call_args_list]
    self.assertEqual(["deleteWebhook", "setMyCommands"], methods)


if __name__ == "__main__":
  unittest.main()

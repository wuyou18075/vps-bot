import json
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

  def test_reads_vnstat_month_json_from_single_interface_object(self):
    output = json.dumps({
      "interface": "eth0",
      "traffic": {
        "month": [{
          "date": {"year": 2026, "month": 7},
          "rx": 1024,
          "tx": 2048,
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


class TelegramCommandTest(unittest.TestCase):
  def test_start_returns_helpful_command_list(self):
    result = bot_agent.handle_command({"NODE_NAME": "vps-1"}, "/start")

    self.assertIn("支持命令", result)
    self.assertIn("/ping", result)
    self.assertIn("/1", result)
    self.assertIn("/2", result)

  def test_ping_with_host_argument_runs_on_current_node(self):
    with mock.patch("bot_agent.run_ping", return_value="1.1.1.1: avg 10 ms"):
      result = bot_agent.handle_command({"NODE_NAME": "vps-1"}, "/ping 1.1.1.1")

    self.assertEqual("[vps-1] Ping 结果\n1.1.1.1: avg 10 ms", result)

  def test_numeric_shortcut_one_returns_status(self):
    with mock.patch("bot_agent.build_report", return_value="[vps-1] 状态"):
      result = bot_agent.handle_command({"NODE_NAME": "vps-1"}, "/1")

    self.assertEqual("[vps-1] 状态", result)

  def test_numeric_shortcut_two_returns_report(self):
    with mock.patch("bot_agent.build_report", return_value="[vps-1] 流量汇报"):
      result = bot_agent.handle_command({"NODE_NAME": "vps-1"}, "/2")

    self.assertEqual("[vps-1] 流量汇报", result)

  def test_use_returns_traffic_usage_only(self):
    with mock.patch("bot_agent.get_traffic_usage", return_value="本月已用: 3.00 GB"):
      result = bot_agent.handle_command({"NODE_NAME": "vps-1"}, "/use")

    self.assertEqual("[vps-1] 流量使用情况\n本月已用: 3.00 GB", result)

  def test_configure_bot_commands_registers_slash_menu(self):
    with mock.patch("bot_agent.telegram_api") as telegram_api:
      bot_agent.configure_bot_commands({"BOT_TOKEN": "token"})

    method = telegram_api.call_args.args[1]
    payload = telegram_api.call_args.args[2]
    commands = json.loads(payload["commands"])

    self.assertEqual("setMyCommands", method)
    self.assertIn({"command": "ping", "description": "Ping 默认目标"}, commands)
    self.assertIn({"command": "use", "description": "查看流量使用"}, commands)
    self.assertNotIn({"command": "1", "description": "查看节点状态"}, commands)
    self.assertNotIn({"command": "2", "description": "查看流量汇报"}, commands)

  def test_prepare_listener_deletes_webhook_and_registers_commands(self):
    with mock.patch("bot_agent.telegram_api") as telegram_api:
      bot_agent.prepare_listener({"BOT_TOKEN": "token"})

    methods = [call.args[1] for call in telegram_api.call_args_list]
    self.assertEqual(["deleteWebhook", "setMyCommands"], methods)


if __name__ == "__main__":
  unittest.main()

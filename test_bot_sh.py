import subprocess
import textwrap
import unittest


class BotShellInterfaceSelectionTest(unittest.TestCase):
  def run_bash(self, script, stdin=""):
    result = subprocess.run(
      ["bash", "-c", script],
      input=stdin,
      capture_output=True,
      text=True,
      check=False,
    )
    self.assertEqual(result.returncode, 0, result.stderr)
    return result.stdout.strip()

  def test_default_raw_base_url_uses_current_repository(self):
    script = textwrap.dedent("""
      BOT_PANEL_TESTING=1 source ./bot.sh
      printf '%s\\n' "${RAW_BASE_URL}"
    """)

    self.assertEqual(
      "https://raw.githubusercontent.com/wuyou18075/vps-bot/refs/heads/main",
      self.run_bash(script),
    )

  def test_single_interface_is_selected_automatically(self):
    script = textwrap.dedent("""
      BOT_PANEL_TESTING=1 source ./bot.sh
      list_network_interfaces() {
        printf '%s\\n' ens5
      }
      select_monitor_interface ""
    """)

    self.assertEqual("ens5", self.run_bash(script))

  def test_multiple_interfaces_can_be_selected_by_number(self):
    script = textwrap.dedent("""
      BOT_PANEL_TESTING=1 source ./bot.sh
      list_network_interfaces() {
        printf '%s\\n' ens5 eth0
      }
      select_monitor_interface ens5
    """)

    self.assertEqual("eth0", self.run_bash(script, stdin="2\n"))

  def test_main_panel_shows_status_summary_and_short_commands(self):
    script = textwrap.dedent("""
      BOT_PANEL_TESTING=1 source ./bot.sh
      get_traffic_summary() {
        printf '%s\\n' '12.34G / 500G'
      }
      get_telegram_status() {
        printf '%s\\n' '在线'
      }
      render_main_panel
    """)

    output = self.run_bash(script)

    self.assertIn("Bot 一键面板 - Debian 13", output)
    self.assertIn("流量:    12.34G / 500G", output)
    self.assertIn("TG状态:  在线", output)
    self.assertIn("TG指令说明:", output)
    self.assertIn("/ping", output)
    self.assertIn("/1", output)
    self.assertIn("/2", output)
    self.assertIn("1. 月流量监控", output)

  def test_traffic_summary_reads_vnstat_json_in_gb(self):
    script = textwrap.dedent("""
      BOT_PANEL_TESTING=1 source ./bot.sh
      TRAFFIC_MONITOR=1
      INTERFACE=ens5
      TOTAL_TRAFFIC_GB=500
      vnstat() {
        printf '%s\\n' '{"interfaces":[{"traffic":{"month":[{"rx":1073741824,"tx":2147483648}]}}]}'
      }
      get_traffic_summary
    """)

    self.assertEqual("3.00G / 500G", self.run_bash(script))


if __name__ == "__main__":
  unittest.main()

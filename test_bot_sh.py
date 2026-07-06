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


if __name__ == "__main__":
  unittest.main()

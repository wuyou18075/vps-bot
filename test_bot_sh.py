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
      CONFIG_FILE=/tmp/bot-panel-test-config.env
      touch "${CONFIG_FILE}"
      get_traffic_summary() {
        printf '%s\\n' '0.00G / 500G'
      }
      get_telegram_status() {
        printf '%s\\n' '离线'
      }
      get_script_version_status() {
        printf '%s\\n' '本地 2026.07.06.2 / 最新 2026.07.06.2 (已最新)'
      }
      render_main_panel
      rm -f "${CONFIG_FILE}"
    """)

    output = self.run_bash(script)

    self.assertIn("Bot 一键面板 - Debian 13", output)
    self.assertIn("配置文件:/tmp/bot-panel-test-config.env", output)
    self.assertIn("脚本版本:本地 2026.07.06.2 / 最新 2026.07.06.2 (已最新)", output)
    self.assertIn("流量:    0.00G / 500G", output)
    self.assertIn("TG状态:  离线", output)
    self.assertIn("TG指令说明:", output)
    self.assertIn("/ping", output)
    self.assertIn("/use", output)
    self.assertIn("/1", output)
    self.assertIn("/2", output)
    self.assertIn("1. 月流量监控", output)
    self.assertIn("10. 设置每天定时汇报流量", output)
    self.assertIn("90. 查出定时任务", output)
    self.assertIn("97. 查看配置文件", output)
    self.assertIn("98. 删除配置文件", output)
    self.assertIn("99. 删除所有", output)

  def test_script_version_status_marks_latest(self):
    script = textwrap.dedent("""
      BOT_PANEL_TESTING=1 source ./bot.sh
      SCRIPT_VERSION=2026.07.06.2
      get_latest_script_version() {
        printf '%s\\n' 2026.07.06.2
      }
      get_script_version_status
    """)

    self.assertEqual(
      "本地 2026.07.06.2 / 最新 2026.07.06.2 (已最新)",
      self.run_bash(script),
    )

  def test_script_version_status_marks_outdated(self):
    script = textwrap.dedent("""
      BOT_PANEL_TESTING=1 source ./bot.sh
      SCRIPT_VERSION=2026.07.06.1
      get_latest_script_version() {
        printf '%s\\n' 2026.07.06.2
      }
      get_script_version_status
    """)

    self.assertEqual(
      "本地 2026.07.06.1 / 最新 2026.07.06.2 (可更新)",
      self.run_bash(script),
    )

  def test_script_version_status_handles_unknown_latest(self):
    script = textwrap.dedent("""
      BOT_PANEL_TESTING=1 source ./bot.sh
      SCRIPT_VERSION=2026.07.06.2
      get_latest_script_version() {
        return 1
      }
      get_script_version_status
    """)

    self.assertEqual(
      "本地 2026.07.06.2 / 最新 未知",
      self.run_bash(script),
    )

  def test_commands_help_shows_use_command(self):
    script = textwrap.dedent("""
      BOT_PANEL_TESTING=1 source ./bot.sh
      pause() { :; }
      show_commands_help
    """)

    output = self.run_bash(script)

    self.assertIn("/use", output)
    self.assertIn("- /use 查看本月流量使用情况。", output)

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

  def test_config_file_status_shows_none_when_missing(self):
    script = textwrap.dedent("""
      BOT_PANEL_TESTING=1 source ./bot.sh
      CONFIG_FILE=/tmp/bot-panel-missing-config.env
      rm -f "${CONFIG_FILE}"
      get_config_file_status
    """)

    self.assertEqual("无", self.run_bash(script))

  def test_missing_dependencies_is_empty_when_commands_exist(self):
    script = textwrap.dedent("""
      BOT_PANEL_TESTING=1 source ./bot.sh
      command() {
        if [ "$1" = "-v" ]; then
          return 0
        fi
        builtin command "$@"
      }
      get_missing_dependencies
    """)

    self.assertEqual("", self.run_bash(script))

  def test_main_choice_two_shows_node_info(self):
    script = textwrap.dedent("""
      BOT_PANEL_TESTING=1 source ./bot.sh
      show_node_info() { printf '%s\\n' node; }
      handle_main_choice 2
    """)

    self.assertEqual("node", self.run_bash(script))

  def test_main_choice_three_binds_telegram(self):
    script = textwrap.dedent("""
      BOT_PANEL_TESTING=1 source ./bot.sh
      bind_telegram_bot() { printf '%s\\n' bind; }
      handle_main_choice 3
    """)

    self.assertEqual("bind", self.run_bash(script))

  def test_bind_telegram_starts_listener_after_successful_test(self):
    script = textwrap.dedent("""
      BOT_PANEL_TESTING=1
      source ./bot.sh
      install_dependencies() { :; }
      install_agent_file() { :; }
      ensure_base_config() { :; }
      write_config_value() { :; }
      python3() { return 0; }
      setup_listener_service() { printf '%s\\n' listener-started; }
      pause() { :; }
      bind_telegram_bot
    """)

    output = self.run_bash(script, stdin="token\nchat\nnode\n")

    self.assertIn("Telegram 绑定成功。", output)
    self.assertIn("listener-started", output)

  def test_listener_setup_restarts_existing_service(self):
    script = textwrap.dedent("""
      BOT_PANEL_TESTING=1
      source ./bot.sh
      SERVICE_FILE=/tmp/bot-panel-test.service
      systemctl() {
        printf '%s\\n' "$*"
      }
      setup_listener_service
      rm -f "${SERVICE_FILE}"
    """)

    output = self.run_bash(script)

    self.assertIn("daemon-reload", output)
    self.assertIn("enable bot-panel-listener.service", output)
    self.assertIn("restart bot-panel-listener.service", output)

  def test_main_choice_ninety_seven_shows_config(self):
    script = textwrap.dedent("""
      BOT_PANEL_TESTING=1 source ./bot.sh
      show_config_file() { printf '%s\\n' config; }
      handle_main_choice 97
    """)

    self.assertEqual("config", self.run_bash(script))


if __name__ == "__main__":
  unittest.main()

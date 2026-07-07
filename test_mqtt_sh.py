import subprocess
import textwrap
import unittest


class MqttShellTest(unittest.TestCase):
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

  def test_missing_dependencies_include_mqtt_and_web_runtime(self):
    script = textwrap.dedent("""
      VPS_MQTT_TESTING=1 source ./mqtt.sh
      command() {
        if [ "$1" = "-v" ]; then
          return 1
        fi
        builtin command "$@"
      }
      get_missing_dependencies
    """)

    output = self.run_bash(script)

    self.assertIn("mosquitto", output)
    self.assertIn("mosquitto-clients", output)
    self.assertIn("python3", output)
    self.assertIn("nginx", output)

  def test_render_main_panel_shows_status_lines(self):
    script = textwrap.dedent("""
      VPS_MQTT_TESTING=1 source ./mqtt.sh
      get_mqtt_status() { printf '%s\\n' '运行'; }
      get_web_status() { printf '%s\\n' '运行'; }
      get_online_node_count() { printf '%s\\n' '2'; }
      get_registered_node_count() { printf '%s\\n' '3'; }
      get_totp_status() { printf '%s\\n' '已开启'; }
      CONFIG_DIR=/tmp/vps-mqtt-panel-domain-test
      CONFIG_FILE="${CONFIG_DIR}/config.env"
      mkdir -p "${CONFIG_DIR}"
      printf '%s\\n' 'PUBLIC_URL="https://panel.example.com"' > "${CONFIG_FILE}"
      render_main_panel
    """)

    output = self.run_bash(script)

    self.assertIn("MQTT服务: 运行", output)
    self.assertIn("Web面板: 运行 (https://panel.example.com)", output)
    self.assertIn("公网访问: https://panel.example.com", output)
    self.assertIn("在线VPS: 2", output)
    self.assertIn("已注册VPS: 3", output)
    self.assertIn("双重认证: 已开启", output)

  def test_panel_uses_ip_and_port_when_public_url_is_empty(self):
    script = textwrap.dedent("""
      VPS_MQTT_TESTING=1 source ./mqtt.sh
      CONFIG_DIR=/tmp/vps-mqtt-panel-ip-test
      CONFIG_FILE="${CONFIG_DIR}/config.env"
      mkdir -p "${CONFIG_DIR}"
      printf '%s\\n' 'WEB_PORT="8088"' > "${CONFIG_FILE}"
      get_web_status() { printf '%s\\n' '运行'; }
      get_primary_ip() { printf '%s\\n' '1.2.3.4'; }
      load_config
      get_web_access_url
      printf '%s\\n' "---"
      render_main_panel
    """)

    output = self.run_bash(script)

    self.assertIn("http://1.2.3.4:8088", output)
    self.assertIn("Web面板: 运行 (http://1.2.3.4:8088)", output)
    self.assertIn("公网访问: http://1.2.3.4:8088", output)

  def test_panel_shows_unconfigured_after_uninstall(self):
    script = textwrap.dedent("""
      VPS_MQTT_TESTING=1 source ./mqtt.sh
      CONFIG_DIR=/tmp/vps-mqtt-panel-uninstalled
      CONFIG_FILE="${CONFIG_DIR}/config.env"
      MOSQUITTO_CONF=/tmp/vps-mqtt-panel-uninstalled.conf
      rm -f "${CONFIG_FILE}"
      rm -f "${MOSQUITTO_CONF}"
      PUBLIC_URL=http://old.example.com
      WEB_PORT=8088
      systemctl() {
        if [ "$1" = "is-active" ]; then
          return 0
        fi
      }
      get_web_status() { printf '%s\\n' '未运行'; }
      render_main_panel
    """)

    output = self.run_bash(script)

    self.assertIn("MQTT服务: 未配置", output)
    self.assertIn("Web面板: 未运行 (未配置)", output)
    self.assertIn("公网访问: 未配置", output)
    self.assertNotIn("old.example.com", output)

  def test_primary_ip_prefers_public_ip_lookup(self):
    script = textwrap.dedent("""
      VPS_MQTT_TESTING=1 source ./mqtt.sh
      curl() {
        printf '%s\\n' '8.8.8.8'
      }
      hostname() {
        if [ "$1" = "-I" ]; then
          printf '%s\\n' '172.26.3.247'
        fi
      }
      get_primary_ip
    """)

    self.assertEqual("8.8.8.8", self.run_bash(script))

  def test_setup_master_writes_secure_config_and_services(self):
    script = textwrap.dedent("""
      VPS_MQTT_TESTING=1 source ./mqtt.sh
      CONFIG_DIR=/tmp/vps-mqtt-test-config
      CONFIG_FILE="${CONFIG_DIR}/config.env"
      INSTALL_DIR=/tmp/vps-mqtt-test-install
      STATE_DIR=/tmp/vps-mqtt-test-state
      SERVICE_FILE=/tmp/vps-mqtt-master.service
      NGINX_FILE=/tmp/vps-mqtt-nginx.conf
      MOSQUITTO_CONF=/tmp/vps-mqtt-mosquitto.conf
      MOSQUITTO_ACL=/tmp/vps-mqtt-acl
      MOSQUITTO_PASSWD=/tmp/vps-mqtt-passwd
      install_dependencies() { :; }
      systemctl() { :; }
      check_web_health() { printf '%s\\n' health-ok; }
      create_web_admin() { printf 'admin:%s\\n' "$1"; }
      mosquitto_passwd() { printf '%s %s %s\\n' "$@" >> /tmp/vps-mqtt-passwd-calls; }
      cp() { command cp "$@"; }
      setup_master <<'EOF'
https://panel.example.com
1883
8088
admin
pw
pw
EOF
      cat "${CONFIG_FILE}"
      printf '%s\\n' '---SERVICE---'
      cat "${SERVICE_FILE}"
      printf '%s\\n' '---MOSQUITTO---'
      cat "${MOSQUITTO_CONF}"
    """)

    output = self.run_bash(script)

    self.assertIn('PUBLIC_URL="https://panel.example.com"', output)
    self.assertIn('MQTT_PORT="1883"', output)
    self.assertIn('WEB_PORT="8088"', output)
    self.assertIn('WEB_HOST="127.0.0.1"', output)
    self.assertIn("ExecStart=/usr/bin/python3 /tmp/vps-mqtt-test-install/mqtt_master.py --config /tmp/vps-mqtt-test-config/config.env serve", output)
    self.assertIn("password_file /tmp/vps-mqtt-passwd", output)
    self.assertIn("acl_file /tmp/vps-mqtt-acl", output)
    self.assertIn("admin:admin", output)
    self.assertIn("health-ok", output)

  def test_setup_master_defaults_public_url_to_ip_port(self):
    script = textwrap.dedent("""
      VPS_MQTT_TESTING=1 source ./mqtt.sh
      CONFIG_DIR=/tmp/vps-mqtt-test-config-default-url
      CONFIG_FILE="${CONFIG_DIR}/config.env"
      INSTALL_DIR=/tmp/vps-mqtt-test-install-default-url
      STATE_DIR=/tmp/vps-mqtt-test-state-default-url
      SERVICE_FILE=/tmp/vps-mqtt-master-default-url.service
      NGINX_FILE=/tmp/vps-mqtt-nginx-default-url.conf
      MOSQUITTO_CONF=/tmp/vps-mqtt-mosquitto-default-url.conf
      MOSQUITTO_ACL=/tmp/vps-mqtt-acl-default-url
      MOSQUITTO_PASSWD=/tmp/vps-mqtt-passwd-default-url
      get_primary_ip() { printf '%s\\n' '5.6.7.8'; }
      install_dependencies() { :; }
      systemctl() { :; }
      check_web_health() { :; }
      create_web_admin() { :; }
      mosquitto_passwd() { :; }
      cp() { command cp "$@"; }
      setup_master <<'EOF'

1883
9090
admin
pw
pw
EOF
      cat "${CONFIG_FILE}"
    """)

    output = self.run_bash(script)

    self.assertIn('PUBLIC_URL="http://5.6.7.8:9090"', output)
    self.assertIn('WEB_HOST="0.0.0.0"', output)

  def test_setup_master_rejects_mismatched_admin_passwords(self):
    script = textwrap.dedent("""
      VPS_MQTT_TESTING=1 source ./mqtt.sh
      CONFIG_DIR=/tmp/vps-mqtt-test-password-mismatch
      CONFIG_FILE="${CONFIG_DIR}/config.env"
      INSTALL_DIR=/tmp/vps-mqtt-test-password-mismatch-install
      STATE_DIR=/tmp/vps-mqtt-test-password-mismatch-state
      install_dependencies() { :; }
      setup_master <<'EOF'

1883
8088
admin
pw
p2
EOF
    """)

    output = self.run_bash(script)

    self.assertIn("两次输入的密码不一致", output)

  def test_setup_master_rejects_one_character_admin_password(self):
    script = textwrap.dedent("""
      VPS_MQTT_TESTING=1 source ./mqtt.sh
      CONFIG_DIR=/tmp/vps-mqtt-test-short-password
      CONFIG_FILE="${CONFIG_DIR}/config.env"
      INSTALL_DIR=/tmp/vps-mqtt-test-short-password-install
      STATE_DIR=/tmp/vps-mqtt-test-short-password-state
      install_dependencies() { :; }
      setup_master <<'EOF'

1883
8088
admin
p
p
EOF
    """)

    output = self.run_bash(script)

    self.assertIn("Web 管理员密码至少 2 位", output)

  def test_installer_password_input_is_visible(self):
    with open("mqtt.sh", "r", encoding="utf-8") as file:
      script = file.read()

    self.assertNotIn("stty -echo", script)
    self.assertNotIn("read -r -s", script)
    self.assertIn("请输入 Web 管理员密码（至少 2 位）", script)

  def test_setup_master_persists_runtime_settings_to_sqlite(self):
    script = textwrap.dedent("""
      VPS_MQTT_TESTING=1 source ./mqtt.sh
      CONFIG_DIR=/tmp/vps-mqtt-test-db-config
      CONFIG_FILE="${CONFIG_DIR}/config.env"
      INSTALL_DIR=/tmp/vps-mqtt-test-db-install
      STATE_DIR=/tmp/vps-mqtt-test-db-state
      SERVICE_FILE=/tmp/vps-mqtt-test-db.service
      NGINX_FILE=/tmp/vps-mqtt-test-db-nginx.conf
      MOSQUITTO_CONF=/tmp/vps-mqtt-test-db-mosquitto.conf
      MOSQUITTO_ACL=/tmp/vps-mqtt-test-db-acl
      MOSQUITTO_PASSWD=/tmp/vps-mqtt-test-db-passwd
      get_primary_ip() { printf '%s\\n' '5.6.7.8'; }
      install_dependencies() { :; }
      systemctl() { :; }
      check_web_health() { :; }
      create_web_admin() { :; }
      mosquitto_passwd() { :; }
      cp() { command cp "$@"; }
      setup_master <<'EOF'

1883
9090
admin
pw
pw
EOF
      python3 - <<PY
import sqlite3
db = sqlite3.connect("/tmp/vps-mqtt-test-db-state/master.db")
for key in ["PUBLIC_URL", "MQTT_PORT", "WEB_HOST", "WEB_PORT"]:
  print(f"{key}=" + db.execute("select value from settings where key=?", (key,)).fetchone()[0])
PY
    """)

    output = self.run_bash(script)

    self.assertIn("PUBLIC_URL=http://5.6.7.8:9090", output)
    self.assertIn("MQTT_PORT=1883", output)
    self.assertIn("WEB_HOST=0.0.0.0", output)
    self.assertIn("WEB_PORT=9090", output)

  def test_check_web_health_reports_failure(self):
    script = textwrap.dedent("""
      VPS_MQTT_TESTING=1 source ./mqtt.sh
      WEB_PORT=8088
      curl() { return 7; }
      sleep() { :; }
      check_web_health
    """)

    output = self.run_bash(script)

    self.assertIn("Web 本机健康检查失败", output)
    self.assertIn("journalctl -u vps-mqtt-master.service", output)

  def test_register_agent_invokes_agent_and_service_setup(self):
    script = textwrap.dedent("""
      VPS_MQTT_TESTING=1 source ./mqtt.sh
      INSTALL_DIR=/tmp/vps-mqtt-agent-install
      AGENT_CONFIG=/tmp/vps-mqtt-agent.env
      AGENT_SERVICE_FILE=/tmp/vps-mqtt-agent.service
      install_dependencies() { :; }
      systemctl() { :; }
      python3() { printf '%s\\n' "$*"; }
      cp() { command cp "$@"; }
      register_agent --master-url https://panel.example.com --token abc --node-name test7
      cat "${AGENT_SERVICE_FILE}"
    """)

    output = self.run_bash(script)

    self.assertIn("mqtt_agent.py --config /tmp/vps-mqtt-agent.env register --master-url https://panel.example.com --token abc --node-name test7", output)
    self.assertIn("ExecStart=/usr/bin/python3 /tmp/vps-mqtt-agent-install/mqtt_agent.py --config /tmp/vps-mqtt-agent.env listen", output)


if __name__ == "__main__":
  unittest.main()

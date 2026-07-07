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
      PUBLIC_URL=https://panel.example.com
      render_main_panel
    """)

    output = self.run_bash(script)

    self.assertIn("MQTT服务: 运行", output)
    self.assertIn("Web面板: 运行", output)
    self.assertIn("公网访问: https://panel.example.com", output)
    self.assertIn("在线VPS: 2", output)
    self.assertIn("已注册VPS: 3", output)
    self.assertIn("双重认证: 已开启", output)

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
      mosquitto_passwd() { printf '%s %s %s\\n' "$@" >> /tmp/vps-mqtt-passwd-calls; }
      cp() { command cp "$@"; }
      setup_master <<'EOF'
https://panel.example.com
1883
8088
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
    self.assertIn("ExecStart=/usr/bin/python3 /tmp/vps-mqtt-test-install/mqtt_master.py --config /tmp/vps-mqtt-test-config/config.env serve", output)
    self.assertIn("password_file /tmp/vps-mqtt-passwd", output)
    self.assertIn("acl_file /tmp/vps-mqtt-acl", output)

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

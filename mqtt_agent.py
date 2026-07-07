#!/usr/bin/env python3
"""MQTT node agent with signed command verification and command allow-list."""

import argparse
import json
import os
import shlex
import shutil
import socket
import subprocess
import time
import urllib.parse
import urllib.request

import mqtt_master


DEFAULT_CONFIG = "/etc/vps-mqtt/agent.env"
ALLOWED_COMMANDS = {
  "ping",
  "use",
  "speed",
  "status",
  "report",
  "disk",
  "top",
  "uptime",
  "services",
}


def load_env(path=DEFAULT_CONFIG):
  """Load KEY=VALUE config."""
  config = {}
  if not os.path.exists(path):
    return config
  with open(path, "r", encoding="utf-8") as file:
    for raw_line in file:
      line = raw_line.strip()
      if not line or line.startswith("#") or "=" not in line:
        continue
      key, value = line.split("=", 1)
      config[key.strip()] = value.strip().strip('"').strip("'")
  return config


def write_env(path, values):
  """Write an env file with strict permissions."""
  directory = os.path.dirname(path)
  if directory:
    os.makedirs(directory, mode=0o700, exist_ok=True)
  with open(path, "w", encoding="utf-8") as file:
    for key, value in values.items():
      escaped = str(value).replace('"', '\\"')
      file.write(f'{key}="{escaped}"\n')
  os.chmod(path, 0o600)


def verify_command_signature(payload, secret, now=None, max_age_seconds=120):
  """Return whether a signed command payload is authentic and fresh."""
  if not isinstance(payload, dict) or "sig" not in payload:
    return False
  try:
    timestamp = int(payload.get("ts", 0))
  except (TypeError, ValueError):
    return False
  current = int(time.time() if now is None else now)
  if abs(current - timestamp) > max_age_seconds:
    return False
  expected = mqtt_master.command_signature(payload, secret)
  return mqtt_master.hmac.compare_digest(expected, str(payload.get("sig", "")))


def parse_allowed_command(text):
  """Parse and validate a supported command."""
  if not text or not text.startswith("/"):
    raise ValueError("命令必须以 / 开头")
  parts = shlex.split(text)
  command = parts[0].lstrip("/").split("@", 1)[0].lower()
  if command not in ALLOWED_COMMANDS:
    raise ValueError("命令不在白名单")
  return [command, parts[1:]]


def run_command(command, timeout=60):
  """Run a local command and return compact output."""
  try:
    result = subprocess.run(
      command,
      capture_output=True,
      text=True,
      timeout=timeout,
      check=False,
    )
  except subprocess.TimeoutExpired:
    return "执行超时"
  output = (result.stdout or result.stderr or "").strip()
  return output[-4000:] if output else "无输出"


def bytes_to_human(value):
  """Convert bytes to a human-readable size."""
  size = float(value)
  for unit in ["B", "KB", "MB", "GB", "TB"]:
    if size < 1024 or unit == "TB":
      return f"{size:.2f} {unit}"
    size = size / 1024
  return f"{size:.2f} TB"


def get_public_ip():
  """Best-effort public IP lookup."""
  for url in ["https://api.ipify.org", "https://ifconfig.me/ip"]:
    try:
      with urllib.request.urlopen(url, timeout=5) as response:
        value = response.read().decode("utf-8").strip()
        if value:
          return value
    except Exception:
      continue
  return ""


def execute_allowed_command(config, text):
  """Execute one allow-listed command."""
  node_name = config.get("NODE_NAME") or socket.gethostname()
  command, args = parse_allowed_command(text)
  if command == "ping":
    target = args[0] if args else "1.1.1.1"
    return f"[{node_name}] Ping\n{run_command(['ping', '-c', '4', '-W', '2', target], timeout=15)}"
  if command == "speed":
    binary = "speedtest-cli" if shutil.which("speedtest-cli") else "speedtest"
    return f"[{node_name}] 测速\n{run_command([binary, '--simple'], timeout=180)}"
  if command == "use":
    return f"[{node_name}] 流量\n{run_command(['vnstat', '--oneline'], timeout=20)}"
  if command == "status":
    return f"[{node_name}] 状态\n{run_command(['sh', '-c', 'uptime; free -h; df -h /'], timeout=20)}"
  if command == "report":
    return f"[{node_name}] 报告\n{run_command(['sh', '-c', 'uptime; vnstat --oneline; df -h /'], timeout=30)}"
  if command == "disk":
    return f"[{node_name}] 磁盘\n{run_command(['df', '-h'], timeout=20)}"
  if command == "top":
    return f"[{node_name}] 进程\n{run_command(['ps', '-eo', 'pid,comm,%cpu,%mem', '--sort=-%cpu'], timeout=20)}"
  if command == "uptime":
    return f"[{node_name}] 运行时间\n{run_command(['uptime'], timeout=10)}"
  if command == "services":
    return f"[{node_name}] 服务\n{run_command(['systemctl', '--no-pager', '--type=service', '--state=running'], timeout=20)}"
  raise ValueError("命令不在白名单")


def mqtt_base_args(config):
  """Return common mosquitto CLI args."""
  return [
    "-h", config.get("MQTT_HOST", "127.0.0.1"),
    "-p", str(config.get("MQTT_PORT", "1883")),
    "-u", config.get("MQTT_USERNAME", ""),
    "-P", config.get("MQTT_PASSWORD", ""),
  ]


def mqtt_topic(config, suffix):
  """Build a topic with prefix."""
  prefix = config.get("MQTT_TOPIC_PREFIX", "vps-bot").strip("/")
  return f"{prefix}/{suffix.strip('/')}"


def mqtt_publish(config, topic, payload, retain=False):
  """Publish an MQTT payload."""
  command = ["mosquitto_pub", *mqtt_base_args(config), "-t", topic, "-m", payload]
  if retain:
    command.append("-r")
  subprocess.run(command, check=False, timeout=20)


def publish_status(config):
  """Publish retained node status."""
  node_id = config["NODE_ID"]
  payload = json.dumps({
    "node_id": node_id,
    "name": config.get("NODE_NAME") or socket.gethostname(),
    "status": "online",
    "ip": get_public_ip(),
    "ts": int(time.time()),
  }, ensure_ascii=False)
  mqtt_publish(config, mqtt_topic(config, f"nodes/{node_id}/status"), payload, retain=True)


def handle_payload(config, raw_payload):
  """Verify and execute one command payload."""
  payload = json.loads(raw_payload)
  if not verify_command_signature(payload, config["COMMAND_SECRET"]):
    return None
  result = execute_allowed_command(config, payload["command"])
  return json.dumps({
    "id": payload.get("id"),
    "node_id": config["NODE_ID"],
    "name": config.get("NODE_NAME") or socket.gethostname(),
    "ok": True,
    "text": result,
    "ts": int(time.time()),
  }, ensure_ascii=False)


def listen(config_path=DEFAULT_CONFIG):
  """Listen for signed MQTT commands."""
  config = load_env(config_path)
  publish_status(config)
  topic = mqtt_topic(config, f"commands/{config['NODE_ID']}")
  command = ["mosquitto_sub", *mqtt_base_args(config), "-v", "-t", topic]
  while True:
    process = subprocess.Popen(
      command,
      stdout=subprocess.PIPE,
      stderr=subprocess.STDOUT,
      text=True,
    )
    try:
      for line in process.stdout or []:
        raw = line.rstrip("\n")
        if " " not in raw:
          continue
        _, payload = raw.split(" ", 1)
        result = handle_payload(config, payload)
        if result:
          mqtt_publish(config, mqtt_topic(config, f"results/{config['NODE_ID']}"), result)
    finally:
      process.kill()
      time.sleep(5)


def register_agent(master_url, token, node_name, config_path=DEFAULT_CONFIG):
  """Register this node against the master web API."""
  data = urllib.parse.urlencode({
    "token": token,
    "name": node_name or socket.gethostname(),
  }).encode("utf-8")
  request = urllib.request.Request(f"{master_url.rstrip('/')}/api/register", data=data)
  with urllib.request.urlopen(request, timeout=30) as response:
    payload = json.loads(response.read().decode("utf-8"))
  write_env(config_path, {
    "NODE_ID": payload["node_id"],
    "NODE_NAME": payload["name"],
    "MQTT_HOST": payload["mqtt_host"],
    "MQTT_PORT": payload["mqtt_port"],
    "MQTT_USERNAME": payload["mqtt_username"],
    "MQTT_PASSWORD": payload["mqtt_password"],
    "MQTT_TOPIC_PREFIX": payload["topic_prefix"],
    "COMMAND_SECRET": payload["command_secret"],
  })
  return payload


def main():
  """CLI entrypoint."""
  parser = argparse.ArgumentParser()
  parser.add_argument("--config", default=DEFAULT_CONFIG)
  sub = parser.add_subparsers(dest="command")
  register = sub.add_parser("register")
  register.add_argument("--master-url", required=True)
  register.add_argument("--token", required=True)
  register.add_argument("--node-name", default="")
  sub.add_parser("listen")
  args = parser.parse_args()

  if args.command == "register":
    payload = register_agent(args.master_url, args.token, args.node_name, args.config)
    print(f"注册成功: {payload['name']} ({payload['node_id']})")
    return
  if args.command == "listen":
    listen(args.config)
    return
  parser.print_help()


if __name__ == "__main__":
  main()

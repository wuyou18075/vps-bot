#!/usr/bin/env python3
"""Telegram command agent for the bot traffic panel."""

import argparse
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request


CONFIG_FILE = os.environ.get("BOT_PANEL_CONFIG", "/etc/bot-panel/config.env")
STATE_DIR = os.environ.get("BOT_PANEL_STATE_DIR", "/var/lib/bot-panel")
LAST_UPDATE_FILE = os.path.join(STATE_DIR, "last_update_id")


def load_config(path=CONFIG_FILE):
  """Load simple KEY=VALUE config files."""
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


def bytes_to_human(value):
  """Convert bytes into a compact human-readable string."""
  size = float(value)
  for unit in ["B", "KB", "MB", "GB", "TB", "PB"]:
    if size < 1024 or unit == "PB":
      return f"{size:.2f} {unit}"
    size = size / 1024
  return f"{size:.2f} PB"


def parse_command(text):
  """Parse Telegram slash commands into command, target, and args."""
  if not text:
    return None

  parts = text.strip().split()
  if not parts or not parts[0].startswith("/"):
    return None

  command = parts[0][1:].split("@", 1)[0].lower()
  target = parts[1] if len(parts) > 1 else None
  args = parts[2:] if len(parts) > 2 else []
  return {
    "command": command,
    "target": target,
    "args": args,
  }


def command_targets_node(parsed, node_name):
  """Return whether a parsed command should run on this node."""
  target = parsed.get("target")
  if target is None:
    return True
  return target in ["all", "*", node_name]


def ensure_state_dir():
  """Create the state directory if it does not exist."""
  os.makedirs(STATE_DIR, mode=0o700, exist_ok=True)


def read_last_update_id():
  """Read the last locally processed Telegram update id."""
  try:
    with open(LAST_UPDATE_FILE, "r", encoding="utf-8") as file:
      return int(file.read().strip())
  except (FileNotFoundError, ValueError):
    return None


def write_last_update_id(update_id):
  """Persist the last locally processed Telegram update id."""
  ensure_state_dir()
  with open(LAST_UPDATE_FILE, "w", encoding="utf-8") as file:
    file.write(str(update_id))


def telegram_api(config, method, data=None, timeout=30):
  """Call a Telegram Bot API method."""
  token = config.get("BOT_TOKEN")
  if not token:
    raise RuntimeError("BOT_TOKEN 未配置")

  url = f"https://api.telegram.org/bot{token}/{method}"
  encoded = None
  headers = {}
  if data is not None:
    encoded = urllib.parse.urlencode(data).encode("utf-8")
    headers["Content-Type"] = "application/x-www-form-urlencoded"

  request = urllib.request.Request(url, data=encoded, headers=headers)
  with urllib.request.urlopen(request, timeout=timeout) as response:
    payload = response.read().decode("utf-8")
  result = json.loads(payload)
  if not result.get("ok"):
    raise RuntimeError(result)
  return result


def send_message(config, text):
  """Send a message to the configured Telegram chat."""
  chat_id = config.get("CHAT_ID")
  if not chat_id:
    raise RuntimeError("CHAT_ID 未配置")

  telegram_api(config, "sendMessage", {
    "chat_id": chat_id,
    "text": text,
    "disable_web_page_preview": "true",
  })


def run_command(command, timeout=60):
  """Run a command safely without shell expansion."""
  try:
    completed = subprocess.run(
      command,
      check=False,
      capture_output=True,
      text=True,
      timeout=timeout,
    )
  except FileNotFoundError:
    return 127, "", f"命令不存在: {command[0]}"
  except subprocess.TimeoutExpired:
    return 124, "", "命令执行超时"
  return completed.returncode, completed.stdout.strip(), completed.stderr.strip()


def get_default_interface():
  """Find the default outbound network interface."""
  code, output, _ = run_command(["ip", "route", "get", "1.1.1.1"], timeout=5)
  if code != 0:
    return ""
  match = re.search(r"\bdev\s+(\S+)", output)
  return match.group(1) if match else ""


def get_public_ip():
  """Fetch public IP with a short timeout."""
  try:
    with urllib.request.urlopen("https://api.ipify.org", timeout=8) as response:
      return response.read().decode("utf-8").strip()
  except (urllib.error.URLError, TimeoutError):
    return "未知"


def get_vnstat_months(data):
  """Extract monthly traffic entries from supported vnStat JSON shapes."""
  if isinstance(data.get("interfaces"), list) and data["interfaces"]:
    traffic = data["interfaces"][0].get("traffic", {})
    return traffic.get("month", [])
  if isinstance(data.get("traffic"), dict):
    return data["traffic"].get("month", [])
  return []


def get_month_traffic_bytes(months):
  """Return rx + tx bytes from the latest vnStat month entry."""
  if not months:
    return 0

  current = months[-1]
  return int(current.get("rx", 0)) + int(current.get("tx", 0))


def get_traffic_usage(config):
  """Read current monthly traffic usage from vnStat."""
  interface = config.get("INTERFACE") or get_default_interface()
  if not interface:
    return "未找到默认网卡"
  if not shutil.which("vnstat"):
    return "vnstat 未安装"

  code, output, error = run_command(["vnstat", "--json", "m", "-i", interface], timeout=10)
  if code != 0:
    return f"读取 vnstat 失败: {error or output}"

  try:
    data = json.loads(output)
    used = get_month_traffic_bytes(get_vnstat_months(data))
  except (KeyError, IndexError, TypeError, ValueError, json.JSONDecodeError):
    return "解析 vnstat 数据失败"

  total_gb = float(config.get("TOTAL_TRAFFIC_GB") or 0)
  total_bytes = int(total_gb * 1024 * 1024 * 1024)
  percent = (used / total_bytes * 100) if total_bytes else 0
  limit_text = bytes_to_human(total_bytes) if total_bytes else "未设置"
  return "\n".join([
    f"网卡: {interface}",
    f"本月已用: {bytes_to_human(used)}",
    f"月总流量: {limit_text}",
    f"使用比例: {percent:.2f}%" if total_bytes else "使用比例: 未设置",
  ])


def get_system_status():
  """Collect basic node resource status."""
  hostname = socket.gethostname()
  code_load, load_output, _ = run_command(["cat", "/proc/loadavg"], timeout=5)
  code_mem, mem_output, _ = run_command(["free", "-h"], timeout=5)
  code_disk, disk_output, _ = run_command(["df", "-h", "/"], timeout=5)

  load = load_output.split()[:3] if code_load == 0 else ["未知"]
  memory = "未知"
  if code_mem == 0:
    lines = mem_output.splitlines()
    if len(lines) >= 2:
      fields = lines[1].split()
      if len(fields) >= 3:
        memory = f"{fields[2]} / {fields[1]}"

  disk = "未知"
  if code_disk == 0:
    lines = disk_output.splitlines()
    if len(lines) >= 2:
      fields = lines[1].split()
      if len(fields) >= 5:
        disk = f"{fields[2]} / {fields[1]} ({fields[4]})"

  return "\n".join([
    f"主机名: {hostname}",
    f"负载: {' '.join(load)}",
    f"内存: {memory}",
    f"磁盘: {disk}",
  ])


def valid_host(value):
  """Allow safe hostnames and IP literals for ping."""
  return bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,252}", value))


def run_ping(args):
  """Run latency checks against safe hosts."""
  hosts = args if args else ["1.1.1.1", "8.8.8.8"]
  lines = []
  for host in hosts[:5]:
    if not valid_host(host):
      lines.append(f"{host}: 非法目标")
      continue
    code, output, error = run_command(["ping", "-c", "4", "-W", "2", host], timeout=15)
    if code != 0:
      lines.append(f"{host}: 失败 ({error or output})")
      continue
    match = re.search(r"rtt min/avg/max/mdev = ([^/]+)/([^/]+)/([^/]+)/", output)
    if match:
      lines.append(f"{host}: avg {match.group(2)} ms")
    else:
      lines.append(f"{host}: {output.splitlines()[-1] if output else '无结果'}")
  return "\n".join(lines)


def run_speedtest():
  """Run a speed test with whichever supported CLI exists."""
  if shutil.which("speedtest"):
    code, output, error = run_command(["speedtest", "--accept-license", "--accept-gdpr"], timeout=180)
  elif shutil.which("speedtest-cli"):
    code, output, error = run_command(["speedtest-cli", "--simple"], timeout=180)
  else:
    return "未安装测速工具。可安装 speedtest-cli 或 Ookla speedtest。"

  if code != 0:
    return f"测速失败: {error or output}"
  return output[-3500:]


def build_report(config, title):
  """Build a full node report message."""
  node_name = config.get("NODE_NAME") or socket.gethostname()
  return "\n".join([
    f"[{node_name}] {title}",
    get_system_status(),
    "",
    get_traffic_usage(config),
  ])


def handle_command(config, text):
  """Execute a supported Telegram command and return a response."""
  parsed = parse_command(text)
  if not parsed:
    return None

  node_name = config.get("NODE_NAME") or socket.gethostname()
  command = parsed["command"]
  args = parsed["args"]

  if command == "ping" and parsed["target"] and parsed["target"] not in ["all", "*", node_name]:
    if parsed["args"]:
      if not command_targets_node(parsed, node_name):
        return None
    else:
      args = [parsed["target"]]
  elif not command_targets_node(parsed, node_name):
    return None

  if command == "ping":
    return f"[{node_name}] Ping 结果\n{run_ping(args)}"
  if command in ["speed", "sudu"]:
    return f"[{node_name}] 测速结果\n{run_speedtest()}"
  if command == "status":
    return build_report(config, "状态")
  if command == "report":
    return build_report(config, "流量汇报")
  if command == "nodes":
    public_ip = get_public_ip()
    return f"[{node_name}] 在线\n公网 IP: {public_ip}"
  if command == "help":
    return "\n".join([
      "支持命令:",
      "/ping [节点名|all] [目标]",
      "/speed [节点名|all]",
      "/sudu [节点名|all]",
      "/status [节点名|all]",
      "/report [节点名|all]",
      "/nodes",
    ])
  return None


def get_recent_updates(config):
  """Fetch recent Telegram updates for local de-duplication."""
  result = telegram_api(config, "getUpdates", {
    "offset": "-100",
    "timeout": "20",
    "allowed_updates": json.dumps(["message"]),
  }, timeout=30)
  return result.get("result", [])


def initialize_last_update(config):
  """Start from the newest current update to avoid replaying old commands."""
  if read_last_update_id() is not None:
    return
  try:
    updates = get_recent_updates(config)
  except Exception:
    return
  if updates:
    write_last_update_id(max(int(item["update_id"]) for item in updates))


def listen(config):
  """Listen for Telegram commands forever."""
  expected_chat_id = str(config.get("CHAT_ID") or "")
  if not expected_chat_id:
    raise RuntimeError("CHAT_ID 未配置")

  initialize_last_update(config)
  node_name = config.get("NODE_NAME") or socket.gethostname()
  send_message(config, f"[{node_name}] 指令监听已启动")

  while True:
    try:
      last_update_id = read_last_update_id()
      updates = get_recent_updates(config)
      max_seen = last_update_id
      for update in updates:
        update_id = int(update.get("update_id", 0))
        if last_update_id is not None and update_id <= last_update_id:
          continue
        max_seen = max(update_id, max_seen or update_id)
        message = update.get("message") or {}
        chat = message.get("chat") or {}
        if str(chat.get("id")) != expected_chat_id:
          continue
        text = message.get("text") or ""
        response = handle_command(config, text)
        if response:
          send_message(config, response)
      if max_seen is not None:
        write_last_update_id(max_seen)
    except Exception as error:
      print(f"监听异常: {error}", file=sys.stderr)
      time.sleep(10)


def main():
  """CLI entrypoint."""
  parser = argparse.ArgumentParser(description="Bot panel Telegram agent")
  parser.add_argument("--listen", action="store_true", help="listen for Telegram commands")
  parser.add_argument("--daily-report", action="store_true", help="send daily traffic report")
  parser.add_argument("--send-test", action="store_true", help="send a test message")
  parser.add_argument("--traffic-report", action="store_true", help="print traffic report")
  args = parser.parse_args()

  config = load_config()
  if args.listen:
    listen(config)
    return
  if args.daily_report:
    send_message(config, build_report(config, "每日流量汇报"))
    return
  if args.send_test:
    send_message(config, build_report(config, "绑定测试"))
    return
  if args.traffic_report:
    print(build_report(config, "流量使用情况"))
    return

  parser.print_help()


if __name__ == "__main__":
  main()

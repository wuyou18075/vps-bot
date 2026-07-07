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
import threading
import time
import urllib.error
import urllib.parse
import urllib.request


CONFIG_FILE = os.environ.get("BOT_PANEL_CONFIG", "/etc/bot-panel/config.env")
STATE_DIR = os.environ.get("BOT_PANEL_STATE_DIR", "/var/lib/bot-panel")
LAST_UPDATE_FILE = os.path.join(STATE_DIR, "last_update_id")
PENDING_SELECT_FILE = os.path.join(STATE_DIR, "pending_select")
SELECTED_NODES_FILE = os.path.join(STATE_DIR, "selected_nodes")
MQTT_NODES_FILE = os.path.join(STATE_DIR, "mqtt_nodes.json")


SELECTED_COMMANDS = [
  "ping", "speed", "sudu", "use", "status", "report",
  "disk", "top", "uptime", "services",
]


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


def parse_node_list(config):
  """Return configured VPS node names."""
  mqtt_nodes = read_mqtt_nodes()
  if mqtt_nodes:
    return mqtt_nodes
  raw_nodes = config.get("NODE_LIST") or config.get("NODE_NAME") or socket.gethostname()
  nodes = []
  for item in re.split(r"[,，\s]+", raw_nodes):
    node = item.strip()
    if node and node not in nodes:
      nodes.append(node)
  return nodes


def control_node_name(config):
  """Return the node responsible for visible selection prompts."""
  return (config.get("CONTROL_NODE") or "").strip()


def is_control_node(config):
  """Return whether this node should answer shared control commands."""
  node_name = config.get("NODE_NAME") or socket.gethostname()
  return node_name == control_node_name(config)


def write_pending_select(enabled=True):
  """Persist whether the next numeric Telegram text should update selection."""
  ensure_state_dir()
  if enabled:
    with open(PENDING_SELECT_FILE, "w", encoding="utf-8") as file:
      file.write("1")
    return
  try:
    os.remove(PENDING_SELECT_FILE)
  except FileNotFoundError:
    pass


def has_pending_select():
  """Return whether a /select prompt is waiting for a numeric reply."""
  return os.path.exists(PENDING_SELECT_FILE)


def read_selected_nodes():
  """Read selected node scope from local state."""
  try:
    with open(SELECTED_NODES_FILE, "r", encoding="utf-8") as file:
      value = file.read().strip()
  except FileNotFoundError:
    return []
  if not value:
    return []
  return [item for item in value.split(",") if item]


def write_selected_nodes(nodes):
  """Persist selected node scope to local state."""
  ensure_state_dir()
  with open(SELECTED_NODES_FILE, "w", encoding="utf-8") as file:
    file.write(",".join(nodes))


def selected_scope_text():
  """Return a human-readable selected scope."""
  selected = read_selected_nodes()
  if not selected or selected == ["all"]:
    return "全部"
  return ",".join(selected)


def command_in_selected_scope(config):
  """Return whether this node should answer selected-scope commands."""
  selected = read_selected_nodes()
  if not selected or selected == ["all"]:
    return True
  node_name = config.get("NODE_NAME") or socket.gethostname()
  return node_name in selected


def mqtt_enabled(config):
  """Return whether MQTT mode is configured."""
  return bool((config.get("MQTT_HOST") or "").strip())


def mqtt_topic(config, suffix):
  """Build an MQTT topic from the configured prefix."""
  prefix = (config.get("MQTT_TOPIC_PREFIX") or "vps-bot").strip().strip("/")
  return f"{prefix}/{suffix.strip('/')}"


def mqtt_base_args(config):
  """Return common mosquitto command arguments."""
  args = [
    "-h", config.get("MQTT_HOST", ""),
    "-p", str(config.get("MQTT_PORT") or "1883"),
  ]
  username = config.get("MQTT_USERNAME") or ""
  password = config.get("MQTT_PASSWORD") or ""
  if username:
    args.extend(["-u", username])
  if password:
    args.extend(["-P", password])
  return args


def mqtt_publish(config, topic, payload, retain=False):
  """Publish a JSON/text payload with mosquitto_pub."""
  command = ["mosquitto_pub", *mqtt_base_args(config), "-t", topic, "-m", payload]
  if retain:
    command.append("-r")
  code, _, error = run_command(command, timeout=20)
  if code != 0:
    log(f"MQTT 发布失败: topic={topic} error={error}")
  return code == 0


def mqtt_publish_json(config, topic, payload, retain=False):
  """Publish JSON payload to MQTT."""
  return mqtt_publish(config, topic, json.dumps(payload, ensure_ascii=False), retain=retain)


def read_mqtt_nodes():
  """Read recently known MQTT nodes."""
  try:
    with open(MQTT_NODES_FILE, "r", encoding="utf-8") as file:
      data = json.load(file)
  except (FileNotFoundError, json.JSONDecodeError):
    return []
  nodes = []
  for node, info in data.items():
    if info.get("status") == "online":
      nodes.append(node)
  return sorted(nodes)


def update_mqtt_node_registry(payload):
  """Persist MQTT node status published by agents."""
  try:
    message = json.loads(payload)
  except json.JSONDecodeError:
    return
  node = (message.get("node") or "").strip()
  if not node:
    return

  try:
    with open(MQTT_NODES_FILE, "r", encoding="utf-8") as file:
      data = json.load(file)
  except (FileNotFoundError, json.JSONDecodeError):
    data = {}

  data[node] = {
    "status": message.get("status") or "online",
    "ip": message.get("ip") or "",
    "ts": int(time.time()),
  }
  ensure_state_dir()
  with open(MQTT_NODES_FILE, "w", encoding="utf-8") as file:
    json.dump(data, file, ensure_ascii=False)


def mqtt_selected_nodes(config):
  """Return selected nodes for MQTT command fan-out."""
  selected = read_selected_nodes()
  if selected and selected != ["all"]:
    return selected
  return parse_node_list(config)


def handle_mqtt_control_command(config, text):
  """Publish a selected-scope Telegram command to MQTT targets."""
  parsed = parse_command(text)
  if not parsed or parsed["command"] not in SELECTED_COMMANDS:
    return None
  if not mqtt_enabled(config) or not is_control_node(config):
    return None

  nodes = mqtt_selected_nodes(config)
  if not nodes:
    return "没有可用 VPS 节点，请等待节点上线或检查 MQTT 配置。"

  command_id = f"{int(time.time() * 1000)}-{os.getpid()}"
  payload = {
    "id": command_id,
    "command": text,
    "ts": int(time.time()),
  }
  for node in nodes:
    mqtt_publish_json(config, mqtt_topic(config, f"commands/{node}"), payload)
  return f"已发送 {text} 到: {','.join(nodes)}"


def handle_mqtt_command_payload(config, payload):
  """Execute a command payload received from MQTT and return result payload."""
  try:
    message = json.loads(payload)
  except json.JSONDecodeError:
    return None
  command_text = message.get("command") or ""
  response = handle_command(config, command_text, from_mqtt=True)
  if not response:
    return None
  return {
    "id": message.get("id"),
    "node": config.get("NODE_NAME") or socket.gethostname(),
    "ok": True,
    "text": response,
    "ts": int(time.time()),
  }


def mqtt_subscribe_process(config, topics):
  """Start mosquitto_sub for the given topics."""
  command = ["mosquitto_sub", *mqtt_base_args(config), "-v"]
  for topic in topics:
    command.extend(["-t", topic])
  return subprocess.Popen(
    command,
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
    text=True,
  )


def iter_mqtt_messages(process):
  """Yield topic and payload pairs from mosquitto_sub -v output."""
  if process.stdout is None:
    return
  for line in process.stdout:
    raw = line.rstrip("\n")
    if " " not in raw:
      continue
    topic, payload = raw.split(" ", 1)
    yield topic, payload


def publish_mqtt_node_status(config):
  """Publish this node's retained online status."""
  node_name = config.get("NODE_NAME") or socket.gethostname()
  payload = {
    "node": node_name,
    "status": "online",
    "ip": get_public_ip(),
    "ts": int(time.time()),
  }
  mqtt_publish_json(config, mqtt_topic(config, f"nodes/{node_name}/status"), payload, retain=True)


def mqtt_command_worker(config):
  """Subscribe to MQTT commands for this node and publish command results."""
  node_name = config.get("NODE_NAME") or socket.gethostname()
  topics = [
    mqtt_topic(config, f"commands/{node_name}"),
    mqtt_topic(config, "commands/all"),
  ]
  while True:
    try:
      process = mqtt_subscribe_process(config, topics)
      for _, payload in iter_mqtt_messages(process):
        result = handle_mqtt_command_payload(config, payload)
        if result:
          mqtt_publish_json(config, mqtt_topic(config, f"results/{node_name}"), result)
    except Exception as error:
      log(f"MQTT 命令监听异常: {error}")
      time.sleep(5)


def mqtt_control_worker(config):
  """Subscribe to MQTT node status and command results for the control node."""
  topics = [
    mqtt_topic(config, "nodes/+/status"),
    mqtt_topic(config, "results/#"),
  ]
  while True:
    try:
      process = mqtt_subscribe_process(config, topics)
      for topic, payload in iter_mqtt_messages(process):
        if "/nodes/" in topic and topic.endswith("/status"):
          update_mqtt_node_registry(payload)
          continue
        if "/results/" in topic:
          try:
            result = json.loads(payload)
          except json.JSONDecodeError:
            continue
          text = result.get("text")
          if text:
            send_message(config, text)
    except Exception as error:
      log(f"MQTT 控制监听异常: {error}")
      time.sleep(5)


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


def command_help_text():
  """Return the supported Telegram command list."""
  return "\n".join([
    f"当前选择: {selected_scope_text()}",
    "支持命令:",
    "/select 选择 VPS 范围",
    "/ping [目标] 测延迟，默认 1.1.1.1 和 8.8.8.8",
    "/use 查看月流量和今日流量",
    "/speed 执行网络测速",
    "/status 查看 CPU/内存/磁盘/负载",
    "/report 查看综合报告",
    "/disk 查看磁盘详情",
    "/top 查看高占用进程",
    "/uptime 查看运行时间和负载",
    "/services 查看关键服务状态",
    "/nodes 查看当前节点在线信息",
    "/help 显示本说明",
    "",
    "使用方式:",
    "1. 发送 /select 选择 VPS 范围。",
    "2. 按编号回复，例如 2,3；回复 99 选择全部；回复 0 清空选择。",
    "3. 再发送 /use、/status、/speed 等命令，选中的 VPS 会分别返回结果。",
  ])


def configure_bot_commands(config):
  """Register Telegram slash commands so clients show a clickable command menu."""
  commands = [
    {"command": "start", "description": "显示快捷指令"},
    {"command": "select", "description": "选择 VPS 范围"},
    {"command": "ping", "description": "Ping 默认目标"},
    {"command": "use", "description": "查看流量使用"},
    {"command": "status", "description": "查看节点状态"},
    {"command": "report", "description": "查看流量汇报"},
    {"command": "speed", "description": "测速"},
    {"command": "disk", "description": "查看磁盘详情"},
    {"command": "top", "description": "查看高占用进程"},
    {"command": "uptime", "description": "查看运行时间"},
    {"command": "services", "description": "查看关键服务"},
    {"command": "nodes", "description": "查看在线节点"},
    {"command": "help", "description": "显示帮助"},
  ]
  telegram_api(config, "setMyCommands", {
    "commands": json.dumps(commands, ensure_ascii=False),
  })


def prepare_listener(config):
  """Prepare Telegram polling and the clickable slash command menu."""
  telegram_api(config, "deleteWebhook", {
    "drop_pending_updates": "false",
  })
  configure_bot_commands(config)


def log(message):
  """Write listener diagnostics to systemd journal/stdout immediately."""
  print(message, file=sys.stderr, flush=True)


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


def get_vnstat_days(data):
  """Extract daily traffic entries from supported vnStat JSON shapes."""
  if isinstance(data.get("interfaces"), list) and data["interfaces"]:
    traffic = data["interfaces"][0].get("traffic", {})
    return traffic.get("day", [])
  if isinstance(data.get("traffic"), dict):
    return data["traffic"].get("day", [])
  return []


def get_month_traffic_bytes(months):
  """Return rx + tx bytes from the latest vnStat month entry."""
  if not months:
    return 0

  current = months[-1]
  return int(current.get("rx", 0)) + int(current.get("tx", 0))


def get_latest_traffic_bytes(entries):
  """Return rx + tx bytes from the latest vnStat traffic entry."""
  if not entries:
    return 0
  current = entries[-1]
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
    today_used = get_latest_traffic_bytes(get_vnstat_days(data))
  except (KeyError, IndexError, TypeError, ValueError, json.JSONDecodeError):
    return "解析 vnstat 数据失败"

  total_gb = float(config.get("TOTAL_TRAFFIC_GB") or 0)
  total_bytes = int(total_gb * 1024 * 1024 * 1024)
  percent = (used / total_bytes * 100) if total_bytes else 0
  limit_text = bytes_to_human(total_bytes) if total_bytes else "未设置"
  return "\n".join([
    f"网卡: {interface}",
    f"本月已用: {bytes_to_human(used)}",
    f"今日已用: {bytes_to_human(today_used)}",
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


def get_disk_detail():
  """Return filesystem usage details."""
  code, output, error = run_command(["df", "-h"], timeout=10)
  if code != 0:
    return f"读取磁盘失败: {error or output}"
  return output[-3500:]


def get_top_processes():
  """Return highest CPU and memory processes."""
  code, output, error = run_command([
    "ps", "-eo", "pid,comm,%cpu,%mem", "--sort=-%cpu",
  ], timeout=10)
  if code != 0:
    return f"读取进程失败: {error or output}"
  return "\n".join(output.splitlines()[:8])


def get_uptime_status():
  """Return uptime and load status."""
  code, output, error = run_command(["uptime", "-p"], timeout=5)
  code_load, load_output, _ = run_command(["cat", "/proc/loadavg"], timeout=5)
  uptime = output if code == 0 else f"读取 uptime 失败: {error or output}"
  load = " ".join(load_output.split()[:3]) if code_load == 0 else "未知"
  return "\n".join([
    f"运行时间: {uptime}",
    f"负载: {load}",
  ])


def get_services_status():
  """Return key service states."""
  services = ["ssh", "cron", "vnstat", "bot-panel-listener"]
  lines = []
  for service in services:
    code, output, _ = run_command(["systemctl", "is-active", service], timeout=5)
    status = output if code == 0 and output else "inactive"
    lines.append(f"{service}: {status}")
  return "\n".join(lines)


def build_report(config, title):
  """Build a full node report message."""
  node_name = config.get("NODE_NAME") or socket.gethostname()
  return "\n".join([
    f"[{node_name}] {title}",
    get_system_status(),
    "",
    get_traffic_usage(config),
  ])


def build_select_menu(config):
  """Build the numbered VPS selection menu."""
  write_pending_select(True)
  lines = [
    f"当前选择: {selected_scope_text()}",
    "",
    "0 清空",
  ]
  for index, node in enumerate(parse_node_list(config), start=1):
    lines.append(f"{index} {node}")
  lines.extend([
    "99 所有",
    "",
    "回复数字，例如: 2,3",
  ])
  return "\n".join(lines)


def apply_selection_reply(config, text):
  """Apply a numeric /select reply and return a control-node confirmation."""
  nodes = parse_node_list(config)
  raw_items = [item.strip() for item in re.split(r"[,，\s]+", text) if item.strip()]
  selected = []

  if not raw_items:
    return "选择无效，请回复数字，例如: 2,3"
  if raw_items == ["0"]:
    write_selected_nodes([])
    write_pending_select(False)
    return "已清空选择，当前范围: 全部"
  if raw_items == ["99"]:
    write_selected_nodes(["all"])
    write_pending_select(False)
    return "已选择: 全部"

  for item in raw_items:
    if not item.isdigit():
      return "选择无效，请回复数字，例如: 2,3"
    index = int(item)
    if index < 1 or index > len(nodes):
      return f"选择无效，请输入 1-{len(nodes)}、0 或 99"
    node = nodes[index - 1]
    if node not in selected:
      selected.append(node)

  write_selected_nodes(selected)
  write_pending_select(False)
  return f"已选择: {','.join(selected)}"


def handle_text(config, text):
  """Handle non-command Telegram text replies."""
  if not has_pending_select():
    return None
  response = apply_selection_reply(config, text.strip())
  if is_control_node(config):
    return response
  return None


def handle_command(config, text, from_mqtt=False):
  """Execute a supported Telegram command and return a response."""
  parsed = parse_command(text)
  if not parsed:
    return None

  node_name = config.get("NODE_NAME") or socket.gethostname()
  command = parsed["command"]
  args = parsed["args"]
  selected_commands = SELECTED_COMMANDS

  if command == "select":
    if is_control_node(config):
      return build_select_menu(config)
    write_pending_select(True)
    return None

  if not from_mqtt and command in selected_commands and not command_in_selected_scope(config):
    return None

  if command == "ping" and parsed["target"] and parsed["target"] not in ["all", "*", node_name]:
    if parsed["args"]:
      if not command_targets_node(parsed, node_name):
        return None
    else:
      args = [parsed["target"]]
  elif not command_targets_node(parsed, node_name):
    return None

  if command in ["start", "help"]:
    return command_help_text()
  if command == "ping":
    return f"[{node_name}] Ping 结果\n{run_ping(args)}"
  if command in ["speed", "sudu"]:
    return f"[{node_name}] 测速结果\n{run_speedtest()}"
  if command == "use":
    return f"[{node_name}] 流量使用情况\n{get_traffic_usage(config)}"
  if command == "status":
    return build_report(config, "状态")
  if command == "report":
    return build_report(config, "流量汇报")
  if command == "nodes":
    public_ip = get_public_ip()
    return f"[{node_name}] 在线\n公网 IP: {public_ip}"
  if command == "disk":
    return f"[{node_name}] 磁盘详情\n{get_disk_detail()}"
  if command == "top":
    return f"[{node_name}] 高占用进程\n{get_top_processes()}"
  if command == "uptime":
    return f"[{node_name}] 运行时间\n{get_uptime_status()}"
  if command == "services":
    return f"[{node_name}] 服务状态\n{get_services_status()}"
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

  node_name = config.get("NODE_NAME") or socket.gethostname()
  if mqtt_enabled(config):
    publish_mqtt_node_status(config)
    threading.Thread(target=mqtt_command_worker, args=(config,), daemon=True).start()
    if not is_control_node(config):
      log(f"[{node_name}] MQTT 节点监听已启动，非控制节点不轮询 Telegram")
      while True:
        time.sleep(3600)
    threading.Thread(target=mqtt_control_worker, args=(config,), daemon=True).start()

  initialize_last_update(config)
  prepare_listener(config)
  if mqtt_enabled(config):
    send_message(config, f"[{node_name}] MQTT 控制监听已启动")
  else:
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
        text = message.get("text") or ""
        log(f"收到更新: update_id={update_id} chat_id={chat.get('id')} text={text!r}")
        if str(chat.get("id")) != expected_chat_id:
          log(f"忽略消息: chat_id={chat.get('id')} 与配置 CHAT_ID={expected_chat_id} 不一致")
          continue
        if mqtt_enabled(config) and text.startswith("/"):
          response = handle_mqtt_control_command(config, text)
          if response is None:
            response = handle_command(config, text)
        else:
          response = handle_command(config, text) if text.startswith("/") else handle_text(config, text)
        if response:
          send_message(config, response)
        else:
          log(f"未生成响应: text={text!r}")
      if max_seen is not None:
        write_last_update_id(max_seen)
    except Exception as error:
      log(f"监听异常: {error}")
      time.sleep(10)


def main():
  """CLI entrypoint."""
  parser = argparse.ArgumentParser(description="Bot panel Telegram agent")
  parser.add_argument("--listen", action="store_true", help="listen for Telegram commands")
  parser.add_argument("--daily-report", action="store_true", help="send daily traffic report")
  parser.add_argument("--send-test", action="store_true", help="send a test message")
  parser.add_argument("--set-commands", action="store_true", help="register Telegram slash commands")
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
    prepare_listener(config)
    send_message(config, build_report(config, "绑定测试"))
    return
  if args.set_commands:
    prepare_listener(config)
    return
  if args.traffic_report:
    print(build_report(config, "流量使用情况"))
    return

  parser.print_help()


if __name__ == "__main__":
  main()

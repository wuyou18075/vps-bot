#!/usr/bin/env python3
"""Secure MQTT master service for VPS monitoring and Telegram control."""

import argparse
import base64
import hashlib
import hmac
import html
import http.cookies
import http.server
import json
import os
import secrets
import socket
import sqlite3
import struct
import subprocess
import threading
import time
import urllib.parse
import urllib.request


APP_NAME = "vps-mqtt"
DEFAULT_CONFIG = "/etc/vps-mqtt/config.env"
DEFAULT_DB = "/var/lib/vps-mqtt/master.db"
DEFAULT_TOPIC_PREFIX = "vps-bot"
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


def random_token(length=32):
  """Return a URL-safe random token."""
  return secrets.token_urlsafe(length)


def b64url(data):
  """Encode bytes with URL-safe base64."""
  return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64url_decode(value):
  """Decode URL-safe base64 with optional missing padding."""
  padding = "=" * (-len(value) % 4)
  return base64.urlsafe_b64decode(value + padding)


def generate_totp_secret():
  """Generate a Google Authenticator compatible TOTP secret."""
  return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def generate_totp_code(secret, now=None, step=30, digits=6):
  """Generate a TOTP code for a secret."""
  timestamp = int(time.time() if now is None else now)
  counter = timestamp // step
  padded = secret + "=" * (-len(secret) % 8)
  key = base64.b32decode(padded, casefold=True)
  digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
  offset = digest[-1] & 0x0F
  code = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
  return str(code % (10 ** digits)).zfill(digits)


def verify_totp(secret, code, now=None, window=1):
  """Verify a TOTP code with a small clock drift window."""
  if not code or not code.isdigit():
    return False
  timestamp = int(time.time() if now is None else now)
  for drift in range(-window, window + 1):
    expected = generate_totp_code(secret, now=timestamp + drift * 30)
    if hmac.compare_digest(expected, code):
      return True
  return False


def hash_password(password, salt=None, iterations=260000):
  """Hash a password with PBKDF2-HMAC-SHA256."""
  if salt is None:
    salt = secrets.token_bytes(16)
  digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
  return f"pbkdf2_sha256${iterations}${b64url(salt)}${b64url(digest)}"


def verify_password(password, encoded):
  """Verify a password hash."""
  try:
    algorithm, raw_iterations, raw_salt, raw_digest = encoded.split("$", 3)
    if algorithm != "pbkdf2_sha256":
      return False
    iterations = int(raw_iterations)
    salt = b64url_decode(raw_salt)
  except (ValueError, TypeError):
    return False
  expected = hash_password(password, salt=salt, iterations=iterations)
  return hmac.compare_digest(expected, encoded)


class LoginRateLimiter:
  """In-memory login rate limiter for web authentication."""

  def __init__(self, limit=5, window_seconds=900):
    self.limit = limit
    self.window_seconds = window_seconds
    self.failures = {}

  def _key(self, ip, username):
    return f"{ip}|{username}"

  def allow(self, ip, username, now=None):
    """Return whether login should be allowed."""
    timestamp = int(time.time() if now is None else now)
    key = self._key(ip, username)
    attempts = [
      item for item in self.failures.get(key, [])
      if timestamp - item < self.window_seconds
    ]
    self.failures[key] = attempts
    return len(attempts) < self.limit

  def record_failure(self, ip, username, now=None):
    """Record a failed login attempt."""
    timestamp = int(time.time() if now is None else now)
    key = self._key(ip, username)
    self.failures.setdefault(key, []).append(timestamp)

  def record_success(self, ip, username):
    """Clear failed attempts after a successful login."""
    self.failures.pop(self._key(ip, username), None)


class RegistrationStore:
  """One-time registration token store used by tests and the web layer."""

  def __init__(self):
    self.tokens = {}

  def create_token(self, ttl_seconds=600, now=None):
    """Create a one-time registration token."""
    timestamp = int(time.time() if now is None else now)
    token = random_token(24)
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    self.tokens[digest] = {
      "expires_at": timestamp + ttl_seconds,
      "used": False,
    }
    return token

  def consume_token(self, token, now=None):
    """Consume a token if it exists, is unused, and is not expired."""
    timestamp = int(time.time() if now is None else now)
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    item = self.tokens.get(digest)
    if not item or item["used"] or item["expires_at"] < timestamp:
      return False
    item["used"] = True
    return True


def command_signature(payload, secret):
  """Return the HMAC signature for a command payload."""
  message = {
    key: payload[key]
    for key in sorted(payload)
    if key != "sig"
  }
  raw = json.dumps(message, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
  key = secret.encode("utf-8")
  return hmac.new(key, raw.encode("utf-8"), hashlib.sha256).hexdigest()


def sign_command(payload, secret):
  """Attach an HMAC signature to a command payload."""
  signed = dict(payload)
  signed["sig"] = command_signature(signed, secret)
  return signed


def render_mosquitto_acl(topic_prefix, nodes):
  """Render a Mosquitto ACL file with per-node isolation."""
  prefix = topic_prefix.strip("/") or DEFAULT_TOPIC_PREFIX
  lines = [
    "user vps_master",
    f"topic readwrite {prefix}/#",
    "",
  ]
  for node in nodes:
    username = node["mqtt_username"]
    node_id = node["node_id"]
    lines.extend([
      f"user {username}",
      f"topic read {prefix}/commands/{node_id}",
      f"topic write {prefix}/nodes/{node_id}/status",
      f"topic write {prefix}/results/{node_id}",
      "",
    ])
  return "\n".join(lines).rstrip() + "\n"


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


class MasterDatabase:
  """SQLite storage for users, nodes, registrations, sessions, and settings."""

  def __init__(self, path=DEFAULT_DB):
    self.path = path
    directory = os.path.dirname(path)
    if directory:
      os.makedirs(directory, mode=0o700, exist_ok=True)
    self.initialize()

  def connect(self):
    """Open a database connection."""
    connection = sqlite3.connect(self.path)
    connection.row_factory = sqlite3.Row
    return connection

  def initialize(self):
    """Create tables if missing."""
    with self.connect() as db:
      db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
          username TEXT PRIMARY KEY,
          password_hash TEXT NOT NULL,
          totp_secret TEXT,
          totp_enabled INTEGER NOT NULL DEFAULT 0,
          created_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sessions (
          token_hash TEXT PRIMARY KEY,
          username TEXT NOT NULL,
          expires_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS registration_tokens (
          token_hash TEXT PRIMARY KEY,
          expires_at INTEGER NOT NULL,
          used_at INTEGER
        );
        CREATE TABLE IF NOT EXISTS nodes (
          node_id TEXT PRIMARY KEY,
          name TEXT NOT NULL,
          mqtt_username TEXT NOT NULL UNIQUE,
          mqtt_password TEXT NOT NULL,
          command_secret TEXT NOT NULL,
          status TEXT NOT NULL DEFAULT 'offline',
          public_ip TEXT,
          created_at INTEGER NOT NULL,
          last_seen INTEGER
        );
        CREATE TABLE IF NOT EXISTS settings (
          key TEXT PRIMARY KEY,
          value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS audit_log (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          ts INTEGER NOT NULL,
          actor TEXT NOT NULL,
          action TEXT NOT NULL,
          detail TEXT NOT NULL
        );
      """)

  def has_admin(self):
    """Return whether an admin user exists."""
    with self.connect() as db:
      row = db.execute("SELECT 1 FROM users LIMIT 1").fetchone()
    return row is not None

  def create_admin(self, username, password):
    """Create or replace the admin user."""
    with self.connect() as db:
      db.execute(
        "INSERT OR REPLACE INTO users(username,password_hash,created_at) VALUES(?,?,?)",
        (username, hash_password(password), int(time.time())),
      )
      db.commit()

  def get_user(self, username):
    """Return a user row as a dict."""
    with self.connect() as db:
      row = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    return dict(row) if row else None

  def enable_totp(self, username, secret):
    """Enable TOTP for a user."""
    with self.connect() as db:
      db.execute(
        "UPDATE users SET totp_secret=?, totp_enabled=1 WHERE username=?",
        (secret, username),
      )
      db.commit()

  def create_session(self, username, ttl_seconds=86400):
    """Create a web session and return the raw session token."""
    token = random_token(32)
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    with self.connect() as db:
      db.execute(
        "INSERT INTO sessions(token_hash,username,expires_at) VALUES(?,?,?)",
        (token_hash, username, int(time.time()) + ttl_seconds),
      )
      db.commit()
    return token

  def session_user(self, token):
    """Return the username for a valid session token."""
    if not token:
      return None
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    with self.connect() as db:
      row = db.execute(
        "SELECT username FROM sessions WHERE token_hash=? AND expires_at>?",
        (token_hash, int(time.time())),
      ).fetchone()
    return row["username"] if row else None

  def create_registration_token(self, ttl_seconds=600):
    """Create a DB-backed one-time registration token."""
    token = random_token(24)
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    with self.connect() as db:
      db.execute(
        "INSERT INTO registration_tokens(token_hash,expires_at) VALUES(?,?)",
        (token_hash, int(time.time()) + ttl_seconds),
      )
      db.commit()
    return token

  def consume_registration_token(self, token):
    """Consume a DB-backed registration token."""
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    now = int(time.time())
    with self.connect() as db:
      row = db.execute(
        "SELECT used_at,expires_at FROM registration_tokens WHERE token_hash=?",
        (token_hash,),
      ).fetchone()
      if not row or row["used_at"] or row["expires_at"] < now:
        return False
      db.execute(
        "UPDATE registration_tokens SET used_at=? WHERE token_hash=?",
        (now, token_hash),
      )
      db.commit()
    return True

  def register_node(self, name):
    """Register a node and return its credentials."""
    safe_name = (name or socket.gethostname()).strip()[:80]
    node_id = b64url(secrets.token_bytes(12))
    credentials = {
      "node_id": node_id,
      "name": safe_name,
      "mqtt_username": f"vps_{node_id}",
      "mqtt_password": random_token(24),
      "command_secret": random_token(32),
    }
    with self.connect() as db:
      db.execute(
        """
        INSERT INTO nodes(
          node_id,name,mqtt_username,mqtt_password,command_secret,created_at
        ) VALUES(?,?,?,?,?,?)
        """,
        (
          credentials["node_id"],
          credentials["name"],
          credentials["mqtt_username"],
          credentials["mqtt_password"],
          credentials["command_secret"],
          int(time.time()),
        ),
      )
      db.commit()
    return credentials

  def list_nodes(self):
    """Return all registered nodes."""
    with self.connect() as db:
      rows = db.execute("SELECT * FROM nodes ORDER BY rowid").fetchall()
    return [dict(row) for row in rows]

  def update_node_status(self, node_id, status, public_ip=""):
    """Update a node's status heartbeat."""
    with self.connect() as db:
      db.execute(
        "UPDATE nodes SET status=?,public_ip=?,last_seen=? WHERE node_id=?",
        (status, public_ip, int(time.time()), node_id),
      )
      db.commit()

  def set_setting(self, key, value):
    """Persist a setting."""
    with self.connect() as db:
      db.execute(
        "INSERT OR REPLACE INTO settings(key,value) VALUES(?,?)",
        (key, value),
      )
      db.commit()

  def get_setting(self, key, default=""):
    """Read a setting."""
    with self.connect() as db:
      row = db.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    return row["value"] if row else default

  def audit(self, actor, action, detail):
    """Write an audit log entry."""
    with self.connect() as db:
      db.execute(
        "INSERT INTO audit_log(ts,actor,action,detail) VALUES(?,?,?,?)",
        (int(time.time()), actor, action, detail),
      )
      db.commit()


def publish_mqtt(config, topic, payload):
  """Publish a payload with mosquitto_pub."""
  command = [
    "mosquitto_pub",
    "-h", config.get("MQTT_HOST", "127.0.0.1"),
    "-p", str(config.get("MQTT_PORT", "1883")),
    "-u", config.get("MQTT_MASTER_USER", "vps_master"),
    "-P", config.get("MQTT_MASTER_PASSWORD", ""),
    "-t", topic,
    "-m", payload,
  ]
  subprocess.run(command, check=False, timeout=20)


def mqtt_base_args(config):
  """Return common mosquitto CLI args."""
  return [
    "-h", config.get("MQTT_HOST", "127.0.0.1"),
    "-p", str(config.get("MQTT_PORT", "1883")),
    "-u", config.get("MQTT_MASTER_USER", "vps_master"),
    "-P", config.get("MQTT_MASTER_PASSWORD", ""),
  ]


def send_telegram(config, text):
  """Send a Telegram message."""
  token = config.get("TELEGRAM_BOT_TOKEN", "")
  chat_id = config.get("TELEGRAM_CHAT_ID", "")
  if not token or not chat_id:
    return
  data = urllib.parse.urlencode({
    "chat_id": chat_id,
    "text": text,
    "disable_web_page_preview": "true",
  }).encode("utf-8")
  request = urllib.request.Request(
    f"https://api.telegram.org/bot{token}/sendMessage",
    data=data,
  )
  urllib.request.urlopen(request, timeout=15).read()


def telegram_api(config, method, data=None, timeout=30):
  """Call Telegram Bot API."""
  token = config.get("TELEGRAM_BOT_TOKEN", "")
  if not token:
    return None
  encoded = None
  if data is not None:
    encoded = urllib.parse.urlencode(data).encode("utf-8")
  request = urllib.request.Request(
    f"https://api.telegram.org/bot{token}/{method}",
    data=encoded,
  )
  with urllib.request.urlopen(request, timeout=timeout) as response:
    return json.loads(response.read().decode("utf-8"))


def telegram_poll_loop(db, config):
  """Poll Telegram and dispatch commands."""
  token = config.get("TELEGRAM_BOT_TOKEN", "")
  chat_id = str(config.get("TELEGRAM_CHAT_ID", ""))
  if not token or not chat_id:
    return
  offset = None
  while True:
    try:
      data = {"timeout": "25"}
      if offset is not None:
        data["offset"] = str(offset)
      result = telegram_api(config, "getUpdates", data=data, timeout=35) or {}
      for update in result.get("result", []):
        offset = update["update_id"] + 1
        message = update.get("message") or {}
        if str((message.get("chat") or {}).get("id")) != chat_id:
          continue
        text = message.get("text") or ""
        response = handle_telegram_text(db, config, text)
        if response:
          send_telegram(config, response)
    except Exception:
      time.sleep(5)


def mqtt_event_loop(db, config):
  """Subscribe to node status and command results."""
  prefix = config.get("MQTT_TOPIC_PREFIX", DEFAULT_TOPIC_PREFIX).strip("/")
  topics = [
    f"{prefix}/nodes/+/status",
    f"{prefix}/results/#",
  ]
  command = ["mosquitto_sub", *mqtt_base_args(config), "-v"]
  for topic in topics:
    command.extend(["-t", topic])
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
        topic, payload = raw.split(" ", 1)
        if f"{prefix}/nodes/" in topic and topic.endswith("/status"):
          try:
            status = json.loads(payload)
          except json.JSONDecodeError:
            continue
          db.update_node_status(
            status.get("node_id", ""),
            status.get("status", "online"),
            status.get("ip", ""),
          )
        elif f"{prefix}/results/" in topic:
          try:
            result = json.loads(payload)
          except json.JSONDecodeError:
            continue
          if result.get("text"):
            send_telegram(config, result["text"])
    except Exception:
      time.sleep(5)
    finally:
      process.kill()


def command_topic(config, node_id):
  """Return MQTT command topic for a node."""
  prefix = config.get("MQTT_TOPIC_PREFIX", DEFAULT_TOPIC_PREFIX).strip("/")
  return f"{prefix}/commands/{node_id}"


def dispatch_command(db, config, node_id, command_text):
  """Sign and dispatch a command to one node."""
  node = next((item for item in db.list_nodes() if item["node_id"] == node_id), None)
  if not node:
    raise ValueError("节点不存在")
  command = command_text.strip().split()[0].lstrip("/")
  if command not in ALLOWED_COMMANDS:
    raise ValueError("命令不在白名单")
  payload = sign_command({
    "id": random_token(12),
    "command": command_text,
    "ts": int(time.time()),
  }, node["command_secret"])
  publish_mqtt(config, command_topic(config, node_id), json.dumps(payload, ensure_ascii=False))
  db.audit("web", "dispatch_command", f"{node['name']} {command_text}")


def telegram_help_text(db):
  """Return Telegram command help text."""
  return "\n".join([
    f"当前选择: {telegram_selected_text(db)}",
    "支持命令:",
    "/select 选择 VPS 范围",
    "/nodes 查看已注册 VPS",
    "/ping [目标]",
    "/use",
    "/speed",
    "/status",
    "/report",
    "/disk",
    "/top",
    "/uptime",
    "/services",
    "/help",
  ])


def telegram_selected_node_ids(db):
  """Return selected node ids for Telegram commands."""
  raw = db.get_setting("telegram_selected_nodes", "")
  if not raw or raw == "all":
    return [node["node_id"] for node in db.list_nodes()]
  ids = [item for item in raw.split(",") if item]
  known = {node["node_id"] for node in db.list_nodes()}
  return [node_id for node_id in ids if node_id in known]


def telegram_selected_text(db):
  """Return selected node names for Telegram help."""
  raw = db.get_setting("telegram_selected_nodes", "")
  if not raw or raw == "all":
    return "全部"
  selected = set(item for item in raw.split(",") if item)
  names = [node["name"] for node in db.list_nodes() if node["node_id"] in selected]
  return ",".join(names) if names else "全部"


def telegram_select_menu(db):
  """Return node selection menu."""
  db.set_setting("telegram_pending_select", "1")
  lines = [f"当前选择: {telegram_selected_text(db)}", "", "0 清空"]
  for index, node in enumerate(db.list_nodes(), start=1):
    lines.append(f"{index} {node['name']}")
  lines.extend(["99 所有", "", "回复数字，例如: 2,3"])
  return "\n".join(lines)


def apply_telegram_selection(db, text):
  """Apply a numeric Telegram selection reply."""
  nodes = db.list_nodes()
  value = text.strip()
  if value == "0":
    db.set_setting("telegram_selected_nodes", "")
    db.set_setting("telegram_pending_select", "")
    return "已清空选择，默认全部"
  if value == "99":
    db.set_setting("telegram_selected_nodes", "all")
    db.set_setting("telegram_pending_select", "")
    return "已选择: 全部"
  selected = []
  for raw_item in value.replace("，", ",").split(","):
    item = raw_item.strip()
    if not item.isdigit():
      return "选择无效，请回复数字，例如: 2,3"
    index = int(item)
    if index < 1 or index > len(nodes):
      return f"选择无效，请输入 1-{len(nodes)}、0 或 99"
    node_id = nodes[index - 1]["node_id"]
    if node_id not in selected:
      selected.append(node_id)
  db.set_setting("telegram_selected_nodes", ",".join(selected))
  db.set_setting("telegram_pending_select", "")
  names = [node["name"] for node in nodes if node["node_id"] in selected]
  return f"已选择: {','.join(names)}"


def telegram_nodes_text(db):
  """Return node list text."""
  nodes = db.list_nodes()
  if not nodes:
    return "暂无已注册 VPS"
  lines = []
  for node in nodes:
    ip = node.get("public_ip") or ""
    lines.append(f"[{node['name']}] {node['status']}\n公网 IP: {ip}")
  return "\n\n".join(lines)


def handle_telegram_text(db, config, text):
  """Handle a Telegram text command for the MQTT master."""
  value = (text or "").strip()
  if db.get_setting("telegram_pending_select", "") == "1" and not value.startswith("/"):
    return apply_telegram_selection(db, value)
  if value in ["/start", "/help", "/"]:
    return telegram_help_text(db)
  if value == "/nodes":
    return telegram_nodes_text(db)
  if value == "/select":
    return telegram_select_menu(db)
  if not value.startswith("/"):
    return None

  command = value.split()[0].lstrip("/").split("@", 1)[0].lower()
  if command not in ALLOWED_COMMANDS:
    return None

  nodes_by_id = {node["node_id"]: node for node in db.list_nodes()}
  selected_ids = telegram_selected_node_ids(db)
  if not selected_ids:
    return "没有可用 VPS 节点"
  sent_names = []
  for node_id in selected_ids:
    dispatch_command(db, config, node_id, value)
    sent_names.append(nodes_by_id[node_id]["name"])
  return f"已发送 {value} 到: {','.join(sent_names)}"


class MasterRequestHandler(http.server.BaseHTTPRequestHandler):
  """Small secure web/API handler."""

  rate_limiter = LoginRateLimiter()

  def server_version(self):
    return "VpsMqttMaster/1.0"

  @property
  def db(self):
    return self.server.db

  @property
  def config(self):
    return self.server.config

  def log_message(self, fmt, *args):
    return

  def read_form(self):
    """Read URL-encoded form data."""
    length = int(self.headers.get("Content-Length", "0"))
    raw = self.rfile.read(length).decode("utf-8")
    return {
      key: values[0]
      for key, values in urllib.parse.parse_qs(raw, keep_blank_values=True).items()
    }

  def current_user(self):
    """Return current session user."""
    cookie = http.cookies.SimpleCookie(self.headers.get("Cookie", ""))
    token = cookie.get("session")
    return self.db.session_user(token.value) if token else None

  def send_html(self, body, status=200):
    """Send an HTML response with security headers."""
    payload = body.encode("utf-8")
    self.send_response(status)
    self.send_header("Content-Type", "text/html; charset=utf-8")
    self.send_header("Content-Length", str(len(payload)))
    self.send_header("X-Frame-Options", "DENY")
    self.send_header("X-Content-Type-Options", "nosniff")
    self.send_header("Referrer-Policy", "no-referrer")
    self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'")
    self.end_headers()
    self.wfile.write(payload)

  def redirect(self, path):
    """Redirect to path."""
    self.send_response(303)
    self.send_header("Location", path)
    self.end_headers()

  def require_user(self):
    """Require an authenticated user."""
    user = self.current_user()
    if not user:
      self.redirect("/login")
      return None
    return user

  def page(self, title, content):
    """Wrap content in a minimal panel layout."""
    return f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{html.escape(title)}</title>
  <style>
    body {{ margin: 0; font-family: system-ui, sans-serif; background: #f6f7f9; color: #15171a; }}
    main {{ max-width: 980px; margin: 32px auto; padding: 0 18px; }}
    section, form {{ background: #fff; border: 1px solid #d9dde3; border-radius: 8px; padding: 18px; margin: 14px 0; }}
    input, select, button {{ font: inherit; padding: 9px 10px; margin: 5px 0; }}
    input, select {{ width: min(420px, 100%); border: 1px solid #bcc3cc; border-radius: 6px; }}
    button {{ border: 0; border-radius: 6px; background: #155eef; color: #fff; cursor: pointer; }}
    table {{ width: 100%; border-collapse: collapse; background: #fff; }}
    th, td {{ border-bottom: 1px solid #e2e5ea; padding: 9px; text-align: left; }}
    .muted {{ color: #646b75; }}
  </style>
</head>
<body><main>{content}</main></body></html>"""

  def do_GET(self):
    """Handle GET requests."""
    if self.path == "/health":
      self.send_html("ok")
      return
    if self.path == "/login":
      self.send_html(self.render_login())
      return
    if self.path == "/setup":
      if self.db.has_admin():
        self.redirect("/login")
        return
      self.send_html(self.render_setup())
      return
    if self.path == "/totp":
      user = self.require_user()
      if not user:
        return
      self.send_html(self.render_totp(user))
      return
    if self.path == "/":
      user = self.require_user()
      if not user:
        return
      self.send_html(self.render_dashboard(user))
      return
    self.send_error(404)

  def do_POST(self):
    """Handle POST requests."""
    if self.path == "/api/register":
      self.handle_register_api()
      return
    if self.path == "/setup":
      self.handle_setup()
      return
    if self.path == "/login":
      self.handle_login()
      return
    user = self.require_user()
    if not user:
      return
    if self.path == "/totp":
      self.handle_totp(user)
      return
    if self.path == "/telegram":
      self.handle_telegram(user)
      return
    if self.path == "/command":
      self.handle_command(user)
      return
    self.send_error(404)

  def render_setup(self):
    """Render first-run setup."""
    return self.page("初始化管理员", """
<h1>初始化管理员</h1>
<form method="post" action="/setup">
  <label>用户名<br><input name="username" value="admin" required></label><br>
  <label>密码<br><input name="password" type="password" required minlength="12"></label><br>
  <button type="submit">创建管理员</button>
</form>""")

  def handle_setup(self):
    """Create first admin."""
    if self.db.has_admin():
      self.redirect("/login")
      return
    form = self.read_form()
    password = form.get("password", "")
    if len(password) < 12:
      self.send_html(self.page("初始化失败", "<p>密码至少 12 位。</p>"), status=400)
      return
    username = form.get("username", "admin").strip() or "admin"
    self.db.create_admin(username, password)
    self.db.audit(username, "create_admin", "first setup")
    self.redirect("/login")

  def render_login(self, message=""):
    """Render login page."""
    notice = f"<p>{html.escape(message)}</p>" if message else ""
    return self.page("登录", f"""
<h1>VPS MQTT 面板</h1>
{notice}
<form method="post" action="/login">
  <label>用户名<br><input name="username" required></label><br>
  <label>密码<br><input name="password" type="password" required></label><br>
  <label>双重验证码<br><input name="totp" inputmode="numeric" autocomplete="one-time-code"></label><br>
  <button type="submit">登录</button>
</form>""")

  def handle_login(self):
    """Authenticate user with optional TOTP."""
    form = self.read_form()
    username = form.get("username", "")
    password = form.get("password", "")
    remote_ip = self.client_address[0]
    if not self.rate_limiter.allow(remote_ip, username):
      self.send_html(self.render_login("登录失败，请稍后再试。"), status=429)
      return
    user = self.db.get_user(username)
    valid = bool(user and verify_password(password, user["password_hash"]))
    if valid and user["totp_enabled"]:
      valid = verify_totp(user["totp_secret"], form.get("totp", ""))
    if not valid:
      self.rate_limiter.record_failure(remote_ip, username)
      self.send_html(self.render_login("登录失败。"), status=401)
      return
    self.rate_limiter.record_success(remote_ip, username)
    session = self.db.create_session(username)
    self.send_response(303)
    self.send_header("Location", "/")
    self.send_header(
      "Set-Cookie",
      f"session={session}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=86400",
    )
    self.end_headers()

  def render_dashboard(self, user):
    """Render dashboard."""
    nodes = self.db.list_nodes()
    rows = "\n".join([
      "<tr>"
      f"<td>{html.escape(item['name'])}</td>"
      f"<td>{html.escape(item['status'])}</td>"
      f"<td>{html.escape(item.get('public_ip') or '')}</td>"
      f"<td><form method='post' action='/command'>"
      f"<input type='hidden' name='node_id' value='{html.escape(item['node_id'])}'>"
      "<select name='command'>"
      "<option>/status</option><option>/use</option><option>/speed</option>"
      "<option>/disk</option><option>/top</option><option>/uptime</option>"
      "<option>/services</option>"
      "</select> <button>执行</button></form></td>"
      "</tr>"
      for item in nodes
    ])
    online = sum(1 for item in nodes if item["status"] == "online")
    return self.page("VPS MQTT 面板", f"""
<h1>VPS MQTT 面板</h1>
<p class="muted">当前用户: {html.escape(user)}</p>
<section>
  <strong>在线 VPS:</strong> {online} / {len(nodes)}
  <br><a href="/totp">绑定或更新 Google Authenticator</a>
</section>
<section>
  <h2>Telegram</h2>
  <form method="post" action="/telegram">
    <label>Bot Token<br><input name="token" value="{html.escape(self.db.get_setting('telegram_token'))}"></label><br>
    <label>Chat ID<br><input name="chat_id" value="{html.escape(self.db.get_setting('telegram_chat_id'))}"></label><br>
    <button>保存</button>
  </form>
</section>
<section>
  <h2>已注册 VPS</h2>
  <table><thead><tr><th>节点</th><th>状态</th><th>公网 IP</th><th>操作</th></tr></thead><tbody>{rows}</tbody></table>
</section>""")

  def render_totp(self, user):
    """Render TOTP binding page."""
    secret = generate_totp_secret()
    issuer = urllib.parse.quote(APP_NAME)
    account = urllib.parse.quote(user)
    uri = f"otpauth://totp/{issuer}:{account}?secret={secret}&issuer={issuer}"
    return self.page("双重认证", f"""
<h1>绑定 Google Authenticator</h1>
<section>
  <p>在 Google Authenticator 中手动输入密钥：</p>
  <pre>{html.escape(secret)}</pre>
  <p class="muted">{html.escape(uri)}</p>
</section>
<form method="post" action="/totp">
  <input type="hidden" name="secret" value="{html.escape(secret)}">
  <label>验证码<br><input name="code" inputmode="numeric" required></label><br>
  <button>开启双重认证</button>
</form>""")

  def handle_totp(self, user):
    """Enable TOTP after verifying the current code."""
    form = self.read_form()
    secret = form.get("secret", "")
    if not verify_totp(secret, form.get("code", "")):
      self.send_html(self.page("绑定失败", "<p>验证码错误。</p>"), status=400)
      return
    self.db.enable_totp(user, secret)
    self.db.audit(user, "enable_totp", "enabled")
    self.redirect("/")

  def handle_telegram(self, user):
    """Save Telegram settings."""
    form = self.read_form()
    self.db.set_setting("telegram_token", form.get("token", ""))
    self.db.set_setting("telegram_chat_id", form.get("chat_id", ""))
    self.db.audit(user, "save_telegram", "updated")
    self.redirect("/")

  def handle_command(self, user):
    """Dispatch a whitelisted command."""
    form = self.read_form()
    try:
      dispatch_command(self.db, self.config, form.get("node_id", ""), form.get("command", ""))
    except ValueError as error:
      self.send_html(self.page("命令失败", f"<p>{html.escape(str(error))}</p>"), status=400)
      return
    self.db.audit(user, "web_command", form.get("command", ""))
    self.redirect("/")

  def handle_register_api(self):
    """Register an agent using a one-time token."""
    form = self.read_form()
    token = form.get("token", "")
    if not self.db.consume_registration_token(token):
      self.send_response(403)
      self.end_headers()
      return
    node = self.db.register_node(form.get("name", "vps"))
    response = {
      **node,
      "mqtt_host": self.config.get("MQTT_HOST", "127.0.0.1"),
      "mqtt_port": self.config.get("MQTT_PORT", "1883"),
      "topic_prefix": self.config.get("MQTT_TOPIC_PREFIX", DEFAULT_TOPIC_PREFIX),
    }
    payload = json.dumps(response, ensure_ascii=False).encode("utf-8")
    self.send_response(200)
    self.send_header("Content-Type", "application/json; charset=utf-8")
    self.send_header("Content-Length", str(len(payload)))
    self.end_headers()
    self.wfile.write(payload)


class MasterHTTPServer(http.server.ThreadingHTTPServer):
  """HTTP server carrying config and DB state."""

  def __init__(self, address, handler, db, config):
    super().__init__(address, handler)
    self.db = db
    self.config = config


def serve(config_path=DEFAULT_CONFIG, db_path=DEFAULT_DB):
  """Run the master web server."""
  config = load_env(config_path)
  db = MasterDatabase(db_path)
  host = config.get("WEB_HOST", "127.0.0.1")
  port = int(config.get("WEB_PORT", "8088"))
  server = MasterHTTPServer((host, port), MasterRequestHandler, db, config)
  threading.Thread(target=mqtt_event_loop, args=(db, config), daemon=True).start()
  threading.Thread(target=telegram_poll_loop, args=(db, config), daemon=True).start()
  server.serve_forever()


def create_registration_command(config_path=DEFAULT_CONFIG, db_path=DEFAULT_DB, name=""):
  """Create a shell command for registering a VPS agent."""
  config = load_env(config_path)
  db = MasterDatabase(db_path)
  token = db.create_registration_token()
  public_url = config.get("PUBLIC_URL", "").rstrip("/")
  raw_base = config.get(
    "RAW_BASE_URL",
    "https://raw.githubusercontent.com/wuyou18075/vps-bot/refs/heads/main",
  ).rstrip("/")
  node_arg = f" --node-name {sh_quote(name)}" if name else ""
  return (
    "bash <(curl -fsSL "
    f"{sh_quote(raw_base + '/mqtt.sh')}) register-agent "
    f"--master-url {sh_quote(public_url)} --token {sh_quote(token)}{node_arg}"
  )


def sh_quote(value):
  """Return a single-quoted shell token."""
  return "'" + value.replace("'", "'\"'\"'") + "'"


def main():
  """CLI entrypoint."""
  parser = argparse.ArgumentParser()
  parser.add_argument("--config", default=DEFAULT_CONFIG)
  parser.add_argument("--db", default=DEFAULT_DB)
  sub = parser.add_subparsers(dest="command")
  sub.add_parser("serve")
  token_parser = sub.add_parser("registration-command")
  token_parser.add_argument("--name", default="")
  args = parser.parse_args()

  if args.command == "serve":
    serve(args.config, args.db)
    return
  if args.command == "registration-command":
    print(create_registration_command(args.config, args.db, args.name))
    return
  parser.print_help()


if __name__ == "__main__":
  main()

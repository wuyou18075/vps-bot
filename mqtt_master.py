#!/usr/bin/env python3
"""Secure MQTT master service for VPS monitoring and Telegram control."""

import argparse
import asyncio
import base64
from contextlib import contextmanager
import hashlib
import hmac
import html
import http.cookies
import http.server
import json
import os
import pwd
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
DEFAULT_MOSQUITTO_ACL = "/etc/mosquitto/vps-mqtt.acl"
DEFAULT_MOSQUITTO_PASSWD = "/etc/mosquitto/vps-mqtt.passwd"
DEFAULT_MONITOR_MINUTES = 3
REALTIME_MONITOR_INTERVAL_SECONDS = 5
REALTIME_WS_PUSH_SECONDS = 2
RUNTIME_SETTING_KEYS = [
  "PUBLIC_URL",
  "RAW_BASE_URL",
  "MQTT_HOST",
  "MQTT_LOCAL_HOST",
  "MQTT_PORT",
  "MQTT_TOPIC_PREFIX",
  "MQTT_MASTER_USER",
  "MQTT_MASTER_PASSWORD",
  "MOSQUITTO_ACL",
  "MOSQUITTO_PASSWD",
  "WEB_HOST",
  "WEB_PORT",
]
ALLOWED_COMMANDS = {
  "ping",
  "use",
  "snapshot",
  "speed",
  "status",
  "report",
  "disk",
  "top",
  "uptime",
  "services",
  "uninstall-agent",
}
SUPPORTED_THEMES = {
  "light": "白色",
  "dark": "黑色",
  "eye": "护眼绿",
  "blue": "浅蓝色",
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


def qr_svg_data_uri(value):
  """Render a QR code as a local SVG data URI using qrencode."""
  result = subprocess.run(
    ["qrencode", "-t", "SVG", "-o", "-", value],
    capture_output=True,
    check=False,
  )
  if result.returncode != 0:
    return ""
  encoded = base64.b64encode(result.stdout).decode("ascii")
  return f"data:image/svg+xml;base64,{encoded}"


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


def is_https_headers(headers):
  """Return whether proxy headers indicate HTTPS."""
  return (headers.get("X-Forwarded-Proto", "").lower() == "https"
          or headers.get("X-Forwarded-Ssl", "").lower() == "on")


def build_session_cookie_value(session, headers):
  """Build a session cookie value for HTTP or HTTPS deployments."""
  secure = "; Secure" if is_https_headers(headers) else ""
  return f"session={session}; HttpOnly; SameSite=Strict; Path=/; Max-Age=86400{secure}"


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
      f"topic write {prefix}/health/{node_id}",
      "",
    ])
  return "\n".join(lines).rstrip() + "\n"


def refresh_mqtt_auth(db, config):
  """Rewrite Mosquitto password and ACL files from registered nodes."""
  acl_path = config.get("MOSQUITTO_ACL", "") or DEFAULT_MOSQUITTO_ACL
  passwd_path = config.get("MOSQUITTO_PASSWD", "") or DEFAULT_MOSQUITTO_PASSWD
  nodes = db.list_nodes()
  try:
    os.makedirs(os.path.dirname(acl_path), mode=0o755, exist_ok=True)
    os.makedirs(os.path.dirname(passwd_path), mode=0o755, exist_ok=True)
    with open(acl_path, "w", encoding="utf-8") as file:
      file.write(render_mosquitto_acl(config.get("MQTT_TOPIC_PREFIX", DEFAULT_TOPIC_PREFIX), nodes))
    open(passwd_path, "w", encoding="utf-8").close()
    set_mosquitto_file_permissions(acl_path, passwd_path)
  except OSError:
    return False
  users = [(
    config.get("MQTT_MASTER_USER", "vps_master"),
    config.get("MQTT_MASTER_PASSWORD", ""),
  )]
  users.extend((node["mqtt_username"], node["mqtt_password"]) for node in nodes)
  for index, (username, password) in enumerate(users):
    command = ["mosquitto_passwd", "-b"]
    if index == 0:
      command.append("-c")
    command.extend([passwd_path, username, password])
    result = subprocess.run(
      command,
      check=False,
      capture_output=True,
    )
    if command_failed(result):
      return False
  restart = subprocess.run(["systemctl", "restart", "mosquitto"], check=False, capture_output=True)
  if command_failed(restart):
    return False
  return True


def command_failed(result):
  """Return whether a subprocess result definitely failed."""
  returncode = getattr(result, "returncode", 0)
  return isinstance(returncode, int) and returncode != 0


def set_mosquitto_file_permissions(*paths):
  """Make Mosquitto auth files readable by the broker without making them public."""
  try:
    mosquitto = pwd.getpwnam("mosquitto")
  except KeyError:
    mosquitto = None
  for path in paths:
    os.chmod(path, 0o640)
    if mosquitto:
      os.chown(path, 0, mosquitto.pw_gid)


def verify_node_mqtt_auth(config, node, attempts=5, delay_seconds=1):
  """Verify newly issued node credentials against the local broker."""
  prefix = config.get("MQTT_TOPIC_PREFIX", DEFAULT_TOPIC_PREFIX).strip("/")
  topic = f"{prefix}/health/{node['node_id']}"
  payload = json.dumps({
    "node_id": node["node_id"],
    "ts": int(time.time()),
    "check": "register",
  }, ensure_ascii=False)
  last_error = ""
  for attempt in range(max(1, attempts)):
    try:
      result = subprocess.run(
        [
          "mosquitto_pub",
          "-h", master_mqtt_host(config),
          "-p", str(config.get("MQTT_PORT", "1883")),
          "-u", node["mqtt_username"],
          "-P", node["mqtt_password"],
          "-t", topic,
          "-m", payload,
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
      )
    except FileNotFoundError:
      return False, "mosquitto_pub 未安装或不可执行"
    except subprocess.TimeoutExpired:
      last_error = "mosquitto_pub 执行超时"
    else:
      if result.returncode == 0:
        return True, ""
      last_error = (result.stderr or result.stdout or f"mosquitto_pub exit {result.returncode}").strip()
    if attempt < max(1, attempts) - 1:
      time.sleep(delay_seconds)
  return False, last_error


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


def runtime_config(db, file_config):
  """Merge file config with DB-persisted runtime settings for upgraded installs."""
  config = dict(file_config)
  for key in RUNTIME_SETTING_KEYS:
    if not config.get(key):
      value = db.get_setting(key, "")
      if value:
        config[key] = value
  config.setdefault("MOSQUITTO_ACL", DEFAULT_MOSQUITTO_ACL)
  config.setdefault("MOSQUITTO_PASSWD", DEFAULT_MOSQUITTO_PASSWD)
  return config


class MasterDatabase:
  """SQLite storage for users, nodes, registrations, sessions, and settings."""

  def __init__(self, path=DEFAULT_DB):
    self.path = path
    directory = os.path.dirname(path)
    if directory:
      os.makedirs(directory, mode=0o700, exist_ok=True)
    self.initialize()

  @contextmanager
  def connect(self):
    """Open a database connection."""
    connection = sqlite3.connect(self.path)
    connection.row_factory = sqlite3.Row
    try:
      yield connection
      connection.commit()
    except Exception:
      connection.rollback()
      raise
    finally:
      connection.close()

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
        CREATE TABLE IF NOT EXISTS command_results (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          command_id TEXT,
          node_id TEXT NOT NULL,
          command TEXT NOT NULL,
          ok INTEGER NOT NULL,
          text TEXT NOT NULL,
          ts INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS node_snapshots (
          node_id TEXT PRIMARY KEY,
          monthly_used_gb REAL NOT NULL DEFAULT 0,
          daily_used_gb REAL NOT NULL DEFAULT 0,
          network_rx_mbps REAL NOT NULL DEFAULT 0,
          network_tx_mbps REAL NOT NULL DEFAULT 0,
          cpu_percent REAL NOT NULL DEFAULT 0,
          memory_percent REAL NOT NULL DEFAULT 0,
          latency_ms REAL NOT NULL DEFAULT 0,
          ts INTEGER NOT NULL
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
      self.ensure_column(db, "nodes", "group_name", "TEXT NOT NULL DEFAULT ''")
      self.ensure_column(db, "nodes", "sort_order", "INTEGER NOT NULL DEFAULT 0")
      self.ensure_column(db, "nodes", "traffic_total_gb", "REAL NOT NULL DEFAULT 0")
      self.ensure_column(db, "nodes", "traffic_alert_percent", "REAL NOT NULL DEFAULT 80")
      self.ensure_column(db, "nodes", "daily_report_time", "TEXT NOT NULL DEFAULT ''")
      self.ensure_column(db, "nodes", "monthly_report_time", "TEXT NOT NULL DEFAULT ''")

  def ensure_column(self, db, table, column, definition):
    """Add a column to an existing SQLite table when missing."""
    existing = {row["name"] for row in db.execute(f"PRAGMA table_info({table})").fetchall()}
    if column not in existing:
      db.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")

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
      rows = db.execute(
        "SELECT * FROM nodes ORDER BY group_name COLLATE NOCASE, sort_order, rowid",
      ).fetchall()
    return [dict(row) for row in rows]

  def update_node_profile(self, node_id, values):
    """Update editable node profile fields."""
    with self.connect() as db:
      db.execute(
        """
        UPDATE nodes
        SET name=?,group_name=?,sort_order=?,traffic_total_gb=?,
            traffic_alert_percent=?,daily_report_time=?,monthly_report_time=?
        WHERE node_id=?
        """,
        (
          values["name"],
          values["group_name"],
          values["sort_order"],
          values["traffic_total_gb"],
          values["traffic_alert_percent"],
          values["daily_report_time"],
          values["monthly_report_time"],
          node_id,
        ),
      )
      db.commit()

  def update_node_status(self, node_id, status, public_ip=""):
    """Update a node's status heartbeat."""
    with self.connect() as db:
      db.execute(
        "UPDATE nodes SET status=?,public_ip=?,last_seen=? WHERE node_id=?",
        (status, public_ip, int(time.time()), node_id),
      )
      db.commit()

  def delete_node(self, node_id):
    """Delete a registered node."""
    with self.connect() as db:
      db.execute("DELETE FROM nodes WHERE node_id=?", (node_id,))
      db.execute("DELETE FROM node_snapshots WHERE node_id=?", (node_id,))
      db.commit()

  def store_command_result(self, payload):
    """Store a command result and its structured snapshot metrics."""
    node_id = payload.get("node_id", "")
    command = payload.get("command", "")
    ts = int(payload.get("ts") or time.time())
    with self.connect() as db:
      db.execute(
        "UPDATE nodes SET status='online',last_seen=? WHERE node_id=?",
        (ts, node_id),
      )
      db.execute(
        """
        INSERT INTO command_results(command_id,node_id,command,ok,text,ts)
        VALUES(?,?,?,?,?,?)
        """,
        (
          payload.get("id", ""),
          node_id,
          command,
          1 if payload.get("ok") else 0,
          payload.get("text", ""),
          ts,
        ),
      )
      metrics = payload.get("metrics") or {}
      if metrics:
        db.execute(
          """
          INSERT OR REPLACE INTO node_snapshots(
            node_id,monthly_used_gb,daily_used_gb,network_rx_mbps,network_tx_mbps,
            cpu_percent,memory_percent,latency_ms,ts
          ) VALUES(?,?,?,?,?,?,?,?,?)
          """,
          (
            node_id,
            float(metrics.get("monthly_used_gb") or 0),
            float(metrics.get("daily_used_gb") or 0),
            float(metrics.get("network_rx_mbps") or 0),
            float(metrics.get("network_tx_mbps") or 0),
            float(metrics.get("cpu_percent") or 0),
            float(metrics.get("memory_percent") or 0),
            float(metrics.get("latency_ms") or 0),
            ts,
          ),
        )
      db.commit()

  def latest_node_snapshots(self):
    """Return nodes with their latest monitoring snapshot."""
    with self.connect() as db:
      rows = db.execute(
        """
        SELECT n.*,s.monthly_used_gb,s.daily_used_gb,s.network_rx_mbps,
               s.network_tx_mbps,s.cpu_percent,s.memory_percent,s.latency_ms,s.ts AS snapshot_ts
        FROM nodes n
        LEFT JOIN node_snapshots s ON s.node_id=n.node_id
        ORDER BY n.group_name COLLATE NOCASE,n.sort_order,n.rowid
        """,
      ).fetchall()
    return [dict(row) for row in rows]

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
    "-h", master_mqtt_host(config),
    "-p", str(config.get("MQTT_PORT", "1883")),
    "-u", config.get("MQTT_MASTER_USER", "vps_master"),
    "-P", config.get("MQTT_MASTER_PASSWORD", ""),
    "-t", topic,
    "-m", payload,
  ]
  try:
    subprocess.run(command, check=False, timeout=20)
  except (FileNotFoundError, subprocess.TimeoutExpired):
    return


def master_mqtt_host(config):
  """Return the broker host used by the master process itself."""
  return config.get("MQTT_LOCAL_HOST") or "127.0.0.1"


def mqtt_base_args(config):
  """Return common mosquitto CLI args."""
  return [
    "-h", master_mqtt_host(config),
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


def send_telegram_test(token, chat_id):
  """Send a Telegram connectivity test message."""
  if not token or not chat_id:
    return False
  data = urllib.parse.urlencode({
    "chat_id": chat_id,
    "text": "VPS MQTT 面板 Telegram 绑定测试成功",
    "disable_web_page_preview": "true",
  }).encode("utf-8")
  request = urllib.request.Request(
    f"https://api.telegram.org/bot{token}/sendMessage",
    data=data,
  )
  try:
    with urllib.request.urlopen(request, timeout=15) as response:
      payload = json.loads(response.read().decode("utf-8"))
  except Exception:
    return False
  return bool(payload.get("ok"))


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
          db.store_command_result(result)
          if result.get("command") == "snapshot":
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


def save_theme(db, theme):
  """Persist a supported web theme."""
  value = (theme or "").strip()
  if value not in SUPPORTED_THEMES:
    return False
  db.set_setting("web_theme", value)
  return True


def save_telegram_settings(db, username, form):
  """Persist Telegram settings after verifying the current login password."""
  user = db.get_user(username)
  if not user or not verify_password(form.get("current_password", ""), user["password_hash"]):
    return False, "登录密码错误，未保存 Telegram 配置。"
  token = form.get("token", "").strip()
  chat_id = form.get("chat_id", "").strip()
  if not send_telegram_test(token, chat_id):
    return False, "Telegram 连通性验证失败，请检查 Bot Token 和 Chat ID。"
  db.set_setting("telegram_token", token)
  db.set_setting("telegram_chat_id", chat_id)
  db.audit(username, "save_telegram", "updated and tested")
  return True, "Telegram 绑定成功，测试消息已发送。"


def delete_telegram_settings(db, username, current_password):
  """Delete Telegram binding after verifying the current login password."""
  user = db.get_user(username)
  if not user or not verify_password(current_password or "", user["password_hash"]):
    return False, "登录密码错误，未删除 Telegram 配置。"
  db.set_setting("telegram_token", "")
  db.set_setting("telegram_chat_id", "")
  db.audit(username, "delete_telegram", "deleted")
  return True, "Telegram 绑定已删除。"


def parse_float_field(value, default=0.0):
  """Parse a non-negative float form field."""
  raw = str(value or "").strip()
  if not raw:
    return default
  number = float(raw)
  if number < 0:
    raise ValueError("数值不能小于 0")
  return number


def parse_int_field(value, default=0):
  """Parse an integer form field."""
  raw = str(value or "").strip()
  if not raw:
    return default
  return int(raw)


def update_node_profile(db, node_id, form):
  """Validate and persist editable node fields."""
  name = (form.get("name") or "").strip()[:80]
  if not name:
    return False, "节点名称不能为空。"
  try:
    values = {
      "name": name,
      "group_name": (form.get("group_name") or "").strip()[:80],
      "sort_order": parse_int_field(form.get("sort_order"), 0),
      "traffic_total_gb": parse_float_field(form.get("traffic_total_gb"), 0),
      "traffic_alert_percent": min(parse_float_field(form.get("traffic_alert_percent"), 80), 100),
      "daily_report_time": (form.get("daily_report_time") or "").strip()[:20],
      "monthly_report_time": (form.get("monthly_report_time") or "").strip()[:20],
    }
  except ValueError:
    return False, "节点配置格式不正确。"
  db.update_node_profile(node_id, values)
  db.audit("web", "update_node_profile", name)
  return True, "节点配置已保存。"


def create_registration_command_for_web(db, config, name=""):
  """Create a copyable registration command from current web settings."""
  token = db.create_registration_token()
  public_url = (config.get("PUBLIC_URL") or db.get_setting("PUBLIC_URL", "")).rstrip("/")
  raw_base = (
    config.get("RAW_BASE_URL")
    or db.get_setting("RAW_BASE_URL", "")
    or "https://raw.githubusercontent.com/wuyou18075/vps-bot/refs/heads/main"
  ).rstrip("/")
  node_arg = f" --node-name {sh_quote(name)}" if name else ""
  return (
    "bash <(curl -fsSL "
    f"{sh_quote(raw_base + '/mqtt.sh')}) register-agent "
    f"--master-url {sh_quote(public_url)} --token {sh_quote(token)}{node_arg}"
  )


def register_node_from_agent(db, config, form):
  """Register an agent and replace its previous node record when provided."""
  existing_node_id = (form.get("existing_node_id") or "").strip()
  if existing_node_id:
    db.delete_node(existing_node_id)
  node = db.register_node(form.get("name", "vps"))
  if not refresh_mqtt_auth(db, config):
    db.delete_node(node["node_id"])
    raise RuntimeError("MQTT 账号刷新失败，请检查 mosquitto_passwd、ACL 路径和权限。")
  ok, detail = verify_node_mqtt_auth(config, node)
  if not ok:
    db.delete_node(node["node_id"])
    refresh_mqtt_auth(db, config)
    suffix = f"最近错误：{detail}" if detail else "无详细错误。"
    raise RuntimeError(f"MQTT 节点账号验证失败，请检查 Mosquitto 是否已监听并加载最新 ACL。{suffix}")
  return node


def handle_node_action(db, config, node_id, action):
  """Handle a node operation from the web panel."""
  node = next((item for item in db.list_nodes() if item["node_id"] == node_id), None)
  if not node:
    return "节点不存在。"
  if action == "offline":
    db.update_node_status(node_id, "offline", node.get("public_ip") or "")
    db.audit("web", "node_offline", node["name"])
    return f"[{node['name']}] 已标记离线。"
  if action == "delete":
    try:
      dispatch_command(db, config, node_id, "/uninstall-agent")
    except ValueError:
      pass
    db.delete_node(node_id)
    refresh_mqtt_auth(db, config)
    db.audit("web", "node_delete", node["name"])
    return f"[{node['name']}] 已发送卸载指令并已删除记录。"
  if action == "refresh":
    dispatch_command(db, config, node_id, "/status")
    return f"[{node['name']}] 已发送更新请求。"
  if action == "online":
    dispatch_command(db, config, node_id, "/status")
    return f"[{node['name']}] 已发送上线检查。"
  return "不支持的操作。"


def request_realtime_metrics(db, config, online_only=False):
  """Dispatch a realtime metrics command to registered nodes."""
  nodes = db.list_nodes()
  if online_only:
    nodes = [node for node in nodes if node["status"] == "online"]
  for node in nodes:
    dispatch_command(db, config, node["node_id"], "/snapshot")
  scope = "在线 VPS" if online_only else "VPS"
  return f"已向 {len(nodes)} 台{scope}请求实时指标。"


def request_snapshot(db, config, online_only=True):
  """Compatibility wrapper for older callers."""
  return request_realtime_metrics(db, config, online_only=online_only)


def monitor_payload(db):
  """Return the current monitor state as JSON-serializable data."""
  now = int(time.time())
  monitor_until = int(db.get_setting("monitor_until", "0") or "0")
  nodes = []
  for item in db.latest_node_snapshots():
    nodes.append({
      "name": item.get("name") or "",
      "group_name": item.get("group_name") or "未分组",
      "status": item.get("status") or "offline",
      "monthly_used_gb": float(item.get("monthly_used_gb") or 0),
      "traffic_total_gb": float(item.get("traffic_total_gb") or 0),
      "daily_used_gb": float(item.get("daily_used_gb") or 0),
      "network_rx_mbps": float(item.get("network_rx_mbps") or 0),
      "network_tx_mbps": float(item.get("network_tx_mbps") or 0),
      "cpu_percent": float(item.get("cpu_percent") or 0),
      "memory_percent": float(item.get("memory_percent") or 0),
      "latency_ms": float(item.get("latency_ms") or 0),
      "snapshot_ts": int(item.get("snapshot_ts") or 0),
      "last_seen": int(item.get("last_seen") or 0),
      "public_ip": item.get("public_ip") or "",
    })
  return {
    "monitor_state": "运行中" if monitor_until > now else "未运行",
    "server_ts": now,
    "nodes": nodes,
  }


def dynamic_monitor_loop(db, config, until_ts, interval_seconds=REALTIME_MONITOR_INTERVAL_SECONDS):
  """Request realtime metrics periodically until the configured deadline."""
  while int(time.time()) < until_ts:
    try:
      request_realtime_metrics(db, config, online_only=False)
    except Exception:
      pass
    time.sleep(interval_seconds)


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
  server_version = "VpsMqttMaster/1.0"

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
    self.send_header("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; connect-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'")
    self.end_headers()
    self.wfile.write(payload)

  def send_json(self, data, status=200):
    """Send a JSON response with security headers."""
    payload = json.dumps(data, ensure_ascii=False).encode("utf-8")
    self.send_response(status)
    self.send_header("Content-Type", "application/json; charset=utf-8")
    self.send_header("Content-Length", str(len(payload)))
    self.send_header("X-Content-Type-Options", "nosniff")
    self.send_header("Cache-Control", "no-store")
    self.end_headers()
    self.wfile.write(payload)

  def send_monitor_events(self):
    """Stream monitor updates to the browser with Server-Sent Events."""
    self.send_response(200)
    self.send_header("Content-Type", "text/event-stream; charset=utf-8")
    self.send_header("Cache-Control", "no-cache")
    self.send_header("Connection", "keep-alive")
    self.send_header("X-Accel-Buffering", "no")
    self.end_headers()
    deadline = time.time() + 300
    while time.time() < deadline:
      payload = json.dumps(monitor_payload(self.db), ensure_ascii=False)
      try:
        self.wfile.write(f"data: {payload}\n\n".encode("utf-8"))
        self.wfile.flush()
      except (BrokenPipeError, ConnectionResetError):
        return
      time.sleep(3)

  def is_https_request(self):
    """Return whether the original request used HTTPS."""
    return is_https_headers(self.headers)

  def build_session_cookie(self, session):
    """Build a session cookie suitable for HTTP or HTTPS deployments."""
    return build_session_cookie_value(session, self.headers)

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
    """Wrap content in the web panel layout."""
    try:
      theme = self.db.get_setting("web_theme", "light")
    except Exception:
      theme = "light"
    if theme not in SUPPORTED_THEMES:
      theme = "light"
    return f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{html.escape(title)}</title>
  <style>
    :root {{
      --bg: #f5f7fb; --panel: #ffffff; --text: #141820; --muted: #626b7a;
      --line: #d9e0ea; --accent: #155eef; --accent-text: #ffffff; --soft: #eef3ff;
      --danger: #c9372c; --ok: #1f845a;
    }}
    body.theme-dark {{
      --bg: #111418; --panel: #1b2028; --text: #f4f7fb; --muted: #a8b3c4;
      --line: #303846; --accent: #6ea8ff; --accent-text: #07111f; --soft: #182337;
      --danger: #ff766f; --ok: #6bd6a2;
    }}
    body.theme-eye {{
      --bg: #edf5e8; --panel: #fbfff7; --text: #172015; --muted: #64735e;
      --line: #cadac1; --accent: #397a3b; --accent-text: #ffffff; --soft: #e3f1dc;
    }}
    body.theme-blue {{
      --bg: #edf7ff; --panel: #ffffff; --text: #102033; --muted: #607286;
      --line: #c9dff2; --accent: #2176c7; --accent-text: #ffffff; --soft: #dff0ff;
    }}
    * {{ box-sizing: border-box; }}
    body {{ margin: 0; font-family: system-ui, sans-serif; background: var(--bg); color: var(--text); }}
    main {{ max-width: 1180px; margin: 24px auto; padding: 0 18px 42px; }}
    h1 {{ margin: 0 0 6px; font-size: 28px; }}
    h2 {{ margin: 0; font-size: 18px; }}
    a {{ color: var(--accent); }}
    .topbar, .panel {{ background: var(--panel); border: 1px solid var(--line); border-radius: 8px; padding: 16px; margin: 14px 0; box-shadow: 0 8px 24px rgba(15,23,42,.06); }}
    .topbar {{ display: flex; align-items: center; justify-content: space-between; gap: 14px; flex-wrap: wrap; }}
    .toolbar {{ display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }}
    .grid {{ display: grid; gap: 14px; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); }}
    .stat {{ background: var(--soft); border-radius: 8px; padding: 12px; }}
    form.inline {{ display: inline-flex; align-items: center; gap: 8px; flex-wrap: wrap; margin: 0; }}
    input, select, button {{ font: inherit; padding: 9px 10px; margin: 4px 0; }}
    input, select {{ max-width: 100%; border: 1px solid var(--line); border-radius: 6px; background: var(--panel); color: var(--text); }}
    button {{ border: 0; border-radius: 6px; background: var(--accent); color: var(--accent-text); cursor: pointer; }}
    button.secondary {{ background: var(--soft); color: var(--text); border: 1px solid var(--line); }}
    button.danger {{ background: var(--danger); color: #fff; }}
    table {{ width: 100%; border-collapse: collapse; background: var(--panel); }}
    th, td {{ border-bottom: 1px solid var(--line); padding: 10px; text-align: left; vertical-align: top; }}
    th {{ color: var(--muted); font-weight: 600; }}
    details {{ margin-top: 8px; }}
    summary {{ cursor: pointer; color: var(--accent); }}
    .muted {{ color: var(--muted); }}
    .badge {{ display: inline-block; border-radius: 999px; padding: 2px 8px; background: var(--soft); color: var(--text); }}
    .badge.ok {{ color: var(--ok); }}
    .node-edit {{ display: grid; gap: 8px; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); margin-top: 8px; }}
    textarea {{ width: 100%; min-height: 120px; border: 1px solid var(--line); border-radius: 8px; background: var(--panel); color: var(--text); padding: 10px; }}
    @media (max-width: 720px) {{ table, thead, tbody, th, td, tr {{ display: block; }} th {{ display: none; }} td {{ padding: 8px 0; }} }}
  </style>
</head>
<body class="theme-{html.escape(theme)}"><main>{content}</main></body></html>"""

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
    if self.path == "/monitor":
      user = self.require_user()
      if not user:
        return
      self.send_html(self.render_monitor(user))
      return
    if self.path == "/api/monitor":
      user = self.require_user()
      if not user:
        return
      self.send_json(monitor_payload(self.db))
      return
    if self.path == "/events/monitor":
      user = self.require_user()
      if not user:
        return
      self.send_monitor_events()
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
    if self.path == "/telegram-delete":
      self.handle_telegram_delete(user)
      return
    if self.path == "/theme":
      self.handle_theme(user)
      return
    if self.path == "/command":
      self.handle_command(user)
      return
    if self.path == "/registration-command":
      self.handle_registration_command(user)
      return
    if self.path == "/node-action":
      self.handle_node_action(user)
      return
    if self.path == "/node-profile":
      self.handle_node_profile(user)
      return
    if self.path == "/dynamic-monitor":
      self.handle_dynamic_monitor(user)
      return
    self.send_error(404)

  def render_setup(self):
    """Render first-run setup."""
    return self.page("初始化管理员", """
<h1>初始化管理员</h1>
<form method="post" action="/setup">
  <label>用户名<br><input name="username" value="admin" required></label><br>
  <label>密码<br><input name="password" type="password" required minlength="2"></label><br>
  <button type="submit">创建管理员</button>
</form>""")

  def handle_setup(self):
    """Create first admin."""
    if self.db.has_admin():
      self.redirect("/login")
      return
    form = self.read_form()
    password = form.get("password", "")
    if len(password) < 2:
      self.send_html(self.page("初始化失败", "<p>密码至少 2 位。</p>"), status=400)
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
  <label>双重验证码（未绑定可留空）<br><input name="totp" inputmode="numeric" autocomplete="one-time-code"></label><br>
  <button type="submit">登录</button>
</form>""")

  def handle_login(self):
    """Authenticate user with optional TOTP."""
    form = self.read_form()
    username = form.get("username", "").strip()
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
    self.send_header("Set-Cookie", self.build_session_cookie(session))
    self.end_headers()

  def render_dashboard(self, user):
    """Render dashboard."""
    nodes = self.db.list_nodes()
    current_theme = self.db.get_setting("web_theme", "light")
    theme_options = "".join(
      f"<option value='{html.escape(key)}' {'selected' if key == current_theme else ''}>{html.escape(label)}</option>"
      for key, label in SUPPORTED_THEMES.items()
    )
    telegram_token = self.db.get_setting("telegram_token")
    telegram_chat_id = self.db.get_setting("telegram_chat_id")
    if telegram_token and telegram_chat_id:
      tg_last = f"{telegram_token[:5]}*** / {telegram_chat_id}"
      telegram_html = f"""
  <div class="stat">
    <span class="badge ok">已绑定</span>
    <strong>{html.escape(tg_last)}</strong>
    <details>
      <summary>编辑</summary>
      <form method="post" action="/telegram">
        <label>Bot Token<br><input name="token" value="{html.escape(telegram_token)}" required></label><br>
        <label>Chat ID<br><input name="chat_id" value="{html.escape(telegram_chat_id)}" required></label><br>
        <label>当前登录密码<br><input name="current_password" type="password" required></label><br>
        <button>验证并保存</button>
      </form>
      <form method="post" action="/telegram-delete" class="inline">
        <input name="current_password" type="password" placeholder="当前登录密码" required>
        <button class="danger">删除绑定</button>
      </form>
    </details>
  </div>"""
    else:
      telegram_html = """
  <form method="post" action="/telegram">
    <label>Bot Token<br><input name="token" required></label><br>
    <label>Chat ID<br><input name="chat_id" required></label><br>
    <label>当前登录密码<br><input name="current_password" type="password" required></label><br>
    <button>验证并绑定</button>
  </form>"""
    rows = "\n".join([
      "<tr>"
      f"<td draggable='true'><strong>{html.escape(item['name'])}</strong><br>"
      f"<span class='muted'>{html.escape(item.get('group_name') or '未分组')}</span></td>"
      f"<td><span class='badge {'ok' if item['status'] == 'online' else ''}'>{html.escape(item['status'])}</span></td>"
      f"<td>{html.escape(item.get('public_ip') or '')}</td>"
      f"<td>{html.escape(str(item.get('traffic_total_gb') or 0))} GB<br>"
      f"<span class='muted'>告警 {html.escape(str(item.get('traffic_alert_percent') or 80))}%</span></td>"
      f"<td>日报 {html.escape(item.get('daily_report_time') or '关闭')}<br>"
      f"<span class='muted'>月报 {html.escape(item.get('monthly_report_time') or '关闭')}</span></td>"
      f"<td><form method='post' action='/command'>"
      f"<input type='hidden' name='node_id' value='{html.escape(item['node_id'])}'>"
      "<select name='command'>"
      "<option>/status</option><option>/use</option><option>/speed</option>"
      "<option>/disk</option><option>/top</option><option>/uptime</option>"
      "<option>/services</option>"
      "</select> <button>执行</button></form>"
      f"<form method='post' action='/node-action'><input type='hidden' name='node_id' value='{html.escape(item['node_id'])}'>"
      "<button name='action' value='online'>上线检查</button> "
      "<button name='action' value='refresh'>更新</button> "
      "<button name='action' value='offline'>下线</button> "
      "<button class='danger' name='action' value='delete'>删除</button></form>"
      "<details><summary>编辑</summary>"
      f"<form method='post' action='/node-profile'><input type='hidden' name='node_id' value='{html.escape(item['node_id'])}'>"
      "<div class='node-edit'>"
      f"<label>名称<input name='name' value='{html.escape(item['name'])}' required></label>"
      f"<label>分组<input name='group_name' value='{html.escape(item.get('group_name') or '')}'></label>"
      f"<label>排序<input name='sort_order' value='{html.escape(str(item.get('sort_order') or 0))}' inputmode='numeric'></label>"
      f"<label>总流量 GB<input name='traffic_total_gb' value='{html.escape(str(item.get('traffic_total_gb') or ''))}' inputmode='decimal'></label>"
      f"<label>告警百分比<input name='traffic_alert_percent' value='{html.escape(str(item.get('traffic_alert_percent') or 80))}' inputmode='decimal'></label>"
      f"<label>日报时间<input name='daily_report_time' value='{html.escape(item.get('daily_report_time') or '')}' placeholder='22:00:00'></label>"
      f"<label>月报时间<input name='monthly_report_time' value='{html.escape(item.get('monthly_report_time') or '')}' placeholder='01 00:00:00'></label>"
      "</div><button>保存节点</button></form></details></td>"
      "</tr>"
      for item in nodes
    ])
    online = sum(1 for item in nodes if item["status"] == "online")
    return self.page("VPS MQTT 面板", f"""
<div class="topbar">
  <div>
    <h1>VPS MQTT 面板</h1>
    <p class="muted">当前用户: {html.escape(user)} · 在线 VPS {online} / {len(nodes)}</p>
  </div>
  <div class="toolbar">
    <form class="inline" method="post" action="/theme">
      <select name="theme">{theme_options}</select>
      <button class="secondary">切换主题</button>
    </form>
    <a href="/monitor">展示页面</a>
    <a href="/totp">Google Authenticator</a>
  </div>
</div>
<section class="panel">
  <h2>Telegram</h2>
  {telegram_html}
</section>
<section class="panel">
  <div class="topbar">
    <h2>已注册 VPS</h2>
    <form method="post" action="/registration-command" class="inline">
    <label>节点备注名<br><input name="name" placeholder="可留空"></label>
    <button>绑定 VPS</button>
    </form>
  </div>
  <table><thead><tr><th>节点</th><th>状态</th><th>公网 IP</th><th>流量</th><th>汇报</th><th>操作</th></tr></thead><tbody>{rows}</tbody></table>
</section>""")

  def render_totp(self, user):
    """Render TOTP binding page."""
    secret = generate_totp_secret()
    issuer = urllib.parse.quote(APP_NAME)
    account = urllib.parse.quote(user)
    uri = f"otpauth://totp/{issuer}:{account}?secret={secret}&issuer={issuer}"
    qr_uri = qr_svg_data_uri(uri)
    qr_html = f'<img alt="Google Authenticator QR" src="{qr_uri}" style="width:220px;height:220px">' if qr_uri else "<p>未安装 qrencode，暂无法生成二维码。</p>"
    return self.page("双重认证", f"""
<h1>绑定 Google Authenticator</h1>
<section>
  {qr_html}
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

  def render_monitor(self, user):
    """Render the realtime monitoring page."""
    def ts_text(value):
      timestamp = int(value or 0)
      if not timestamp:
        return "暂无"
      return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp))

    rows = "\n".join([
      "<tr>"
      f"<td><strong>{html.escape(item['name'])}</strong><br><span class='muted'>{html.escape(item.get('group_name') or '未分组')}</span>"
      f"<br><span class='muted'>IP {html.escape(item.get('public_ip') or '未知')}</span></td>"
      f"<td><span class='badge {'ok' if item['status'] == 'online' else ''}'>{html.escape(item['status'])}</span></td>"
      f"<td>{float(item.get('monthly_used_gb') or 0):.2f} / {float(item.get('traffic_total_gb') or 0):.2f} GB<br>"
      f"<span class='muted'>今日 {float(item.get('daily_used_gb') or 0):.2f} GB</span></td>"
      f"<td>↓ {float(item.get('network_rx_mbps') or 0):.2f} Mbps<br>↑ {float(item.get('network_tx_mbps') or 0):.2f} Mbps</td>"
      f"<td>{float(item.get('cpu_percent') or 0):.1f}%</td>"
      f"<td>{float(item.get('memory_percent') or 0):.1f}%</td>"
      f"<td>{float(item.get('latency_ms') or 0):.1f} ms</td>"
      f"<td>数据 {ts_text(item.get('snapshot_ts'))}<br><span class='muted'>心跳 {ts_text(item.get('last_seen'))}</span></td>"
      "</tr>"
      for item in self.db.latest_node_snapshots()
    ])
    monitor_until = int(self.db.get_setting("monitor_until", "0") or "0")
    state = "运行中" if monitor_until > int(time.time()) else "未运行"
    monitor_minutes = html.escape(self.db.get_setting("monitor_minutes", str(DEFAULT_MONITOR_MINUTES)) or str(DEFAULT_MONITOR_MINUTES))
    return self.page("VPS 监控展示", f"""
<div class="topbar">
  <div>
    <h1>VPS 监控展示</h1>
    <p class="muted">实时监控: <span id="monitor-state">{state}</span> · 连接: <span id="ws-state">未连接</span> · 最后刷新: <span id="last-refresh">暂无</span></p>
  </div>
  <div class="toolbar">
    <a href="/">返回面板</a>
    <form class="inline" id="realtime-form" method="post" action="/dynamic-monitor">
      <input name="minutes" inputmode="numeric" value="{monitor_minutes}" placeholder="分钟数" style="width: 100px">
      <button>实时监控</button>
    </form>
  </div>
</div>
<section class="panel">
  <table><thead><tr><th>节点</th><th>状态</th><th>流量</th><th>网速</th><th>CPU</th><th>内存</th><th>延迟</th><th>更新时间</th></tr></thead><tbody id="monitor-body">{rows}</tbody></table>
</section>
<script>
(() => {{
  const body = document.getElementById("monitor-body");
  const state = document.getElementById("monitor-state");
  const wsState = document.getElementById("ws-state");
  const lastRefresh = document.getElementById("last-refresh");
  const esc = (value) => String(value ?? "").replace(/[&<>"']/g, (char) => ({{
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    "\\"": "&quot;",
    "'": "&#39;",
  }}[char]));
  const fixed = (value, digits = 2) => Number(value || 0).toFixed(digits);
  const timeText = (seconds) => {{
    if (!seconds) return "暂无";
    return new Date(seconds * 1000).toLocaleString("zh-CN", {{ hour12: false }});
  }};
  const row = (item) => `
    <tr>
      <td><strong>${{esc(item.name)}}</strong><br><span class="muted">${{esc(item.group_name || "未分组")}}</span><br><span class="muted">IP ${{esc(item.public_ip || "未知")}}</span></td>
      <td><span class="badge ${{item.status === "online" ? "ok" : ""}}">${{esc(item.status || "offline")}}</span></td>
      <td>${{fixed(item.monthly_used_gb)}} / ${{fixed(item.traffic_total_gb)}} GB<br><span class="muted">今日 ${{fixed(item.daily_used_gb)}} GB</span></td>
      <td>↓ ${{fixed(item.network_rx_mbps)}} Mbps<br>↑ ${{fixed(item.network_tx_mbps)}} Mbps</td>
      <td>${{fixed(item.cpu_percent, 1)}}%</td>
      <td>${{fixed(item.memory_percent, 1)}}%</td>
      <td>${{fixed(item.latency_ms, 1)}} ms</td>
      <td>数据 ${{timeText(item.snapshot_ts)}}<br><span class="muted">心跳 ${{timeText(item.last_seen)}}</span></td>
    </tr>`;
  const render = (data) => {{
    state.textContent = data.monitor_state || "未运行";
    lastRefresh.textContent = timeText(data.server_ts);
    body.innerHTML = (data.nodes || []).map(row).join("");
  }};
  let socket = null;
  const setWsState = (value) => {{
    wsState.textContent = value;
  }};
  const startRealtime = (minutes) => {{
    if (!("WebSocket" in window)) {{
      setWsState("浏览器不支持 WebSocket");
      return;
    }}
    if (socket && socket.readyState !== WebSocket.CLOSED) {{
      socket.close();
    }}
    const scheme = window.location.protocol === "https:" ? "wss" : "ws";
    socket = new WebSocket(`${{scheme}}://${{window.location.host}}/ws/monitor`);
    setWsState("连接中");
    socket.onopen = () => {{
      setWsState("WebSocket 已连接");
      socket.send(JSON.stringify({{ action: "start_monitor", minutes }}));
    }};
    socket.onmessage = (event) => render(JSON.parse(event.data));
    socket.onclose = () => setWsState("实时监控已结束");
    socket.onerror = () => setWsState("WebSocket 错误");
  }};
  document.getElementById("realtime-form").addEventListener("submit", (event) => {{
    event.preventDefault();
    const minutes = event.currentTarget.querySelector('input[name="minutes"]').value;
    startRealtime(minutes);
  }});
}})();
</script>""")

  def handle_telegram(self, user):
    """Save Telegram settings."""
    form = self.read_form()
    ok, message = save_telegram_settings(self.db, user, form)
    if not ok:
      self.send_html(self.page("Telegram 绑定失败", f"<p>{html.escape(message)}</p>"), status=400)
      return
    self.send_html(self.page("Telegram 绑定成功", f"<p>{html.escape(message)}</p><p><a href='/'>返回面板</a></p>"))

  def handle_telegram_delete(self, user):
    """Delete Telegram settings."""
    form = self.read_form()
    ok, message = delete_telegram_settings(self.db, user, form.get("current_password", ""))
    if not ok:
      self.send_html(self.page("Telegram 删除失败", f"<p>{html.escape(message)}</p><p><a href='/'>返回面板</a></p>"), status=400)
      return
    self.send_html(self.page("Telegram 已删除", f"<p>{html.escape(message)}</p><p><a href='/'>返回面板</a></p>"))

  def handle_theme(self, user):
    """Save the selected theme."""
    form = self.read_form()
    if not save_theme(self.db, form.get("theme", "light")):
      self.send_html(self.page("主题切换失败", "<p>不支持的主题。</p>"), status=400)
      return
    self.db.audit(user, "save_theme", form.get("theme", ""))
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

  def handle_registration_command(self, user):
    """Render a copyable agent registration command."""
    form = self.read_form()
    command = create_registration_command_for_web(self.db, self.config, form.get("name", ""))
    self.db.audit(user, "create_registration_command", form.get("name", ""))
    self.send_html(self.page("绑定 VPS", f"""
<h1>绑定 VPS</h1>
<p>在要绑定的 VPS 上执行：</p>
<textarea style="width:100%; min-height:120px">{html.escape(command)}</textarea>
<p><a href="/">返回面板</a></p>"""))

  def handle_node_action(self, user):
    """Handle node action buttons."""
    form = self.read_form()
    message = handle_node_action(self.db, self.config, form.get("node_id", ""), form.get("action", ""))
    self.db.audit(user, "node_action", message)
    self.send_html(self.page("VPS 操作", f"<p>{html.escape(message)}</p><p><a href='/'>返回面板</a></p>"))

  def handle_node_profile(self, user):
    """Save editable node profile fields."""
    form = self.read_form()
    ok, message = update_node_profile(self.db, form.get("node_id", ""), form)
    if not ok:
      self.send_html(self.page("节点保存失败", f"<p>{html.escape(message)}</p><p><a href='/'>返回面板</a></p>"), status=400)
      return
    self.db.audit(user, "node_profile", message)
    self.redirect("/")

  def handle_snapshot(self, user):
    """Compatibility handler for older one-time metrics requests."""
    try:
      message = request_snapshot(self.db, self.config, online_only=False)
    except ValueError as error:
      message = str(error)
    self.db.audit(user, "request_metrics", message)
    self.send_html(self.page("实时指标", f"<p>{html.escape(message)}</p><p><a href='/monitor'>查看展示页面</a></p>"))

  def handle_dynamic_monitor(self, user):
    """Start a short-lived dynamic monitor loop."""
    form = self.read_form()
    try:
      minutes = max(1, min(int(form.get("minutes", "1") or "1"), 120))
    except ValueError:
      minutes = 1
    until = int(time.time()) + minutes * 60
    self.db.set_setting("monitor_until", str(until))
    thread = threading.Thread(
      target=dynamic_monitor_loop,
      args=(self.db, self.config, until),
      daemon=True,
    )
    thread.start()
    self.db.audit(user, "dynamic_monitor", f"{minutes} minutes")
    self.redirect("/monitor")

  def handle_register_api(self):
    """Register an agent using a one-time token."""
    form = self.read_form()
    token = form.get("token", "")
    if not self.db.consume_registration_token(token):
      self.send_response(403)
      self.end_headers()
      return
    try:
      node = register_node_from_agent(self.db, self.config, form)
    except RuntimeError as error:
      payload = json.dumps({"error": str(error)}, ensure_ascii=False).encode("utf-8")
      self.send_response(503)
      self.send_header("Content-Type", "application/json; charset=utf-8")
      self.send_header("Content-Length", str(len(payload)))
      self.end_headers()
      self.wfile.write(payload)
      return
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


class PanelRenderer:
  """Reuse existing page renderers outside BaseHTTPRequestHandler."""

  page = MasterRequestHandler.page
  render_setup = MasterRequestHandler.render_setup
  render_login = MasterRequestHandler.render_login
  render_dashboard = MasterRequestHandler.render_dashboard
  render_totp = MasterRequestHandler.render_totp
  render_monitor = MasterRequestHandler.render_monitor

  def __init__(self, db, config):
    self.server = type("Server", (), {"db": db, "config": config})()

  @property
  def db(self):
    return self.server.db

  @property
  def config(self):
    return self.server.config


def aiohttp_import():
  """Import aiohttp lazily so tests can run without the optional package."""
  from aiohttp import web
  return web


def aiohttp_html_response(web, body, status=200):
  """Build an aiohttp HTML response with security headers."""
  headers = {
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": "default-src 'self'; img-src 'self' data:; connect-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'",
  }
  return web.Response(text=body, status=status, content_type="text/html", charset="utf-8", headers=headers)


def aiohttp_redirect(web, path):
  """Build an aiohttp redirect response."""
  raise web.HTTPSeeOther(path)


async def aiohttp_require_user(request):
  """Return current session user or raise a login redirect."""
  user = request.app["db"].session_user(request.cookies.get("session", ""))
  if not user:
    aiohttp_redirect(request.app["web"], "/login")
  return user


async def aiohttp_form(request):
  """Read URL-encoded form data from aiohttp."""
  data = await request.post()
  return {key: str(value) for key, value in data.items()}


def start_dynamic_monitor(db, config, minutes):
  """Start dynamic monitor collection for a bounded number of minutes."""
  raw_value = str(minutes or "").strip()
  if not raw_value:
    raw_value = db.get_setting("monitor_minutes", str(DEFAULT_MONITOR_MINUTES))
  try:
    value = max(1, min(int(raw_value or str(DEFAULT_MONITOR_MINUTES)), 120))
  except ValueError:
    value = DEFAULT_MONITOR_MINUTES
  until = int(time.time()) + value * 60
  db.set_setting("monitor_minutes", str(value))
  db.set_setting("monitor_until", str(until))
  threading.Thread(
    target=dynamic_monitor_loop,
    args=(db, config, until, REALTIME_MONITOR_INTERVAL_SECONDS),
    daemon=True,
  ).start()
  return value


def build_aiohttp_app(db, config):
  """Build the aiohttp web application."""
  web = aiohttp_import()
  app = web.Application()
  app["db"] = db
  app["config"] = config
  app["web"] = web
  app["renderer"] = PanelRenderer(db, config)
  app["rate_limiter"] = LoginRateLimiter()

  async def health(request):
    return web.Response(text="ok")

  async def login_page(request):
    return aiohttp_html_response(web, app["renderer"].render_login())

  async def setup_page(request):
    if db.has_admin():
      aiohttp_redirect(web, "/login")
    return aiohttp_html_response(web, app["renderer"].render_setup())

  async def setup_post(request):
    if db.has_admin():
      aiohttp_redirect(web, "/login")
    form = await aiohttp_form(request)
    password = form.get("password", "")
    if len(password) < 2:
      return aiohttp_html_response(web, app["renderer"].page("初始化失败", "<p>密码至少 2 位。</p>"), status=400)
    username = form.get("username", "admin").strip() or "admin"
    db.create_admin(username, password)
    db.audit(username, "create_admin", "first setup")
    aiohttp_redirect(web, "/login")

  async def login_post(request):
    form = await aiohttp_form(request)
    username = form.get("username", "").strip()
    password = form.get("password", "")
    remote_ip = request.remote or ""
    limiter = app["rate_limiter"]
    if not limiter.allow(remote_ip, username):
      return aiohttp_html_response(web, app["renderer"].render_login("登录失败，请稍后再试。"), status=429)
    user = db.get_user(username)
    valid = bool(user and verify_password(password, user["password_hash"]))
    if valid and user["totp_enabled"]:
      valid = verify_totp(user["totp_secret"], form.get("totp", ""))
    if not valid:
      limiter.record_failure(remote_ip, username)
      return aiohttp_html_response(web, app["renderer"].render_login("登录失败。"), status=401)
    limiter.record_success(remote_ip, username)
    session = db.create_session(username)
    response = web.HTTPSeeOther("/")
    response.headers["Set-Cookie"] = build_session_cookie_value(session, request.headers)
    raise response

  async def dashboard(request):
    user = await aiohttp_require_user(request)
    return aiohttp_html_response(web, app["renderer"].render_dashboard(user))

  async def totp_page(request):
    user = await aiohttp_require_user(request)
    return aiohttp_html_response(web, app["renderer"].render_totp(user))

  async def totp_post(request):
    user = await aiohttp_require_user(request)
    form = await aiohttp_form(request)
    secret = form.get("secret", "")
    if not verify_totp(secret, form.get("code", "")):
      return aiohttp_html_response(web, app["renderer"].page("绑定失败", "<p>验证码错误。</p>"), status=400)
    db.enable_totp(user, secret)
    db.audit(user, "enable_totp", "enabled")
    aiohttp_redirect(web, "/")

  async def monitor_page(request):
    user = await aiohttp_require_user(request)
    return aiohttp_html_response(web, app["renderer"].render_monitor(user))

  async def monitor_api(request):
    await aiohttp_require_user(request)
    return web.json_response(monitor_payload(db))

  async def monitor_ws(request):
    await aiohttp_require_user(request)
    ws = web.WebSocketResponse(heartbeat=20)
    await ws.prepare(request)
    client_until = 0
    while not ws.closed:
      now = int(time.time())
      if client_until and now >= client_until:
        await ws.send_json(monitor_payload(db))
        await ws.close()
        break
      await ws.send_json(monitor_payload(db))
      try:
        message = await asyncio.wait_for(ws.receive(), timeout=REALTIME_WS_PUSH_SECONDS)
      except asyncio.TimeoutError:
        continue
      if message.type == web.WSMsgType.TEXT:
        try:
          payload = json.loads(message.data)
        except json.JSONDecodeError:
          continue
        action = payload.get("action")
        if action == "start_monitor":
          minutes = start_dynamic_monitor(db, config, payload.get("minutes", "1"))
          client_until = int(db.get_setting("monitor_until", "0") or "0")
          db.audit("websocket", "dynamic_monitor", f"{minutes} minutes")
        elif action == "stop_monitor":
          db.set_setting("monitor_until", "0")
          client_until = 0
        await ws.send_json(monitor_payload(db))
      elif message.type in (web.WSMsgType.CLOSE, web.WSMsgType.CLOSED, web.WSMsgType.ERROR):
        break
    return ws

  async def telegram_post(request):
    user = await aiohttp_require_user(request)
    form = await aiohttp_form(request)
    ok, message = save_telegram_settings(db, user, form)
    if not ok:
      return aiohttp_html_response(web, app["renderer"].page("Telegram 绑定失败", f"<p>{html.escape(message)}</p>"), status=400)
    return aiohttp_html_response(web, app["renderer"].page("Telegram 绑定成功", f"<p>{html.escape(message)}</p><p><a href='/'>返回面板</a></p>"))

  async def telegram_delete_post(request):
    user = await aiohttp_require_user(request)
    form = await aiohttp_form(request)
    ok, message = delete_telegram_settings(db, user, form.get("current_password", ""))
    if not ok:
      return aiohttp_html_response(web, app["renderer"].page("Telegram 删除失败", f"<p>{html.escape(message)}</p><p><a href='/'>返回面板</a></p>"), status=400)
    return aiohttp_html_response(web, app["renderer"].page("Telegram 已删除", f"<p>{html.escape(message)}</p><p><a href='/'>返回面板</a></p>"))

  async def theme_post(request):
    user = await aiohttp_require_user(request)
    form = await aiohttp_form(request)
    if not save_theme(db, form.get("theme", "light")):
      return aiohttp_html_response(web, app["renderer"].page("主题切换失败", "<p>不支持的主题。</p>"), status=400)
    db.audit(user, "save_theme", form.get("theme", ""))
    aiohttp_redirect(web, "/")

  async def command_post(request):
    user = await aiohttp_require_user(request)
    form = await aiohttp_form(request)
    try:
      dispatch_command(db, config, form.get("node_id", ""), form.get("command", ""))
    except ValueError as error:
      return aiohttp_html_response(web, app["renderer"].page("命令失败", f"<p>{html.escape(str(error))}</p>"), status=400)
    db.audit(user, "web_command", form.get("command", ""))
    aiohttp_redirect(web, "/")

  async def registration_command_post(request):
    user = await aiohttp_require_user(request)
    form = await aiohttp_form(request)
    command = create_registration_command_for_web(db, config, form.get("name", ""))
    db.audit(user, "create_registration_command", form.get("name", ""))
    return aiohttp_html_response(web, app["renderer"].page("绑定 VPS", f"""
<h1>绑定 VPS</h1>
<p>在要绑定的 VPS 上执行：</p>
<textarea style="width:100%; min-height:120px">{html.escape(command)}</textarea>
<p><a href="/">返回面板</a></p>"""))

  async def node_action_post(request):
    user = await aiohttp_require_user(request)
    form = await aiohttp_form(request)
    message = handle_node_action(db, config, form.get("node_id", ""), form.get("action", ""))
    db.audit(user, "node_action", message)
    return aiohttp_html_response(web, app["renderer"].page("VPS 操作", f"<p>{html.escape(message)}</p><p><a href='/'>返回面板</a></p>"))

  async def node_profile_post(request):
    user = await aiohttp_require_user(request)
    form = await aiohttp_form(request)
    ok, message = update_node_profile(db, form.get("node_id", ""), form)
    if not ok:
      return aiohttp_html_response(web, app["renderer"].page("节点保存失败", f"<p>{html.escape(message)}</p><p><a href='/'>返回面板</a></p>"), status=400)
    db.audit(user, "node_profile", message)
    aiohttp_redirect(web, "/")

  async def dynamic_monitor_post(request):
    user = await aiohttp_require_user(request)
    form = await aiohttp_form(request)
    minutes = start_dynamic_monitor(db, config, form.get("minutes", "1"))
    db.audit(user, "dynamic_monitor", f"{minutes} minutes")
    aiohttp_redirect(web, "/monitor")

  async def register_api(request):
    form = await aiohttp_form(request)
    if not db.consume_registration_token(form.get("token", "")):
      return web.Response(status=403)
    try:
      node = register_node_from_agent(db, config, form)
    except RuntimeError as error:
      return web.json_response({"error": str(error)}, status=503)
    return web.json_response({
      **node,
      "mqtt_host": config.get("MQTT_HOST", "127.0.0.1"),
      "mqtt_port": config.get("MQTT_PORT", "1883"),
      "topic_prefix": config.get("MQTT_TOPIC_PREFIX", DEFAULT_TOPIC_PREFIX),
    })

  app.add_routes([
    web.get("/health", health),
    web.get("/login", login_page),
    web.post("/login", login_post),
    web.get("/setup", setup_page),
    web.post("/setup", setup_post),
    web.get("/", dashboard),
    web.get("/totp", totp_page),
    web.post("/totp", totp_post),
    web.get("/monitor", monitor_page),
    web.get("/api/monitor", monitor_api),
    web.get("/ws/monitor", monitor_ws),
    web.post("/telegram", telegram_post),
    web.post("/telegram-delete", telegram_delete_post),
    web.post("/theme", theme_post),
    web.post("/command", command_post),
    web.post("/registration-command", registration_command_post),
    web.post("/node-action", node_action_post),
    web.post("/node-profile", node_profile_post),
    web.post("/dynamic-monitor", dynamic_monitor_post),
    web.post("/api/register", register_api),
  ])
  return app


def serve(config_path=DEFAULT_CONFIG, db_path=DEFAULT_DB):
  """Run the master web server."""
  config = load_env(config_path)
  db = MasterDatabase(db_path)
  config = runtime_config(db, config)
  host = config.get("WEB_HOST", "127.0.0.1")
  port = int(config.get("WEB_PORT", "8088"))
  threading.Thread(target=mqtt_event_loop, args=(db, config), daemon=True).start()
  threading.Thread(target=telegram_poll_loop, args=(db, config), daemon=True).start()
  web = aiohttp_import()
  web.run_app(build_aiohttp_app(db, config), host=host, port=port)


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


def create_admin_user(db_path, username, password):
  """Create or reset the web administrator account."""
  if len(password) < 2:
    raise ValueError("管理员密码至少 2 位")
  db = MasterDatabase(db_path)
  db.create_admin(username.strip() or "admin", password)
  db.audit(username.strip() or "admin", "create_admin", "installer")


def save_runtime_settings(db_path, settings):
  """Persist installer/runtime settings into SQLite."""
  db = MasterDatabase(db_path)
  for key, value in settings.items():
    db.set_setting(key, value)


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
  admin_parser = sub.add_parser("create-admin")
  admin_parser.add_argument("--username", default="admin")
  settings_parser = sub.add_parser("set-settings")
  settings_parser.add_argument("--set", dest="settings", action="append", default=[])
  args = parser.parse_args()

  if args.command == "serve":
    serve(args.config, args.db)
    return
  if args.command == "registration-command":
    print(create_registration_command(args.config, args.db, args.name))
    return
  if args.command == "create-admin":
    password = os.environ.get("VPS_MQTT_ADMIN_PASSWORD", "")
    create_admin_user(args.db, args.username, password)
    print(f"管理员已创建: {args.username}")
    return
  if args.command == "set-settings":
    settings = {}
    for item in args.settings:
      if "=" not in item:
        continue
      key, value = item.split("=", 1)
      settings[key] = value
    save_runtime_settings(args.db, settings)
    print("运行参数已写入 SQLite")
    return
  parser.print_help()


if __name__ == "__main__":
  main()

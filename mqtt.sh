#!/usr/bin/env bash
set -euo pipefail

PANEL_NAME="${PANEL_NAME:-vps-mqtt}"
SCRIPT_VERSION="${VPS_MQTT_SCRIPT_VERSION:-2026.07.07.23}"
VPS_MQTT_TESTING="${VPS_MQTT_TESTING:-0}"
RAW_BASE_URL="${VPS_MQTT_RAW_BASE_URL:-https://raw.githubusercontent.com/wuyou18075/vps-bot/refs/heads/main}"
CONFIG_DIR="${CONFIG_DIR:-/etc/${PANEL_NAME}}"
CONFIG_FILE="${CONFIG_FILE:-${CONFIG_DIR}/config.env}"
STATE_DIR="${STATE_DIR:-/var/lib/${PANEL_NAME}}"
INSTALL_DIR="${INSTALL_DIR:-/opt/${PANEL_NAME}}"
MASTER_FILE="${MASTER_FILE:-${INSTALL_DIR}/mqtt_master.py}"
AGENT_FILE="${AGENT_FILE:-${INSTALL_DIR}/mqtt_agent.py}"
SERVICE_FILE="${SERVICE_FILE:-/etc/systemd/system/${PANEL_NAME}-master.service}"
AGENT_SERVICE_FILE="${AGENT_SERVICE_FILE:-/etc/systemd/system/${PANEL_NAME}-agent.service}"
NGINX_FILE="${NGINX_FILE:-/etc/nginx/sites-available/${PANEL_NAME}.conf}"
NGINX_LINK="${NGINX_LINK:-/etc/nginx/sites-enabled/${PANEL_NAME}.conf}"
MOSQUITTO_CONF="${MOSQUITTO_CONF:-/etc/mosquitto/conf.d/${PANEL_NAME}.conf}"
MOSQUITTO_ACL="${MOSQUITTO_ACL:-/etc/mosquitto/${PANEL_NAME}.acl}"
MOSQUITTO_PASSWD="${MOSQUITTO_PASSWD:-/etc/mosquitto/${PANEL_NAME}.passwd}"
AGENT_CONFIG="${AGENT_CONFIG:-${CONFIG_DIR}/agent.env}"

red() {
  printf "\033[31m%s\033[0m\n" "$1"
}

green() {
  printf "\033[32m%s\033[0m\n" "$1"
}

yellow() {
  printf "\033[33m%s\033[0m\n" "$1"
}

require_root() {
  if is_testing; then
    return
  fi
  if [ "$(id -u)" -ne 0 ]; then
    red "请使用 root 运行：sudo bash mqtt.sh"
    exit 1
  fi
}

is_testing() {
  if [ "${VPS_MQTT_TESTING:-0}" = "1" ]; then
    return 0
  fi
  case "${CONFIG_DIR}:${INSTALL_DIR}:${STATE_DIR}" in
    *"/tmp/"*) return 0 ;;
  esac
  return 1
}

pause() {
  read -r -p "按 Enter 返回菜单..."
}

load_config() {
  unset PUBLIC_URL MQTT_HOST MQTT_LOCAL_HOST MQTT_PORT MQTT_TOPIC_PREFIX WEB_HOST WEB_PORT
  unset MQTT_MASTER_USER MQTT_MASTER_PASSWORD TELEGRAM_BOT_TOKEN TELEGRAM_CHAT_ID
  if [ -f "${CONFIG_FILE}" ]; then
    # shellcheck disable=SC1090
    source "${CONFIG_FILE}"
  fi
}

normalize_paths() {
  if [ "${MASTER_FILE}" = "/opt/${PANEL_NAME}/mqtt_master.py" ]; then
    MASTER_FILE="${INSTALL_DIR}/mqtt_master.py"
  fi
  if [ "${AGENT_FILE}" = "/opt/${PANEL_NAME}/mqtt_agent.py" ]; then
    AGENT_FILE="${INSTALL_DIR}/mqtt_agent.py"
  fi
  if [ "${AGENT_CONFIG}" = "/etc/${PANEL_NAME}/agent.env" ]; then
    AGENT_CONFIG="${CONFIG_DIR}/agent.env"
  fi
  case "${INSTALL_DIR}:${AGENT_CONFIG}" in
    /tmp/*:*|*:/tmp/*)
      if [ "${CONFIG_DIR}" = "/etc/${PANEL_NAME}" ]; then
        CONFIG_DIR="$(dirname "${AGENT_CONFIG}")"
        CONFIG_FILE="${CONFIG_DIR}/config.env"
      fi
      if [ "${STATE_DIR}" = "/var/lib/${PANEL_NAME}" ]; then
        STATE_DIR="/tmp/${PANEL_NAME}-state"
      fi
      ;;
  esac
}

write_config_value() {
  local key="$1"
  local value="$2"

  mkdir -p "${CONFIG_DIR}"
  touch "${CONFIG_FILE}"
  chmod 600 "${CONFIG_FILE}"
  if grep -q "^${key}=" "${CONFIG_FILE}"; then
    sed -i "s|^${key}=.*|${key}=\"${value}\"|" "${CONFIG_FILE}"
  else
    printf "%s=\"%s\"\n" "${key}" "${value}" >> "${CONFIG_FILE}"
  fi
}

random_secret() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -base64 32 | tr -d '=+/[:space:]' | cut -c1-32
  else
    date +%s%N | sha256sum | cut -c1-32
  fi
}

download_file() {
  local url="$1"
  local target="$2"
  local temp_file

  temp_file="$(mktemp)"
  if curl -fsSL \
      --connect-timeout 15 \
      --retry 1 \
      --retry-delay 2 \
      -H "Cache-Control: no-cache, no-store, must-revalidate" \
      -H "Pragma: no-cache" \
      -H "Expires: 0" \
      "${url}" \
      -o "${temp_file}"; then
    mv "${temp_file}" "${target}"
    return
  fi
  rm -f "${temp_file}"
  red "下载失败：${url}"
  exit 1
}

install_project_files() {
  normalize_paths
  mkdir -p "${INSTALL_DIR}" "${STATE_DIR}" "${CONFIG_DIR}"
  chmod 700 "${STATE_DIR}" "${CONFIG_DIR}" 2>/dev/null || true

  local script_dir=""
  if [ -n "${BASH_SOURCE[0]:-}" ] && [ -f "${BASH_SOURCE[0]}" ]; then
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  fi

  if [ -n "${script_dir}" ] && [ -f "${script_dir}/mqtt_master.py" ]; then
    cp "${script_dir}/mqtt_master.py" "${MASTER_FILE}"
  else
    download_file "${RAW_BASE_URL}/mqtt_master.py" "${MASTER_FILE}"
  fi

  if [ -n "${script_dir}" ] && [ -f "${script_dir}/mqtt_agent.py" ]; then
    cp "${script_dir}/mqtt_agent.py" "${AGENT_FILE}"
  else
    download_file "${RAW_BASE_URL}/mqtt_agent.py" "${AGENT_FILE}"
  fi

  chmod 755 "${MASTER_FILE}" "${AGENT_FILE}" 2>/dev/null || true
}

has_dependency_command() {
  local package="$1"
  local command_name="$2"

  if [ "${package}" = "mosquitto" ]; then
    systemctl list-unit-files mosquitto.service >/dev/null 2>&1 || command -v mosquitto >/dev/null 2>&1
    return
  fi
  if [ "${package}" = "python3-aiohttp" ]; then
    python3 -c "import aiohttp" >/dev/null 2>&1
    return
  fi
  command -v "${command_name}" >/dev/null 2>&1
}

get_missing_dependencies() {
  local specs=(
    "curl:curl"
    "python3:python3"
    "python3-aiohttp:aiohttp"
    "openssl:openssl"
    "qrencode:qrencode"
    "mosquitto:mosquitto"
    "mosquitto-clients:mosquitto_pub"
    "nginx:nginx"
  )
  local spec
  local package
  local command_name

  for spec in "${specs[@]}"; do
    package="${spec%%:*}"
    command_name="${spec#*:}"
    if ! has_dependency_command "${package}" "${command_name}"; then
      printf "%s\n" "${package}"
    fi
  done
}

install_dependencies() {
  require_root
  local missing
  missing="$(get_missing_dependencies)"
  if [ -z "${missing}" ]; then
    return
  fi
  if ! command -v apt-get >/dev/null 2>&1; then
    red "当前脚本仅支持 Debian/Ubuntu 系统（需要 apt-get）。"
    exit 1
  fi
  yellow "正在安装缺失依赖：$(printf "%s" "${missing}" | tr "\n" " ")"
  apt-get update
  # shellcheck disable=SC2086
  DEBIAN_FRONTEND=noninteractive apt-get install -y ${missing}
}

get_mqtt_status() {
  if [ ! -f "${MOSQUITTO_CONF}" ]; then
    printf "未配置\n"
    return
  fi
  if systemctl is-active --quiet mosquitto 2>/dev/null; then
    printf "运行\n"
  else
    printf "未运行\n"
  fi
}

get_web_status() {
  if systemctl is-active --quiet "${PANEL_NAME}-master.service" 2>/dev/null; then
    printf "运行\n"
  else
    printf "未运行\n"
  fi
}

get_primary_ip() {
  local ip=""
  if command -v curl >/dev/null 2>&1; then
    ip="$(curl -fsSL --connect-timeout 3 https://api.ipify.org 2>/dev/null || true)"
    if [ -z "${ip}" ]; then
      ip="$(curl -fsSL --connect-timeout 3 https://ifconfig.me/ip 2>/dev/null || true)"
    fi
  fi
  if [ -z "${ip}" ]; then
    ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
  fi
  if [ -z "${ip}" ] && command -v ip >/dev/null 2>&1; then
    ip="$(ip route get 1.1.1.1 2>/dev/null | awk '{for (i=1; i<=NF; i++) if ($i=="src") {print $(i+1); exit}}')"
  fi
  printf "%s\n" "${ip:-127.0.0.1}"
}

get_web_access_url() {
  if [ -n "${PUBLIC_URL:-}" ]; then
    printf "%s\n" "${PUBLIC_URL}"
  elif [ ! -f "${CONFIG_FILE}" ]; then
    printf "未配置\n"
  else
    printf "http://%s:%s\n" "$(get_primary_ip)" "${WEB_PORT:-8088}"
  fi
}

check_web_health() {
  local port="${WEB_PORT:-8088}"
  local attempt

  for attempt in 1 2 3 4 5; do
    if curl -fsS --connect-timeout 2 "http://127.0.0.1:${port}/health" >/dev/null 2>&1; then
      green "Web 本机健康检查通过：http://127.0.0.1:${port}/health"
      return 0
    fi
    sleep 1
  done

  yellow "Web 本机健康检查失败：http://127.0.0.1:${port}/health"
  yellow "请在 VPS 上查看：systemctl status ${PANEL_NAME}-master.service"
  yellow "请在 VPS 上查看：journalctl -u ${PANEL_NAME}-master.service -n 80 --no-pager"
  return 0
}

check_mqtt_health() {
  local host="${1:-127.0.0.1}"
  local port="${MQTT_PORT:-1883}"
  local topic="${MQTT_TOPIC_PREFIX:-vps-bot}/health/installer"
  local attempt
  local error_file
  error_file="$(mktemp)"

  for attempt in 1 2 3 4 5; do
    if mosquitto_pub \
      -h "${host}" \
      -p "${port}" \
      -u "${MQTT_MASTER_USER:-vps_master}" \
      -P "${MQTT_MASTER_PASSWORD:-}" \
      -t "${topic}" \
      -m "ok" \
      2>"${error_file}"; then
      green "MQTT 本机健康检查通过：${host}:${port}"
      rm -f "${error_file}"
      return 0
    fi
    sleep 1
  done

  yellow "MQTT 本机健康检查失败：${host}:${port}"
  if [ -s "${error_file}" ]; then
    yellow "最近错误：$(tail -n 1 "${error_file}")"
  fi
  yellow "请在主控 VPS 上查看：systemctl status mosquitto --no-pager"
  yellow "请在主控 VPS 上查看：ss -lntp | grep ':${port}'"
  rm -f "${error_file}"
  return 0
}

create_web_admin() {
  local username="$1"
  local password="$2"

  VPS_MQTT_ADMIN_PASSWORD="${password}" \
    python3 "${MASTER_FILE}" --config "${CONFIG_FILE}" --db "${STATE_DIR}/master.db" create-admin --username "${username}"
}

save_runtime_settings() {
  python3 "${MASTER_FILE}" --config "${CONFIG_FILE}" --db "${STATE_DIR}/master.db" set-settings \
    --set "PUBLIC_URL=${PUBLIC_URL:-}" \
    --set "RAW_BASE_URL=${RAW_BASE_URL}" \
    --set "MQTT_HOST=${MQTT_HOST:-}" \
    --set "MQTT_LOCAL_HOST=${MQTT_LOCAL_HOST:-}" \
    --set "MQTT_PORT=${MQTT_PORT:-}" \
    --set "MQTT_TOPIC_PREFIX=${MQTT_TOPIC_PREFIX:-vps-bot}" \
    --set "MQTT_MASTER_USER=${MQTT_MASTER_USER:-vps_master}" \
    --set "MQTT_MASTER_PASSWORD=${MQTT_MASTER_PASSWORD:-}" \
    --set "MOSQUITTO_ACL=${MOSQUITTO_ACL}" \
    --set "MOSQUITTO_PASSWD=${MOSQUITTO_PASSWD}" \
    --set "WEB_HOST=${WEB_HOST:-}" \
    --set "WEB_PORT=${WEB_PORT:-}"
}

get_registered_node_count() {
  if [ ! -f "${STATE_DIR}/master.db" ]; then
    printf "0\n"
    return
  fi
  python3 - <<PY
import sqlite3
db = sqlite3.connect("${STATE_DIR}/master.db")
print(db.execute("select count(*) from nodes").fetchone()[0])
PY
}

get_online_node_count() {
  if [ ! -f "${STATE_DIR}/master.db" ]; then
    printf "0\n"
    return
  fi
  python3 - <<PY
import sqlite3
db = sqlite3.connect("${STATE_DIR}/master.db")
print(db.execute("select count(*) from nodes where status='online'").fetchone()[0])
PY
}

get_totp_status() {
  if [ ! -f "${STATE_DIR}/master.db" ]; then
    printf "未开启\n"
    return
  fi
  local enabled
  enabled="$(python3 - <<PY
import sqlite3
db = sqlite3.connect("${STATE_DIR}/master.db")
try:
  print(db.execute("select count(*) from users where totp_enabled=1").fetchone()[0])
except sqlite3.OperationalError:
  print(0)
PY
)"
  if [ "${enabled}" -gt 0 ]; then
    printf "已开启\n"
  else
    printf "未开启\n"
  fi
}

render_main_panel() {
  load_config
  cat <<EOF
========================================
 VPS MQTT 监控面板 - 脚本 ${SCRIPT_VERSION}
========================================
MQTT服务: $(get_mqtt_status)
Web面板: $(get_web_status) ($(get_web_access_url))
公网访问: $(get_web_access_url)
在线VPS: $(get_online_node_count)
已注册VPS: $(get_registered_node_count)
双重认证: $(get_totp_status)
----------------------------------------
1 安装 MQTT 监控服务
2 部署 Web 页面
3 生成注册命令
4 查看已注册 VPS
5 配置 Telegram Bot
6 查看安全状态
7 重启服务
99 卸载
0 退出
EOF
}

write_mosquitto_files() {
  local master_password="${MQTT_MASTER_PASSWORD:-$(random_secret)}"
  local mqtt_port="${MQTT_PORT:-1883}"

  write_config_value "MQTT_MASTER_USER" "vps_master"
  write_config_value "MQTT_MASTER_PASSWORD" "${master_password}"

  mkdir -p "$(dirname "${MOSQUITTO_CONF}")" "$(dirname "${MOSQUITTO_ACL}")" "$(dirname "${MOSQUITTO_PASSWD}")"
  cat > "${MOSQUITTO_CONF}" <<EOF
listener ${mqtt_port} 0.0.0.0
allow_anonymous false
password_file ${MOSQUITTO_PASSWD}
acl_file ${MOSQUITTO_ACL}
persistence true
persistence_location ${STATE_DIR}/mosquitto/
EOF

  cat > "${MOSQUITTO_ACL}" <<EOF
user vps_master
topic readwrite ${MQTT_TOPIC_PREFIX:-vps-bot}/#
EOF

  touch "${MOSQUITTO_PASSWD}"
  chmod 600 "${MOSQUITTO_PASSWD}" "${MOSQUITTO_ACL}"
  mosquitto_passwd -b "${MOSQUITTO_PASSWD}" vps_master "${master_password}" >/dev/null
}

write_master_service() {
  cat > "${SERVICE_FILE}" <<EOF
[Unit]
Description=VPS MQTT Master
After=network-online.target mosquitto.service
Wants=network-online.target

[Service]
Type=simple
Environment=VPS_MQTT_CONFIG=${CONFIG_FILE}
ExecStart=/usr/bin/python3 ${MASTER_FILE} --config ${CONFIG_FILE} serve
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
EOF
}

write_nginx_config() {
  mkdir -p "$(dirname "${NGINX_FILE}")"
  cat > "${NGINX_FILE}" <<EOF
server {
  listen 80;
  server_name _;

  location / {
    proxy_pass http://127.0.0.1:${WEB_PORT:-8088};
    proxy_set_header Host \$host;
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto \$scheme;
    proxy_set_header Upgrade \$http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_read_timeout 3600s;
  }
}
EOF
  if ! is_testing; then
    ln -sf "${NGINX_FILE}" "${NGINX_LINK}"
  fi
}

setup_master() {
  normalize_paths
  require_root
  load_config

  local public_url
  local public_url_input
  local mqtt_port
  local web_port
  local admin_username
  local admin_password
  local admin_password_confirm
  read -r -p "请输入 Web 公网地址，例如 https://panel.example.com；无域名直接回车使用 IP:端口 [${PUBLIC_URL:-}]: " public_url_input
  read -r -p "请输入 MQTT 端口 [${MQTT_PORT:-1883}]: " mqtt_port
  mqtt_port="${mqtt_port:-${MQTT_PORT:-1883}}"
  read -r -p "请输入 Web 本地端口 [${WEB_PORT:-8088}]: " web_port
  web_port="${web_port:-${WEB_PORT:-8088}}"
  read -r -p "请输入 Web 管理员用户名 [admin]: " admin_username
  admin_username="${admin_username:-admin}"
  read -r -p "请输入 Web 管理员密码（至少 2 位）: " admin_password
  read -r -p "请再次输入 Web 管理员密码: " admin_password_confirm
  if [ "${admin_password}" != "${admin_password_confirm}" ]; then
    red "两次输入的密码不一致。"
    return
  fi
  if [ "${#admin_password}" -lt 2 ]; then
    red "Web 管理员密码至少 2 位。"
    return
  fi
  public_url="${public_url_input:-${PUBLIC_URL:-http://$(get_primary_ip):${web_port}}}"

  install_dependencies
  install_project_files

  write_config_value "PUBLIC_URL" "${public_url}"
  write_config_value "RAW_BASE_URL" "${RAW_BASE_URL}"
  write_config_value "MQTT_HOST" "$(get_primary_ip)"
  write_config_value "MQTT_PORT" "${mqtt_port}"
  write_config_value "MQTT_TOPIC_PREFIX" "${MQTT_TOPIC_PREFIX:-vps-bot}"
  write_config_value "MOSQUITTO_ACL" "${MOSQUITTO_ACL}"
  write_config_value "MOSQUITTO_PASSWD" "${MOSQUITTO_PASSWD}"
  if [ -z "${public_url_input}" ] && [[ "${public_url}" == http://*:* ]]; then
    write_config_value "WEB_HOST" "0.0.0.0"
  else
    write_config_value "WEB_HOST" "127.0.0.1"
  fi
  write_config_value "WEB_PORT" "${web_port}"

  load_config
  create_web_admin "${admin_username}" "${admin_password}"
  write_mosquitto_files
  load_config
  save_runtime_settings
  write_master_service
  write_nginx_config

  systemctl daemon-reload
  systemctl enable mosquitto >/dev/null 2>&1 || true
  systemctl restart mosquitto >/dev/null 2>&1 || true
  systemctl enable --now "${PANEL_NAME}-master.service" >/dev/null 2>&1 || true
  systemctl reload nginx >/dev/null 2>&1 || systemctl restart nginx >/dev/null 2>&1 || true
  check_mqtt_health "127.0.0.1"
  check_web_health

  green "MQTT 主控服务已安装。Web 首次访问 ${public_url}，使用账号 ${admin_username} 登录后绑定 Google Authenticator。"
}

deploy_web() {
  require_root
  install_dependencies
  install_project_files
  load_config
  write_nginx_config
  systemctl restart "${PANEL_NAME}-master.service" >/dev/null 2>&1 || true
  systemctl reload nginx >/dev/null 2>&1 || systemctl restart nginx >/dev/null 2>&1 || true
  green "Web 页面已部署。"
  pause
}

generate_registration_command() {
  require_root
  install_project_files
  load_config
  local name=""
  read -r -p "请输入预备注节点名（可留空）: " name
  python3 "${MASTER_FILE}" --config "${CONFIG_FILE}" --db "${STATE_DIR}/master.db" registration-command --name "${name}"
  pause
}

show_registered_nodes() {
  require_root
  if [ ! -f "${STATE_DIR}/master.db" ]; then
    yellow "暂无已注册 VPS。"
    pause
    return
  fi
  python3 - <<PY
import sqlite3
db = sqlite3.connect("${STATE_DIR}/master.db")
db.row_factory = sqlite3.Row
for row in db.execute("select name,node_id,status,public_ip,last_seen from nodes order by name"):
  print(f"{row['name']}\\t{row['node_id']}\\t{row['status']}\\t{row['public_ip'] or ''}\\t{row['last_seen'] or ''}")
PY
  pause
}

configure_telegram() {
  require_root
  load_config
  local token
  local chat_id
  read -r -p "请输入 Telegram Bot Token [${TELEGRAM_BOT_TOKEN:+已配置}]: " token
  token="${token:-${TELEGRAM_BOT_TOKEN:-}}"
  read -r -p "请输入 Telegram Chat ID [${TELEGRAM_CHAT_ID:-}]: " chat_id
  chat_id="${chat_id:-${TELEGRAM_CHAT_ID:-}}"
  write_config_value "TELEGRAM_BOT_TOKEN" "${token}"
  write_config_value "TELEGRAM_CHAT_ID" "${chat_id}"
  green "Telegram 配置已保存。"
  pause
}

show_security_status() {
  load_config
  cat <<EOF
安全状态:
- Web 登录限速: 已启用
- Google Authenticator: $(get_totp_status)
- MQTT 匿名访问: 禁止
- MQTT ACL: ${MOSQUITTO_ACL}
- 每节点独立凭据: 已启用
- 命令签名: 已启用
- 任意 shell: 禁止
EOF
  pause
}

restart_services() {
  require_root
  systemctl restart mosquitto >/dev/null 2>&1 || true
  systemctl restart "${PANEL_NAME}-master.service" >/dev/null 2>&1 || true
  systemctl restart nginx >/dev/null 2>&1 || true
  green "服务已重启。"
  pause
}

uninstall_all() {
  require_root
  systemctl disable --now "${PANEL_NAME}-master.service" >/dev/null 2>&1 || true
  systemctl disable --now "${PANEL_NAME}-agent.service" >/dev/null 2>&1 || true
  rm -f "${SERVICE_FILE}" "${AGENT_SERVICE_FILE}" "${NGINX_LINK}" "${NGINX_FILE}" "${MOSQUITTO_CONF}" "${MOSQUITTO_ACL}" "${MOSQUITTO_PASSWD}"
  rm -rf "${INSTALL_DIR}" "${CONFIG_DIR}" "${STATE_DIR}"
  systemctl daemon-reload >/dev/null 2>&1 || true
  systemctl restart mosquitto >/dev/null 2>&1 || true
  green "已卸载 VPS MQTT 监控服务。"
  pause
}

write_agent_service() {
  cat > "${AGENT_SERVICE_FILE}" <<EOF
[Unit]
Description=VPS MQTT Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 ${AGENT_FILE} --config ${AGENT_CONFIG} listen
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
EOF
}

register_agent() {
  normalize_paths
  require_root
  green "VPS MQTT 脚本版本: ${SCRIPT_VERSION}"
  systemctl stop "${PANEL_NAME}-agent.service" >/dev/null 2>&1 || true
  install_dependencies
  install_project_files

  local master_url=""
  local token=""
  local node_name=""
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --master-url) master_url="$2"; shift 2 ;;
      --token) token="$2"; shift 2 ;;
      --node-name) node_name="$2"; shift 2 ;;
      *) shift ;;
    esac
  done

  if [ -z "${master_url}" ] || [ -z "${token}" ]; then
    red "缺少参数：register-agent --master-url URL --token TOKEN [--node-name 名称]"
    exit 1
  fi

  python3 "${AGENT_FILE}" --config "${AGENT_CONFIG}" register --master-url "${master_url}" --token "${token}" --node-name "${node_name}"
  write_agent_service
  systemctl daemon-reload
  systemctl enable "${PANEL_NAME}-agent.service" >/dev/null 2>&1 || true
  systemctl restart "${PANEL_NAME}-agent.service" >/dev/null 2>&1 || true
  if python3 "${AGENT_FILE}" --config "${AGENT_CONFIG}" startup-check; then
    green "Agent 已注册并通过 MQTT 自检。"
  else
    yellow "Agent 已注册，但 MQTT 自检失败。请检查主控 MQTT 端口、防火墙、安全组和账号。"
    yellow "可查看日志：journalctl -u ${PANEL_NAME}-agent.service -n 80 --no-pager"
  fi
}

handle_choice() {
  case "$1" in
    1) setup_master; pause ;;
    2) deploy_web ;;
    3) generate_registration_command ;;
    4) show_registered_nodes ;;
    5) configure_telegram ;;
    6) show_security_status ;;
    7) restart_services ;;
    99) uninstall_all ;;
    0) exit 0 ;;
    *) red "无效选择"; pause ;;
  esac
}

main_menu() {
  while true; do
    clear
    render_main_panel
    read -r -p "请选择: " choice
    handle_choice "${choice}"
  done
}

if [ "${1:-}" = "register-agent" ]; then
  shift
  register_agent "$@"
elif [ "${VPS_MQTT_TESTING:-0}" != "1" ]; then
  main_menu
fi

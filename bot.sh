#!/usr/bin/env bash
set -euo pipefail

PANEL_NAME="${PANEL_NAME:-bot-panel}"
RAW_BASE_URL="${BOT_PANEL_RAW_BASE_URL:-https://raw.githubusercontent.com/xiangling18/vps-bot/refs/heads/main}"
AGENT_URL="${BOT_PANEL_AGENT_URL:-${RAW_BASE_URL}/bot_agent.py}"
CONFIG_DIR="${CONFIG_DIR:-/etc/${PANEL_NAME}}"
CONFIG_FILE="${CONFIG_FILE:-${CONFIG_DIR}/config.env}"
STATE_DIR="${STATE_DIR:-/var/lib/${PANEL_NAME}}"
INSTALL_DIR="${INSTALL_DIR:-/opt/${PANEL_NAME}}"
AGENT_FILE="${AGENT_FILE:-${INSTALL_DIR}/bot_agent.py}"
SERVICE_FILE="${SERVICE_FILE:-/etc/systemd/system/${PANEL_NAME}-listener.service}"
CRON_FILE="${CRON_FILE:-/etc/cron.d/${PANEL_NAME}-daily}"

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
  if [ "${BOT_PANEL_TESTING:-0}" = "1" ]; then
    return
  fi

  if [ "$(id -u)" -ne 0 ]; then
    red "请使用 root 运行：sudo bash bot.sh"
    red "一键安装：bash <(curl -fsSL -H \"Cache-Control: no-cache\" \"https://raw.githubusercontent.com/xiangling18/vps-bot/refs/heads/main/bot.sh?t=\$RANDOM\")"
    exit 1
  fi
}

pause() {
  read -r -p "按 Enter 返回菜单..."
}

download_file() {
  local url="$1"
  local target="$2"
  local temp_file
  temp_file="$(mktemp)"

  if ! curl -fsSL \
    --connect-timeout 15 \
    --retry 3 \
    --retry-delay 2 \
    -H "Cache-Control: no-cache" \
    "${url}" \
    -o "${temp_file}"; then
    rm -f "${temp_file}"
    red "下载失败：${url}"
    exit 1
  fi

  mv "${temp_file}" "${target}"
}

load_config() {
  if [ -f "${CONFIG_FILE}" ]; then
    # shellcheck disable=SC1090
    source "${CONFIG_FILE}"
  fi
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

detect_interface() {
  ip route get 1.1.1.1 2>/dev/null | awk '{for (i=1; i<=NF; i++) if ($i=="dev") {print $(i+1); exit}}'
}

install_dependencies() {
  require_root
  yellow "正在安装依赖：curl jq vnstat cron python3 iputils-ping speedtest-cli"

  if ! command -v apt-get >/dev/null 2>&1; then
    red "当前脚本仅支持 Debian/Ubuntu 系统（需要 apt-get）。"
    exit 1
  fi

  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y curl jq vnstat cron python3 iputils-ping speedtest-cli
  systemctl enable --now cron >/dev/null 2>&1 || true
}

install_agent_file() {
  require_root
  local script_dir=""
  local source_agent=""

  if [ -n "${BASH_SOURCE[0]:-}" ] && [ -f "${BASH_SOURCE[0]}" ]; then
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    source_agent="${script_dir}/bot_agent.py"
  fi

  mkdir -p "${INSTALL_DIR}" "${STATE_DIR}"
  chmod 700 "${STATE_DIR}"

  if [ -n "${source_agent}" ] && [ -f "${source_agent}" ]; then
    cp "${source_agent}" "${AGENT_FILE}"
  else
    yellow "未找到本地 bot_agent.py，正在从远端下载..."
    download_file "${AGENT_URL}?t=${RANDOM}" "${AGENT_FILE}"
  fi

  chmod 755 "${AGENT_FILE}"
}

ensure_base_config() {
  require_root
  mkdir -p "${CONFIG_DIR}" "${STATE_DIR}"
  chmod 700 "${STATE_DIR}"
  touch "${CONFIG_FILE}"
  chmod 600 "${CONFIG_FILE}"

  load_config
  if [ -z "${NODE_NAME:-}" ]; then
    write_config_value "NODE_NAME" "$(hostname)"
  fi
  if [ -z "${INTERFACE:-}" ]; then
    write_config_value "INTERFACE" "$(detect_interface)"
  fi
  if [ -z "${TRAFFIC_MONITOR:-}" ]; then
    write_config_value "TRAFFIC_MONITOR" "0"
  fi
}

start_traffic_monitor() {
  require_root
  install_dependencies
  ensure_base_config
  load_config

  local interface="${INTERFACE:-}"
  if [ -z "${interface}" ]; then
    interface="$(detect_interface)"
  fi

  read -r -p "请输入监控网卡 [${interface}]: " input_interface
  interface="${input_interface:-${interface}}"
  read -r -p "请输入本月总流量 GB，例如 500: " total_traffic

  if ! [[ "${total_traffic}" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
    red "总流量必须是数字。"
    pause
    return
  fi

  write_config_value "INTERFACE" "${interface}"
  write_config_value "TOTAL_TRAFFIC_GB" "${total_traffic}"
  write_config_value "TRAFFIC_MONITOR" "1"

  systemctl enable --now vnstat >/dev/null 2>&1 || true
  vnstat -u -i "${interface}" >/dev/null 2>&1 || true

  green "流量监控已开启：${interface}，月总流量 ${total_traffic} GB。"
  pause
}

show_traffic_usage() {
  require_root
  install_agent_file
  ensure_base_config
  python3 "${AGENT_FILE}" --traffic-report
  pause
}

stop_traffic_monitor() {
  require_root
  ensure_base_config
  write_config_value "TRAFFIC_MONITOR" "0"
  yellow "已关闭面板流量监控标记。vnStat 历史数据库保留，不会清空。"
  pause
}

bind_telegram_bot() {
  require_root
  install_dependencies
  install_agent_file
  ensure_base_config

  read -r -p "请输入 Telegram Bot Token: " bot_token
  read -r -p "请输入 Telegram Chat ID: " chat_id
  read -r -p "请输入当前 VPS 节点名 [$(hostname)]: " node_name
  node_name="${node_name:-$(hostname)}"

  write_config_value "BOT_TOKEN" "${bot_token}"
  write_config_value "CHAT_ID" "${chat_id}"
  write_config_value "NODE_NAME" "${node_name}"

  if python3 "${AGENT_FILE}" --send-test; then
    green "Telegram 绑定成功。"
  else
    red "测试消息发送失败，请检查 Bot Token 和 Chat ID。"
  fi
  pause
}

setup_daily_report() {
  require_root
  install_agent_file
  ensure_base_config

  read -r -p "请输入每天汇报小时 0-23 [9]: " hour
  hour="${hour:-9}"
  read -r -p "请输入分钟 0-59 [0]: " minute
  minute="${minute:-0}"

  if ! [[ "${hour}" =~ ^[0-9]+$ ]] || [ "${hour}" -gt 23 ]; then
    red "小时必须是 0-23。"
    pause
    return
  fi
  if ! [[ "${minute}" =~ ^[0-9]+$ ]] || [ "${minute}" -gt 59 ]; then
    red "分钟必须是 0-59。"
    pause
    return
  fi

  cat > "${CRON_FILE}" <<EOF
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
${minute} ${hour} * * * root /usr/bin/python3 ${AGENT_FILE} --daily-report >/dev/null 2>&1
EOF
  chmod 644 "${CRON_FILE}"
  systemctl enable --now cron >/dev/null 2>&1 || true
  green "每日流量汇报已设置为 ${hour}:$(printf "%02d" "${minute}")。"
  pause
}

start_listener() {
  require_root
  install_dependencies
  install_agent_file
  ensure_base_config

  cat > "${SERVICE_FILE}" <<EOF
[Unit]
Description=Bot Panel Telegram Listener
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
Environment=BOT_PANEL_CONFIG=${CONFIG_FILE}
Environment=BOT_PANEL_STATE_DIR=${STATE_DIR}
ExecStart=/usr/bin/python3 ${AGENT_FILE} --listen
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable --now "${PANEL_NAME}-listener.service"
  green "Telegram 指令监听已启动。"
  pause
}

stop_listener() {
  require_root
  systemctl disable --now "${PANEL_NAME}-listener.service" >/dev/null 2>&1 || true
  green "Telegram 指令监听已停止。"
  pause
}

show_node_info() {
  require_root
  ensure_base_config
  load_config
  cat <<EOF
节点名: ${NODE_NAME:-未设置}
网卡: ${INTERFACE:-未设置}
月总流量: ${TOTAL_TRAFFIC_GB:-未设置} GB
流量监控: ${TRAFFIC_MONITOR:-0}
Telegram Bot: $([ -n "${BOT_TOKEN:-}" ] && echo "已配置" || echo "未配置")
Chat ID: ${CHAT_ID:-未设置}
监听服务: $(systemctl is-active "${PANEL_NAME}-listener.service" 2>/dev/null || true)
EOF
  pause
}

traffic_menu() {
  while true; do
    clear
    cat <<EOF
月流量监控
1. 开启流量监控，设置总流量
2. 查看使用情况
3. 关闭流量监控
0. 返回主菜单
EOF
    read -r -p "请选择: " choice
    case "${choice}" in
      1) start_traffic_monitor ;;
      2) show_traffic_usage ;;
      3) stop_traffic_monitor ;;
      0) return ;;
      *) red "无效选择"; pause ;;
    esac
  done
}

show_commands_help() {
  cat <<EOF
Telegram 指令：
/ping
/ping all 1.1.1.1
/ping 节点名 1.1.1.1
/speed
/sudu
/speed 节点名
/status
/report
/nodes
/help

说明：
- 不带节点名代表所有正在监听的 VPS 都会尝试执行。
- 节点名来自菜单里的 Telegram 绑定配置。
- 只处理配置的 Chat ID 发来的消息。
EOF
  pause
}

main_menu() {
  require_root
  ensure_base_config

  while true; do
    clear
    cat <<EOF
Bot 一键面板 - Debian 13
1. 月流量监控
2. 关联 Telegram 机器人
3. 设置每天定时汇报流量
4. 启动 Telegram 指令监听
5. 停止 Telegram 指令监听
6. 查看节点信息
7. 查看 Telegram 指令说明
0. 退出
EOF
    read -r -p "请选择: " choice
    case "${choice}" in
      1) traffic_menu ;;
      2) bind_telegram_bot ;;
      3) setup_daily_report ;;
      4) start_listener ;;
      5) stop_listener ;;
      6) show_node_info ;;
      7) show_commands_help ;;
      0) exit 0 ;;
      *) red "无效选择"; pause ;;
    esac
  done
}

main() {
  case "${1:-}" in
    --daily-report)
      require_root
      install_agent_file
      python3 "${AGENT_FILE}" --daily-report
      ;;
    --listen)
      require_root
      install_agent_file
      python3 "${AGENT_FILE}" --listen
      ;;
    *)
      main_menu
      ;;
  esac
}

if [ "${BOT_PANEL_TESTING:-0}" != "1" ]; then
  main "$@"
fi

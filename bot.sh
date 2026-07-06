#!/usr/bin/env bash
set -euo pipefail

PANEL_NAME="${PANEL_NAME:-bot-panel}"
RAW_BASE_URL="${BOT_PANEL_RAW_BASE_URL:-https://raw.githubusercontent.com/wuyou18075/vps-bot/refs/heads/main}"
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
    red "一键安装：bash <(curl -fsSL -H \"Cache-Control: no-cache\" \"${RAW_BASE_URL}/bot.sh?t=\$RANDOM\")"
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

get_config_file_status() {
  if [ -f "${CONFIG_FILE}" ]; then
    printf "%s\n" "${CONFIG_FILE}"
  else
    printf "无\n"
  fi
}

detect_interface() {
  ip route get 1.1.1.1 2>/dev/null | awk '{for (i=1; i<=NF; i++) if ($i=="dev") {print $(i+1); exit}}'
}

list_network_interfaces() {
  ip -o link show 2>/dev/null \
    | awk -F': ' '{print $2}' \
    | cut -d@ -f1 \
    | awk '$0 != "lo" && !seen[$0]++'
}

select_monitor_interface() {
  local default_interface="$1"
  local interfaces=()
  local candidate
  local found_default="0"

  while IFS= read -r candidate; do
    if [ -z "${candidate}" ]; then
      continue
    fi
    interfaces+=("${candidate}")
    if [ "${candidate}" = "${default_interface}" ]; then
      found_default="1"
    fi
  done < <(list_network_interfaces)

  if [ -n "${default_interface}" ] && [ "${found_default}" = "0" ]; then
    interfaces=("${default_interface}" "${interfaces[@]}")
  fi

  if [ "${#interfaces[@]}" -eq 0 ]; then
    return 1
  fi

  if [ "${#interfaces[@]}" -eq 1 ]; then
    yellow "自动选择监控网卡：${interfaces[0]}" >&2
    printf "%s\n" "${interfaces[0]}"
    return
  fi

  local default_choice="1"
  local index
  yellow "检测到多个网卡，请选择要监控的网卡：" >&2
  for index in "${!interfaces[@]}"; do
    local number=$((index + 1))
    local marker=""
    if [ "${interfaces[index]}" = "${default_interface}" ]; then
      marker="（默认出口）"
      default_choice="${number}"
    fi
    printf "%s. %s%s\n" "${number}" "${interfaces[index]}" "${marker}" >&2
  done

  local choice
  while true; do
    read -r -p "请输入序号 [${default_choice}]: " choice || choice=""
    choice="${choice:-${default_choice}}"
    if [[ "${choice}" =~ ^[0-9]+$ ]] && [ "${choice}" -ge 1 ] && [ "${choice}" -le "${#interfaces[@]}" ]; then
      printf "%s\n" "${interfaces[choice - 1]}"
      return
    fi
    red "无效序号，请输入 1-${#interfaces[@]}。" >&2
  done
}

parse_vnstat_used_gb() {
  python3 -c '
import json
import sys

data = json.load(sys.stdin)
if isinstance(data.get("interfaces"), list) and data["interfaces"]:
  months = data["interfaces"][0].get("traffic", {}).get("month", [])
else:
  months = data.get("traffic", {}).get("month", [])

current = months[-1] if months else {}
used = int(current.get("rx", 0)) + int(current.get("tx", 0))
print(f"{used / 1024 / 1024 / 1024:.2f}G")
'
}

get_traffic_summary() {
  local total="${TOTAL_TRAFFIC_GB:-}"
  local interface="${INTERFACE:-}"
  local used="未知"
  local output

  if [ "${TRAFFIC_MONITOR:-0}" != "1" ]; then
    printf "未开启\n"
    return
  fi

  if [ -z "${total}" ]; then
    total="未设置"
  else
    total="${total}G"
  fi

  if [ -z "${interface}" ]; then
    interface="$(detect_interface)"
  fi

  if [ -n "${interface}" ] && command -v vnstat >/dev/null 2>&1 && command -v python3 >/dev/null 2>&1; then
    if output="$(vnstat --json m -i "${interface}" 2>/dev/null)"; then
      used="$(printf "%s" "${output}" | parse_vnstat_used_gb 2>/dev/null || printf "未知")"
    fi
  fi

  printf "%s / %s\n" "${used}" "${total}"
}

get_telegram_status() {
  if ! command -v systemctl >/dev/null 2>&1; then
    printf "离线\n"
    return
  fi

  if systemctl is-active --quiet "${PANEL_NAME}-listener.service" 2>/dev/null; then
    printf "在线\n"
  else
    printf "离线\n"
  fi
}

render_main_panel() {
  load_config

  cat <<EOF
========================================
 Bot 一键面板 - Debian 13
========================================
配置文件:$(get_config_file_status)
流量:    $(get_traffic_summary)
TG状态:  $(get_telegram_status)

TG指令说明:
  /ping 延迟    /use 流量    /1 状态    /2 汇报
----------------------------------------
1. 月流量监控
2. 查看节点信息
3. 关联tg机器人
5. tg离线休眠
6. tg重启上线
7. tg快捷指令说明
10. 设置每天定时汇报流量

90. 查出定时任务
97. 查看配置文件
98. 删除配置文件
99. 删除所有
0. 退出
EOF
}

has_dependency_command() {
  local package="$1"
  local command_name="$2"

  if [ "${package}" = "speedtest-cli" ]; then
    command -v speedtest-cli >/dev/null 2>&1 || command -v speedtest >/dev/null 2>&1
    return
  fi

  command -v "${command_name}" >/dev/null 2>&1
}

get_missing_dependencies() {
  local specs=(
    "curl:curl"
    "jq:jq"
    "vnstat:vnstat"
    "cron:cron"
    "python3:python3"
    "iputils-ping:ping"
    "speedtest-cli:speedtest-cli"
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
    yellow "依赖已安装，跳过安装。"
    systemctl enable --now cron >/dev/null 2>&1 || true
    return
  fi

  yellow "正在安装缺失依赖：$(printf "%s" "${missing}" | tr "\n" " ")"

  if ! command -v apt-get >/dev/null 2>&1; then
    red "当前脚本仅支持 Debian/Ubuntu 系统（需要 apt-get）。"
    exit 1
  fi

  apt-get update
  # shellcheck disable=SC2086
  DEBIAN_FRONTEND=noninteractive apt-get install -y ${missing}
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

  if ! interface="$(select_monitor_interface "${interface}")"; then
    red "未找到可用网卡，请检查网络配置。"
    pause
    return
  fi

  read -r -p "请输入本月总流量 GB [${TOTAL_TRAFFIC_GB:-500}]: " total_traffic
  total_traffic="${total_traffic:-${TOTAL_TRAFFIC_GB:-500}}"

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

  load_config

  if [ -n "${BOT_TOKEN:-}" ]; then
    read -r -p "请输入 Telegram Bot Token [已配置，回车保留]: " bot_token
    bot_token="${bot_token:-${BOT_TOKEN}}"
  else
    read -r -p "请输入 Telegram Bot Token: " bot_token
  fi

  read -r -p "请输入 Telegram Chat ID [${CHAT_ID:-未设置}]: " chat_id
  chat_id="${chat_id:-${CHAT_ID:-}}"
  read -r -p "请输入当前 VPS 节点名 [${NODE_NAME:-$(hostname)}]: " node_name
  node_name="${node_name:-${NODE_NAME:-$(hostname)}}"

  write_config_value "BOT_TOKEN" "${bot_token}"
  write_config_value "CHAT_ID" "${chat_id}"
  write_config_value "NODE_NAME" "${node_name}"

  if python3 "${AGENT_FILE}" --send-test; then
    green "Telegram 绑定成功。"
    setup_listener_service
    green "Telegram 指令监听已启动。"
  else
    red "测试消息发送失败，请检查 Bot Token 和 Chat ID。"
  fi
  pause
}

setup_daily_report() {
  require_root
  install_agent_file
  ensure_base_config
  load_config

  read -r -p "请输入每天汇报小时 0-23 [${REPORT_HOUR:-9}]: " hour
  hour="${hour:-${REPORT_HOUR:-9}}"
  read -r -p "请输入分钟 0-59 [${REPORT_MINUTE:-0}]: " minute
  minute="${minute:-${REPORT_MINUTE:-0}}"

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
  write_config_value "REPORT_HOUR" "${hour}"
  write_config_value "REPORT_MINUTE" "${minute}"
  systemctl enable --now cron >/dev/null 2>&1 || true
  green "每日流量汇报已设置为 ${hour}:$(printf "%02d" "${minute}")。"
  pause
}

setup_listener_service() {
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
  systemctl enable "${PANEL_NAME}-listener.service"
  systemctl restart "${PANEL_NAME}-listener.service"
}

start_listener() {
  require_root
  install_dependencies
  install_agent_file
  ensure_base_config

  setup_listener_service
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

show_cron_jobs() {
  require_root
  if [ -f "${CRON_FILE}" ]; then
    cat "${CRON_FILE}"
  else
    yellow "未设置每日定时汇报。"
  fi
  pause
}

show_config_file() {
  require_root
  if [ -f "${CONFIG_FILE}" ]; then
    cat "${CONFIG_FILE}"
  else
    yellow "配置文件不存在：${CONFIG_FILE}"
  fi
  pause
}

delete_config_file() {
  require_root
  if [ -f "${CONFIG_FILE}" ]; then
    rm -f "${CONFIG_FILE}"
    green "已删除配置文件：${CONFIG_FILE}"
  else
    yellow "配置文件不存在，无需删除。"
  fi
  pause
}

delete_all() {
  require_root
  systemctl disable --now "${PANEL_NAME}-listener.service" >/dev/null 2>&1 || true
  rm -f "${SERVICE_FILE}" "${CRON_FILE}"
  rm -rf "${CONFIG_DIR}" "${STATE_DIR}" "${INSTALL_DIR}"
  systemctl daemon-reload >/dev/null 2>&1 || true
  green "已删除服务、定时任务、配置文件和安装目录。"
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

handle_main_choice() {
  local choice="$1"

  case "${choice}" in
    1) traffic_menu ;;
    2) show_node_info ;;
    3) bind_telegram_bot ;;
    5) stop_listener ;;
    6) start_listener ;;
    7) show_commands_help ;;
    10) setup_daily_report ;;
    90) show_cron_jobs ;;
    97) show_config_file ;;
    98) delete_config_file ;;
    99) delete_all ;;
    0) exit 0 ;;
    *) red "无效选择"; pause ;;
  esac
}

show_commands_help() {
  cat <<EOF
Telegram 指令：
/ping
/ping all 1.1.1.1
/ping 节点名 1.1.1.1
/use
/use all
/use 节点名
/speed
/sudu
/speed 节点名
/status
/report
/1
/2
/nodes
/help

说明：
- /ping 测延迟。
- /use 查看本月流量使用情况。
- /1 等同 /status，/2 等同 /report。
- 不带节点名代表所有正在监听的 VPS 都会尝试执行。
- 节点名来自菜单里的 Telegram 绑定配置。
- 只处理配置的 Chat ID 发来的消息。
EOF
  pause
}

main_menu() {
  require_root

  while true; do
    clear
    render_main_panel
    read -r -p "请选择: " choice
    handle_main_choice "${choice}"
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

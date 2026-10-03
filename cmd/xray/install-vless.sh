#!/usr/bin/env bash
# Ubuntu 24.04: VLESS + REALITY + Vision
set -Eeuo pipefail
umask 077

PORT=443
SNI=
SNI_PROVIDED=0
# Candidate sources and limitations: README.md (reviewed 2026-10-03).
SNI_CANDIDATES=(
  # Technology / developer communities
  www.apple.com
  www.icloud.com
  addons.mozilla.org
  www.python.org
  www.nvidia.com
  www.samsung.com
  # Retail / consumer brands
  www.nike.com
  www.adidas.com
  www.ikea.com
  # Online travel
  www.booking.com
  www.expedia.com
  www.trip.com
  # Commercial software / developer tools
  www.jetbrains.com
  www.atlassian.com
  www.adobe.com
)
ADDRESS=
NODE_NAME=Xray-REALITY
UPGRADE=1
FORCE=0
XRAY=/usr/local/bin/xray
CONFIG=/usr/local/etc/xray/config.json
WORK=
BACKUP=
REPLACED=0
WAS_ACTIVE=0

usage() {
  cat <<'EOF'
用法：sudo bash cmd/xray/install-vless.sh --address <服务器公网 IPv4/域名> [选项]
  --port <端口>       监听 TCP 端口，默认 443
  --sni <域名>        指定 REALITY 目标域名，省略时随机选择并检测（目标端口 443）
  --name <名称>       分享链接的节点名称，默认 Xray-REALITY（支持中文）
  --skip-upgrade      跳过系统软件升级，仍更新索引并安装依赖
  --force            备份并替换已有配置（会生成新的客户端凭据）
  -h, --help         显示帮助
默认更新系统、开启 BBR、安装官方最新稳定版 Xray（已有安装则复用）。
EOF
}
die() { printf '错误：%s\n' "$*" >&2; exit 1; }
log() { printf '\n==> %s\n' "$*"; }

parse_args() {
  while (($#)); do
    case "$1" in
      --address|--port|--sni|--name)
        [[ $# -ge 2 && -n $2 && $2 != --* ]] || die "$1 缺少参数"
        case "$1" in
          --address) ADDRESS=$2 ;;
          --port) PORT=$2 ;;
          --sni) SNI=$2; SNI_PROVIDED=1 ;;
          --name) NODE_NAME=$2 ;;
        esac
        shift 2 ;;
      --skip-upgrade) UPGRADE=0; shift ;;
      --force) FORCE=1; shift ;;
      -h|--help) usage; exit 0 ;;
      *) die "未知参数：$1" ;;
    esac
  done
  [[ $PORT =~ ^[0-9]{1,5}$ ]] || die '端口必须是 1–65535 的整数'
  PORT=$((10#$PORT))
  ((PORT >= 1 && PORT <= 65535)) || die '端口必须是 1–65535 的整数'
  valid_host "$ADDRESS" || die '--address 必须是公网 IPv4 或域名（不带协议和端口）'
  if ((SNI_PROVIDED)); then
    valid_host "$SNI" || die '--sni 必须是有效域名'
    [[ $SNI == *[!0-9.]* ]] || die '--sni 不能使用 IP 地址'
  fi
  return 0
}

valid_host() {
  local host=$1 label octet
  [[ ${#host} -le 253 && $host == *.* && $host != *..* ]] || return 1
  [[ $host =~ ^[a-zA-Z0-9.-]+$ ]] || return 1
  local -a labels
  IFS=. read -r -a labels <<< "$host"
  [[ $host != *. ]] || return 1
  for label in "${labels[@]}"; do
    [[ ${#label} -le 63 && $label =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$ ]] || return 1
  done
  if [[ $host != *[!0-9.]* ]]; then
    [[ ${#labels[@]} == 4 ]] || return 1
    for octet in "${labels[@]}"; do
      [[ ${#octet} -le 3 ]] && ((10#$octet <= 255)) || return 1
    done
  fi
}

shuffle_sni_candidates() {
  python3 - "${SNI_CANDIDATES[@]}" <<'PYSHUFFLE'
import random
import sys
hosts = sys.argv[1:]
random.SystemRandom().shuffle(hosts)
print("\n".join(hosts))
PYSHUFFLE
}

probe_sni() {
  local host=$1
  timeout 15 openssl s_client -connect "$host:443" -servername "$host" \
    -tls1_3 -groups X25519 -alpn h2 -verify_hostname "$host" -verify_return_error \
    </dev/null >"$WORK/tls.txt" 2>&1 || return 1
  grep -q 'ALPN protocol: h2' "$WORK/tls.txt"
}

select_sni() {
  if ((SNI_PROVIDED)); then
    probe_sni "$SNI" || die "指定 SNI $SNI 检测失败（证书、TLS 1.3、X25519 或 HTTP/2），请更换 --sni"
    log "使用指定 SNI：$SNI"
    return 0
  fi
  local candidates candidate
  candidates=$(shuffle_sni_candidates) || die '无法随机排列 SNI 候选列表'
  while IFS= read -r candidate; do
    [[ -n $candidate ]] || continue
    log "检测随机候选 SNI：$candidate"
    if probe_sni "$candidate"; then
      SNI=$candidate
      log "已选择 SNI：$SNI"
      return 0
    fi
    printf '检测未通过，尝试下一个候选。\n' >&2
  done <<< "$candidates"
  die '所有 SNI 候选均不可用，请检查服务器网络或使用 --sni 指定域名'
}

cleanup() {
  local status=$?
  trap - EXIT
  if ((status != 0)); then
    printf '\n安装未完成（退出码 %s）。\n' "$status" >&2
    if ((REPLACED)); then
      if [[ -n $BACKUP ]]; then
        cp -p "$BACKUP" "$CONFIG" || true
        printf '已尝试恢复配置：%s\n' "$BACKUP" >&2
        if ((WAS_ACTIVE)); then systemctl restart xray || true; else systemctl stop xray || true; fi
      else
        systemctl stop xray || true
        rm -f -- "$CONFIG"
      fi
    fi
    printf '系统升级、BBR、软件安装和防火墙规则不会自动撤销。\n' >&2
  fi
  [[ -z $WORK ]] || rm -rf -- "$WORK"
  exit "$status"
}

# Accept PrivateKey/Private key and Password/PublicKey/Public key output.
key_field() {
  local wanted=$1
  awk -F: -v wanted="$wanted" '
    { key=tolower($1); gsub(/[[:space:]]/, "", key) }
    (wanted == "private" && key == "privatekey") ||
    (wanted == "public" && (key == "password" || key == "publickey")) {
      value=$2; gsub(/[[:space:]]/, "", value); print value; exit
    }'
}

write_config() {
  XRAY_UUID=$UUID XRAY_PRIVATE_KEY=$PRIVATE_KEY XRAY_SHORT_ID=$SHORT_ID \
    python3 - "$SNI" "$PORT" <<'PYCONFIG'
import json
import os
import sys
uid = os.environ["XRAY_UUID"]
key = os.environ["XRAY_PRIVATE_KEY"]
sid = os.environ["XRAY_SHORT_ID"]
sni, port = sys.argv[1:]
json.dump({
    "log": {"loglevel": "warning"},
    "inbounds": [{
        "listen": "0.0.0.0", "port": int(port), "protocol": "vless",
        "settings": {"clients": [{"id": uid, "flow": "xtls-rprx-vision"}],
                     "decryption": "none"},
        "streamSettings": {
            "network": "raw", "security": "reality",
            "realitySettings": {
                "show": False, "target": sni + ":443", "xver": 0,
                "serverNames": [sni], "privateKey": key, "shortIds": [sid]
            }
        }
    }],
    "outbounds": [{"protocol": "freedom"}]
}, sys.stdout, indent=2)
PYCONFIG
}

generate_vless_uri() {
  XRAY_UUID=$UUID XRAY_PUBLIC_KEY=$PUBLIC_KEY XRAY_SHORT_ID=$SHORT_ID \
    python3 - "$ADDRESS" "$PORT" "$SNI" "$NODE_NAME" <<'PYURI'
import os
import sys
from urllib.parse import quote, urlencode

address, port, sni, name = sys.argv[1:]
params = {
    "encryption": "none",
    "type": "tcp",
    "headerType": "none",
    "security": "reality",
    "flow": "xtls-rprx-vision",
    "sni": sni,
    "fp": "chrome",
    "pbk": os.environ["XRAY_PUBLIC_KEY"],
    "sid": os.environ["XRAY_SHORT_ID"],
}
uid = quote(os.environ["XRAY_UUID"], safe="")
query = urlencode(params, quote_via=quote, safe="")
print(f"vless://{uid}@{address}:{port}?{query}#{quote(name, safe='')}")
PYURI
}

main() {
  parse_args "$@"
  [[ $EUID == 0 ]] || die '请使用 sudo bash 执行'
  [[ $(uname -s) == Linux && -f /etc/os-release ]] || die '仅支持 Ubuntu 24.04'
  # shellcheck source=/dev/null
  source /etc/os-release
  [[ $ID == ubuntu && $VERSION_ID == 24.04 ]] || die '仅支持 Ubuntu 24.04'
  [[ -d /run/systemd/system ]] || die '需要正在运行 systemd 的服务器'
  exec 9>/run/lock/xray-vless-install.lock
  flock -n 9 || die '已有安装任务正在运行'
  if [[ -e $CONFIG && $FORCE == 0 ]]; then
    die '已有配置；如需重新生成凭据并覆盖，请加 --force'
  fi
  if [[ -e $CONFIG ]]; then
    install -d -m 700 /root/xray-backups
    BACKUP="/root/xray-backups/config.json.$(date +%Y%m%d-%H%M%S).$$"
    cp -p "$CONFIG" "$BACKUP"
    log "配置备份：$BACKUP"
  fi
  systemctl is-active --quiet xray && WAS_ACTIVE=1
  WORK=$(mktemp -d)
  trap cleanup EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM

  log '更新系统和依赖'
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  if ((UPGRADE)); then
    apt-get -o Dpkg::Options::=--force-confold upgrade -y
  fi
  apt-get install -y --no-install-recommends curl ca-certificates unzip python3 openssl iproute2 kmod

  log '检查监听端口和 REALITY 目标'
  local listeners
  listeners=$(ss -H -ltnp "sport = :$PORT")
  if [[ -n $listeners ]]; then
    # Only allow replacing the active main Xray service on the requested port.
    local pid line
    pid=$(systemctl show xray -p MainPID --value)
    [[ $FORCE == 1 && $WAS_ACTIVE == 1 && $pid =~ ^[1-9][0-9]*$ ]] || die "TCP $PORT 已被占用"
    while IFS= read -r line; do
      [[ $line == *"pid=$pid,"* ]] || die "TCP $PORT 被其他进程占用"
    done <<< "$listeners"
  fi
  select_sni

  log '开启 BBR'
  modprobe tcp_bbr || true
  sysctl -n net.ipv4.tcp_available_congestion_control | grep -qw bbr || die '当前内核不支持 BBR'
  cat > /etc/sysctl.d/99-xray-bbr.conf <<'EOF'
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOF
  chmod 644 /etc/sysctl.d/99-xray-bbr.conf
  sysctl -p /etc/sysctl.d/99-xray-bbr.conf
  [[ $(sysctl -n net.ipv4.tcp_congestion_control) == bbr ]] || die 'BBR 未生效'

  if [[ ! -x $XRAY ]]; then
    log '下载并运行 XTLS 官方安装器（最新稳定版）'
    curl --proto '=https' --tlsv1.2 -fsSL --retry 3 \
      https://raw.githubusercontent.com/XTLS/Xray-install/main/install-release.sh \
      -o "$WORK/install-release.sh"
    # Keep the official installer's normal system file permissions.
    (umask 022; unset JSONS_PATH JSON_PATH XRAY_CUSTOMIZE; bash "$WORK/install-release.sh" install)
  fi
  [[ -x $XRAY ]] || die 'Xray 安装失败'
  local exec_start service_user service_group
  exec_start=$(systemctl show xray -p ExecStart --value)
  [[ $exec_start == *"$XRAY run -config $CONFIG ;"* ]] || die '现有 xray.service 使用非标准启动配置，请先手动检查'
  service_user=$(systemctl show xray -p User --value)
  service_user=${service_user:-root}
  service_group=$(systemctl show xray -p Group --value)
  service_group=${service_group:-$(id -gn "$service_user")}

  log '生成 UUID、REALITY 密钥和随机 shortId'
  local UUID PRIVATE_KEY PUBLIC_KEY SHORT_ID keys
  UUID=$("$XRAY" uuid)
  keys=$("$XRAY" x25519)
  PRIVATE_KEY=$(key_field private <<< "$keys")
  PUBLIC_KEY=$(key_field public <<< "$keys")
  [[ $PRIVATE_KEY =~ ^[A-Za-z0-9_-]{43}$ && $PUBLIC_KEY =~ ^[A-Za-z0-9_-]{43}$ ]] || die '无法识别 Xray 密钥输出'
  SHORT_ID=$(openssl rand -hex 8)
  write_config > "$WORK/config.json"
  "$XRAY" run -test -config "$WORK/config.json"

  log '写入配置并放行防火墙'
  if command -v ufw >/dev/null 2>&1; then
    ufw allow "$PORT/tcp"
    ufw status
  else
    printf '未安装 UFW；请确认其他主机防火墙放行 TCP %s。\n' "$PORT"
  fi
  install -d -m 755 /usr/local/etc/xray
  install -m 640 -o root -g "$service_group" "$WORK/config.json" "${CONFIG}.new"
  REPLACED=1
  mv -f "${CONFIG}.new" "$CONFIG"
  systemctl restart xray
  sleep 2
  systemctl is-active --quiet xray || die 'Xray 启动失败，请运行 journalctl -u xray -n 50'
  local main_pid
  main_pid=$(systemctl show xray -p MainPID --value)
  ss -H -ltnp "sport = :$PORT" | grep -Fq "pid=$main_pid," || die 'Xray 未监听指定端口'
  systemctl enable xray
  REPLACED=0

  local uri
  uri=$(generate_vless_uri)
  printf '%s\n' "$uri" > /root/xray-vless-link.txt
  chmod 600 /root/xray-vless-link.txt
  log '安装完成'
  "$XRAY" version
  printf '\n客户端连接参数：\nUUID: %s\nPublicKey (Password): %s\nshortId: %s\nSNI: %s\n\n' \
    "$UUID" "$PUBLIC_KEY" "$SHORT_ID" "$SNI"
  printf 'VLESS URI 分享链接（用于支持 VLESS/REALITY 的客户端及 subconverter）：\n%s\n\n' "$uri"
  printf '链接：/root/xray-vless-link.txt\n配置：%s\n' "$CONFIG"
  printf '请在云厂商安全组放行入站 TCP %s；UFW 未启用时本脚本不会自动启用。\n' "$PORT"
  [[ ! -e /var/run/reboot-required ]] || printf '系统升级要求重启，请择时手动重启服务器。\n'
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then main "$@"; fi

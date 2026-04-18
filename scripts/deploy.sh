#!/usr/bin/env bash
# ==============================================================================
# Proto — sing-box 三入口一键部署脚本
#
# 部署：
#   · VLESS-Reality     TCP/${VLESS_PORT}   (默认 443)
#   · Trojan-WS-TLS     TCP/${TROJAN_PORT}  (默认 8443)
#   · Hysteria2         UDP/${HY2_PORT}     (默认 443，与 VLESS 同端口不冲突)
#
# 必填环境变量：
#   DOMAIN              用于 Trojan / Hysteria2 的域名，须已解析到本机
#
# 可选环境变量：
#   EMAIL               ACME 注册邮箱（默认 admin@${DOMAIN}）
#   REALITY_SNI         Reality 借用的真实站（默认 www.microsoft.com）
#   VLESS_PORT          默认 443
#   TROJAN_PORT         默认 8443
#   HY2_PORT            默认 443
#
# 用法：
#   sudo DOMAIN=vpn.example.com bash deploy.sh
# ==============================================================================

set -euo pipefail

# ----- 配置区 -----
DOMAIN="${DOMAIN:-}"
EMAIL="${EMAIL:-admin@${DOMAIN:-example.com}}"
REALITY_SNI="${REALITY_SNI:-www.microsoft.com}"
REALITY_DEST_PORT="${REALITY_DEST_PORT:-443}"

VLESS_PORT="${VLESS_PORT:-443}"
TROJAN_PORT="${TROJAN_PORT:-8443}"
HY2_PORT="${HY2_PORT:-443}"

CONFIG_DIR="/etc/sing-box"
CERT_DIR="/etc/ssl/proto"
LOG_PREFIX="[proto-deploy]"

# ----- 工具函数 -----
log()  { echo "$LOG_PREFIX $*"; }
die()  { echo "$LOG_PREFIX ERROR: $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "缺少命令: $1"; }

check_root() {
  [[ $EUID -eq 0 ]] || die "请以 root 运行"
}

check_prereq() {
  [[ -n "$DOMAIN" ]] || die "必须设置环境变量 DOMAIN"
  need curl
  need openssl
  need systemctl
  # 端口冲突预检（TCP + UDP 分开查）
  if ss -tlnp 2>/dev/null | grep -qE ":(${VLESS_PORT}|${TROJAN_PORT})\b"; then
    log "警告：检测到 TCP 端口 ${VLESS_PORT}/${TROJAN_PORT} 已被占用，可能冲突"
  fi
  if ss -ulnp 2>/dev/null | grep -qE ":${HY2_PORT}\b"; then
    log "警告：检测到 UDP 端口 ${HY2_PORT} 已被占用，Hysteria2 可能无法监听"
  fi
}

install_sing_box() {
  if command -v sing-box >/dev/null 2>&1; then
    log "sing-box 已安装：$(sing-box version | head -1)"
    return
  fi
  log "安装 sing-box..."
  curl -fsSL https://sing-box.app/install.sh | sh
  command -v sing-box >/dev/null 2>&1 || die "sing-box 安装失败"
}

install_acme() {
  if [[ -x /root/.acme.sh/acme.sh ]]; then
    log "acme.sh 已安装"
    return
  fi
  log "安装 acme.sh..."
  curl -fsSL https://get.acme.sh | sh -s email="$EMAIL"
}

issue_cert() {
  log "签发证书 for $DOMAIN ..."
  mkdir -p "$CERT_DIR"
  /root/.acme.sh/acme.sh --set-default-ca --server letsencrypt
  # HTTP-01 需要 80 端口，请确保未被占用
  /root/.acme.sh/acme.sh --issue -d "$DOMAIN" --standalone --force \
    || die "ACME 签发失败，请检查 80 端口是否空闲且 DNS 已生效"
  /root/.acme.sh/acme.sh --install-cert -d "$DOMAIN" \
    --fullchain-file "$CERT_DIR/fullchain.pem" \
    --key-file       "$CERT_DIR/privkey.pem" \
    --reloadcmd      "systemctl reload sing-box || systemctl restart sing-box"
  chmod 600 "$CERT_DIR/privkey.pem"
}

gen_creds() {
  log "生成凭据..."
  UUID=$(sing-box generate uuid)
  TROJAN_PW=$(openssl rand -base64 18 | tr -d '=+/' | cut -c1-24)
  HY2_PW=$(openssl rand -base64 18 | tr -d '=+/' | cut -c1-24)
  local kp
  kp=$(sing-box generate reality-keypair)
  REALITY_PRIV=$(awk -F': *' '/PrivateKey/ {print $2}' <<<"$kp")
  REALITY_PUB=$(awk  -F': *' '/PublicKey/  {print $2}' <<<"$kp")
  SHORT_ID=$(openssl rand -hex 8)
}

write_config() {
  log "写入 sing-box 配置..."
  mkdir -p "$CONFIG_DIR"
  cat > "$CONFIG_DIR/config.json" <<JSON
{
  "log": { "level": "info", "timestamp": true },
  "inbounds": [
    {
      "type": "vless",
      "tag": "vless-reality",
      "listen": "::",
      "listen_port": ${VLESS_PORT},
      "users": [{ "uuid": "${UUID}", "flow": "xtls-rprx-vision" }],
      "tls": {
        "enabled": true,
        "server_name": "${REALITY_SNI}",
        "reality": {
          "enabled": true,
          "handshake": {
            "server": "${REALITY_SNI}",
            "server_port": ${REALITY_DEST_PORT}
          },
          "private_key": "${REALITY_PRIV}",
          "short_id": ["${SHORT_ID}"]
        }
      }
    },
    {
      "type": "trojan",
      "tag": "trojan-ws",
      "listen": "::",
      "listen_port": ${TROJAN_PORT},
      "users": [{ "password": "${TROJAN_PW}" }],
      "tls": {
        "enabled": true,
        "server_name": "${DOMAIN}",
        "certificate_path": "${CERT_DIR}/fullchain.pem",
        "key_path": "${CERT_DIR}/privkey.pem"
      },
      "transport": { "type": "ws", "path": "/ray" }
    },
    {
      "type": "hysteria2",
      "tag": "hy2",
      "listen": "::",
      "listen_port": ${HY2_PORT},
      "users": [{ "password": "${HY2_PW}" }],
      "tls": {
        "enabled": true,
        "server_name": "${DOMAIN}",
        "certificate_path": "${CERT_DIR}/fullchain.pem",
        "key_path": "${CERT_DIR}/privkey.pem"
      }
    }
  ],
  "outbounds": [
    { "type": "direct", "tag": "direct" },
    { "type": "block",  "tag": "block"  }
  ]
}
JSON
  chmod 600 "$CONFIG_DIR/config.json"
  sing-box check -c "$CONFIG_DIR/config.json" || die "配置校验失败"
}

tune_sysctl() {
  log "调优内核参数（BBR、UDP buffer）..."
  cat > /etc/sysctl.d/99-proto.conf <<'EOF'
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.core.rmem_default = 262144
net.core.wmem_default = 262144
net.ipv4.tcp_fastopen = 3
EOF
  sysctl --system >/dev/null
}

open_firewall() {
  if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
    log "配置 ufw..."
    ufw allow "${VLESS_PORT}"/tcp  >/dev/null || true
    ufw allow "${TROJAN_PORT}"/tcp >/dev/null || true
    ufw allow "${HY2_PORT}"/udp    >/dev/null || true
  elif command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld; then
    log "配置 firewalld..."
    firewall-cmd --permanent --add-port="${VLESS_PORT}"/tcp
    firewall-cmd --permanent --add-port="${TROJAN_PORT}"/tcp
    firewall-cmd --permanent --add-port="${HY2_PORT}"/udp
    firewall-cmd --reload
  else
    log "未检测到活动防火墙，跳过端口放行（请自行确认云厂商安全组）"
  fi
}

enable_service() {
  systemctl enable --now sing-box
  systemctl restart sing-box
  sleep 2
  systemctl is-active --quiet sing-box || {
    journalctl -u sing-box --no-pager -n 30
    die "sing-box 启动失败"
  }
}

write_summary() {
  local summary="$CONFIG_DIR/deploy-summary.txt"
  cat > "$summary" <<EOF
============ Proto 部署结果 ============
域名          : ${DOMAIN}
公网 IP       : $(curl -fsS4 https://ifconfig.me 2>/dev/null || echo "?")

VLESS-Reality : TCP/${VLESS_PORT}
  uuid        : ${UUID}
  sni         : ${REALITY_SNI}
  public_key  : ${REALITY_PUB}
  short_id    : ${SHORT_ID}
  flow        : xtls-rprx-vision

Trojan-WS-TLS : TCP/${TROJAN_PORT}
  host        : ${DOMAIN}
  path        : /ray
  password    : ${TROJAN_PW}

Hysteria2     : UDP/${HY2_PORT}
  host        : ${DOMAIN}
  password    : ${HY2_PW}
=======================================
EOF
  chmod 600 "$summary"
  cat "$summary"
  log "参数已保存至：$summary（权限 600，注意妥善保管）"
}

# ----- 主流程 -----
main() {
  check_root
  check_prereq
  install_sing_box
  install_acme
  issue_cert
  gen_creds
  write_config
  tune_sysctl
  open_firewall
  enable_service
  write_summary
  log "部署完成 ✔"
}

main "$@"

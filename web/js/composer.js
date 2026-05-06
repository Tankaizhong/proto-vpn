// ---------- 选项定义 ----------
const OPTIONS = {
  protocol: [
    { id: "vless",    label: "VLESS",            desc: "无加密载荷，靠传输层 TLS 保密" },
    { id: "trojan",   label: "Trojan",           desc: "密码 + TLS 伪装 HTTPS" },
    { id: "hy2",      label: "Hysteria2",        desc: "基于 QUIC，高丢包跨境" },
    { id: "ss2022",   label: "Shadowsocks-2022", desc: "AEAD + BLAKE3，无 TLS" },
    { id: "vmess",    label: "VMess",            desc: "传统协议，AEAD 模式" },
  ],
  transport: [
    { id: "tcp",  label: "TCP",       desc: "原始 TCP" },
    { id: "ws",   label: "WebSocket", desc: "走 HTTP/1.1 Upgrade，CDN 友好" },
    { id: "grpc", label: "gRPC",      desc: "HTTP/2，CDN 友好" },
    { id: "quic", label: "QUIC/UDP",  desc: "仅 Hysteria2 可用" },
    { id: "mkcp", label: "mKCP",      desc: "UDP 伪装 + FEC" },
  ],
  tls: [
    { id: "none",    label: "无 TLS",  desc: "协议自带密码学（如 SS-2022）" },
    { id: "tls",     label: "标准 TLS 1.3", desc: "真证书 (ACME)" },
    { id: "reality", label: "Reality", desc: "偷用真站握手，仅 VLESS+TCP" },
  ],
  addons: [
    { id: "utls",    label: "uTLS 指纹模拟",  desc: "伪装 Chrome/Firefox ClientHello" },
    { id: "cdn",     label: "CDN 域前置",     desc: "需要 ws 或 grpc" },
    { id: "padding", label: "流量 padding",   desc: "削弱长度指纹" },
    { id: "xtls",    label: "XTLS-Vision 流控", desc: "仅 VLESS + Reality/TLS" },
  ],
};

// ---------- 兼容性矩阵 ----------
// 返回 null 表示兼容；返回字符串表示不兼容原因。
function disableReason(group, id, picked) {
  const p = picked.protocol, t = picked.transport, tl = picked.tls;

  if (group === "transport") {
    if (p === "hy2"    && id !== "quic") return "Hysteria2 仅支持 QUIC/UDP";
    if (p !== "hy2"    && id === "quic") return "QUIC/UDP 仅 Hysteria2 用";
    if (p === "ss2022" && (id === "ws" || id === "grpc")) return "SS-2022 不内建 ws/grpc";
    if (p === "trojan" && id === "mkcp") return "Trojan 走 TLS，不用 mKCP";
    if (p === "vless"  && id === "mkcp") return "Reality/Vision 流控需 TCP";
    if (tl === "reality" && id !== "tcp") return "Reality 必须 TCP";
  }

  if (group === "tls") {
    if (id === "reality") {
      if (p && p !== "vless") return "Reality 仅支持 VLESS";
      if (t && t !== "tcp")   return "Reality 仅支持 TCP 传输";
    }
    if (id === "tls") {
      if (p === "ss2022") return "SS-2022 不用 TLS（有自带 AEAD）";
    }
    if (id === "none") {
      if (p === "trojan") return "Trojan 必须走 TLS";
      if (p === "hy2")    return "Hysteria2 必须走 TLS";
    }
  }

  if (group === "addons") {
    if (id === "cdn") {
      if (t && t !== "ws" && t !== "grpc") return "CDN 需要 ws/grpc 传输";
      if (p === "hy2") return "Hysteria2 不走 HTTP CDN";
    }
    if (id === "utls" && tl === "none") return "uTLS 只用于 TLS 握手";
    if (id === "xtls") {
      if (p && p !== "vless") return "XTLS-Vision 仅 VLESS 可用";
      if (tl && tl === "none") return "XTLS 必须配合 TLS/Reality";
    }
  }

  if (group === "protocol") {
    if (id === "hy2"    && t && t !== "quic") return "Hysteria2 需 QUIC";
    if (id !== "hy2"    && t === "quic")      return "QUIC 只给 Hysteria2";
    if (id !== "vless"  && tl === "reality")  return "Reality 只给 VLESS";
    if (id === "ss2022" && tl === "tls")      return "SS-2022 不用 TLS";
    if ((id === "trojan" || id === "hy2") && tl === "none") return "该协议必须走 TLS";
  }

  return null;
}

// ---------- 状态 ----------
const state = {
  protocol: null,
  transport: null,
  tls: null,
  addons: new Set(),
};

// ---------- 渲染 ----------
function render() {
  for (const group of Object.keys(OPTIONS)) {
    const container = document.querySelector(`.group[data-key="${group}"] .options`);
    container.innerHTML = "";
    for (const opt of OPTIONS[group]) {
      const reason = disableReason(group, opt.id, state);
      const selected = group === "addons"
        ? state.addons.has(opt.id)
        : state[group] === opt.id;
      const disabled = !!reason && !selected;

      const el = document.createElement("div");
      el.className = "opt" + (selected ? " selected" : "") + (disabled ? " disabled" : "");
      el.title = opt.desc + (reason ? " · 冲突：" + reason : "");
      el.innerHTML = `${opt.label}` +
        (disabled ? `<span class="why">${reason}</span>` : "") +
        (!disabled && !selected ? `<span class="why">${opt.desc}</span>` : "");

      el.addEventListener("click", () => {
        if (disabled) return;
        if (group === "addons") {
          if (state.addons.has(opt.id)) state.addons.delete(opt.id);
          else state.addons.add(opt.id);
        } else {
          state[group] = state[group] === opt.id ? null : opt.id;
          // 如果选择使 addons 不兼容，清理
          for (const addon of [...state.addons]) {
            if (disableReason("addons", addon, state)) state.addons.delete(addon);
          }
        }
        render();
      });
      container.appendChild(el);
    }
  }
  renderOutput();
}

function renderOutput() {
  const statusEl = document.getElementById("status");
  const cfgEl = document.getElementById("config");
  const fpEl = document.getElementById("fingerprint");

  const missing = [];
  if (!state.protocol)  missing.push("协议");
  if (!state.transport) missing.push("传输");
  if (!state.tls)       missing.push("TLS");

  if (missing.length) {
    statusEl.innerHTML = `<div class="status err">⚠ 还需选择：${missing.join(" / ")}</div>`;
    cfgEl.textContent = "（请先完成必选项）";
    fpEl.textContent = "";
    return;
  }

  // 再做一轮全量冲突检查（防御：理论上 UI 已挡住）
  const conflicts = [];
  for (const [g, v] of Object.entries({
    protocol: state.protocol, transport: state.transport, tls: state.tls,
  })) {
    const r = disableReason(g, v, state);
    if (r) conflicts.push(`${g}.${v}: ${r}`);
  }
  for (const a of state.addons) {
    const r = disableReason("addons", a, state);
    if (r) conflicts.push(`addons.${a}: ${r}`);
  }
  if (conflicts.length) {
    statusEl.innerHTML = `<div class="status err">⚠ 冲突：<ul>${
      conflicts.map(c => `<li>${c}</li>`).join("")
    }</ul></div>`;
    cfgEl.textContent = "（冲突未解决）";
    return;
  }

  statusEl.innerHTML = `<div class="status ok">✓ 组合无冲突：${fingerprint(state)}</div>`;
  fpEl.textContent = fingerprint(state);
  cfgEl.innerHTML = colorize(JSON.stringify(buildConfig(state), null, 2));
}

function fingerprint(s) {
  const parts = [s.protocol, s.transport, s.tls !== "none" ? s.tls : null].filter(Boolean);
  const adds = [...s.addons];
  return parts.join("+") + (adds.length ? ` [${adds.join(",")}]` : "");
}

// ---------- 配置生成 ----------
function buildConfig(s) {
  const typeMap = { vless: "vless", trojan: "trojan", hy2: "hysteria2", ss2022: "shadowsocks", vmess: "vmess" };
  const inbound = {
    type: typeMap[s.protocol],
    tag:  fingerprint(s).replace(/[\s\[\],+]/g, "-").replace(/-+/g, "-").replace(/^-|-$/g, ""),
    listen: "::",
    listen_port: s.protocol === "hy2" ? 443 : (s.protocol === "trojan" ? 8443 : 443),
  };

  // users
  if (s.protocol === "vless") {
    inbound.users = [{ uuid: "REPLACE-WITH-UUID",
                       ...(s.addons.has("xtls") ? { flow: "xtls-rprx-vision" } : {}) }];
  } else if (s.protocol === "trojan") {
    inbound.users = [{ password: "REPLACE" }];
  } else if (s.protocol === "hy2") {
    inbound.users = [{ password: "REPLACE" }];
  } else if (s.protocol === "ss2022") {
    inbound.method = "2022-blake3-aes-256-gcm";
    inbound.password = "REPLACE-32-BYTE-BASE64";
  } else if (s.protocol === "vmess") {
    inbound.users = [{ uuid: "REPLACE-WITH-UUID", alterId: 0 }];
  }

  // tls block
  if (s.tls === "tls") {
    inbound.tls = {
      enabled: true,
      server_name: "vpn.example.com",
      certificate_path: "/etc/ssl/fullchain.pem",
      key_path: "/etc/ssl/privkey.pem",
      ...(s.addons.has("utls") ? { utls: { enabled: true, fingerprint: "chrome" } } : {}),
    };
  } else if (s.tls === "reality") {
    inbound.tls = {
      enabled: true,
      server_name: "www.microsoft.com",
      reality: {
        enabled: true,
        handshake: { server: "www.microsoft.com", server_port: 443 },
        private_key: "REPLACE-REALITY-PRIV",
        short_id: ["REPLACE-HEX"],
      },
      ...(s.addons.has("utls") ? { utls: { enabled: true, fingerprint: "chrome" } } : {}),
    };
  }

  // transport
  if (s.transport === "ws") {
    inbound.transport = {
      type: "ws",
      path: "/ray",
      ...(s.addons.has("cdn") ? { headers: { Host: "cdn.example.com" } } : {}),
    };
  } else if (s.transport === "grpc") {
    inbound.transport = {
      type: "grpc",
      service_name: "proto",
    };
  } else if (s.transport === "mkcp") {
    inbound.transport = { type: "mkcp", congestion: true };
  } else if (s.transport === "quic" && s.protocol !== "hy2") {
    inbound.transport = { type: "quic" };
  }
  // hy2 默认走 QUIC，不需要显式 transport

  // padding
  if (s.addons.has("padding")) {
    inbound.multiplex = { enabled: true, padding: true };
  }

  return inbound;
}

// ---------- JSON 语法高亮 ----------
function colorize(json) {
  return json
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"([^"]+)":/g, '<span class="k">"$1"</span>:')
    .replace(/: "([^"]+)"/g, ': <span class="s">"$1"</span>')
    .replace(/: (true|false|null)/g, ': <span class="n">$1</span>')
    .replace(/: (\d+)/g, ': <span class="n">$1</span>');
}

// ---------- 事件 ----------
document.getElementById("copy").addEventListener("click", () => {
  const txt = document.getElementById("config").innerText;
  navigator.clipboard.writeText(txt).then(() => {
    const btn = document.getElementById("copy");
    const old = btn.textContent;
    btn.textContent = "已复制 ✓";
    setTimeout(() => (btn.textContent = old), 1200);
  });
});
document.getElementById("reset").addEventListener("click", () => {
  state.protocol = state.transport = state.tls = null;
  state.addons.clear();
  render();
});

render();

// ---------- 公共 API（供 lab-client.js 等其他模块使用） ----------
window.buildConfig = buildConfig;
window.state = state;

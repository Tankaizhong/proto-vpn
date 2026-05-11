// composer.js — Alpine store: UI state + 选项 + 冲突 + buildConfig + JSON 着色
//
// 由 web/composer.html 通过 <script defer> 加载。
// 注册全局 Alpine.store('composer'); lab-client.js 通过它读 state / buildConfig。

document.addEventListener("alpine:init", () => {

  // ---------- 选项定义（数据） ----------
  const GROUPS = {
    protocol: {
      title: "1. 协议 (Protocol)",
      multi: false,
      options: [
        { id: "vless",  label: "VLESS",            desc: "无加密载荷，靠传输层 TLS 保密" },
        { id: "trojan", label: "Trojan",           desc: "密码 + TLS 伪装 HTTPS" },
        { id: "hy2",    label: "Hysteria2",        desc: "基于 QUIC，高丢包跨境" },
        { id: "ss2022", label: "Shadowsocks-2022", desc: "AEAD + BLAKE3，无 TLS" },
        { id: "vmess",  label: "VMess",            desc: "传统协议，AEAD 模式" },
      ],
    },
    transport: {
      title: "2. 传输 (Transport)",
      multi: false,
      options: [
        { id: "tcp",  label: "TCP",            desc: "通用，最稳" },
        { id: "ws",   label: "WebSocket",      desc: "可走 CDN" },
        { id: "grpc", label: "gRPC",           desc: "HTTP/2，CDN 友好" },
        { id: "mkcp", label: "mKCP",           desc: "UDP 上的 KCP，丢包好" },
        { id: "quic", label: "QUIC",           desc: "UDP，低延迟" },
      ],
    },
    tls: {
      title: "3. TLS / 握手伪装",
      multi: false,
      options: [
        { id: "none",    label: "无 TLS",       desc: "明文（仅 SS / 内网）" },
        { id: "tls",     label: "TLS 1.3",      desc: "标准 HTTPS 握手" },
        { id: "reality", label: "Reality",      desc: "借真实站点握手" },
      ],
    },
    addons: {
      title: "4. 加固选项 (Addons)",
      multi: true,
      options: [
        { id: "utls",    label: "uTLS 指纹",   desc: "ClientHello 伪装 Chrome" },
        { id: "padding", label: "包长填充",     desc: "smux + padding，削弱包长统计" },
        { id: "cdn",     label: "CDN 域前置",  desc: "WS Host 头走 CDN" },
        { id: "xtls",    label: "XTLS Vision", desc: "VLESS 专用流控" },
        { id: "ech",     label: "ECH",         desc: "加密 ClientHello，隐藏 SNI" },
      ],
    },
  };

  // ---------- 冲突规则（中心约束） ----------
  // 输入: groupKey, optionId, currentState；返回 string=不可选原因 或 null=可选
  function checkRule(group, id, s) {
    // ss2022 不能配 TLS
    if (group === "tls" && id !== "none" && s.protocol === "ss2022")
      return "ss2022 自带加密，不应叠加 TLS";
    if (group === "protocol" && id === "ss2022" && s.tls && s.tls !== "none")
      return "ss2022 与 TLS 冲突";

    // hy2 必须 UDP
    if (group === "transport" && ["tcp","ws","grpc"].includes(id) && s.protocol === "hy2")
      return "Hysteria2 是 UDP 协议，需 quic 或 mkcp";
    if (group === "protocol" && id === "hy2" && s.transport && !["quic","mkcp"].includes(s.transport))
      return "Hysteria2 需 UDP transport（quic/mkcp）";

    // Reality 不能与 ws/grpc/mkcp 共存
    if (group === "tls" && id === "reality" && ["ws","grpc","mkcp"].includes(s.transport))
      return "Reality 需要 TCP/QUIC，不能在 ws/grpc/mkcp 上";
    if (group === "transport" && ["ws","grpc","mkcp"].includes(id) && s.tls === "reality")
      return "Reality 不支持 ws/grpc/mkcp";

    // XTLS 只配 VLESS
    if (group === "addons" && id === "xtls" && s.protocol && s.protocol !== "vless")
      return "XTLS 仅支持 VLESS";

    // CDN 只配 WS
    if (group === "addons" && id === "cdn" && s.transport && s.transport !== "ws")
      return "CDN 域前置只对 WS 有意义";

    // uTLS 必须有 TLS
    if (group === "addons" && id === "utls" && s.tls === "none")
      return "uTLS 只用于 TLS 握手";

    // ECH 仅在标准 TLS 上有意义：Reality 已经隐藏了 SNI，叠加 ECH 无收益且 sing-box
    // 也不允许同一个 tls 块同时启用 reality+ech；明文协议（none）更没有 ClientHello 可加密。
    if (group === "addons" && id === "ech" && s.tls !== "tls")
      return "ECH 仅在 TLS 模式下可用（与 Reality / 无 TLS 互斥）";
    if (group === "tls" && id !== "tls" && s.addons && s.addons.has && s.addons.has("ech"))
      return "已启用 ECH，TLS 模式必须为 \"TLS 1.3\"";

    return null;
  }

  // ---------- 配置生成（纯函数） ----------
  function buildConfig(s) {
    const typeMap = {
      vless:  "vless",
      trojan: "trojan",
      hy2:    "hysteria2",
      ss2022: "shadowsocks",
      vmess:  "vmess",
    };
    const fp = fingerprintOf(s);
    const inbound = {
      type: typeMap[s.protocol],
      tag: fp.replace(/[\s\[\],+]/g, "-").replace(/-+/g, "-").replace(/^-|-$/g, ""),
      listen: "::",
      listen_port: s.protocol === "hy2" ? 443 : (s.protocol === "trojan" ? 8443 : 443),
    };

    if (s.protocol === "vless") {
      inbound.users = [{
        uuid: "REPLACE-WITH-UUID",
        ...(s.addons.has("xtls") ? { flow: "xtls-rprx-vision" } : {}),
      }];
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

    if (s.tls === "tls") {
      inbound.tls = {
        enabled: true,
        server_name: s.fields.tls_server_name || "vpn.example.com",
        certificate_path: "/etc/ssl/fullchain.pem",
        key_path: "/etc/ssl/privkey.pem",
        ...(s.addons.has("utls") ? { utls: { enabled: true, fingerprint: "chrome" } } : {}),
        ...(s.addons.has("ech") ? {
          ech: {
            enabled: true,
            key: ["-----BEGIN ECH KEYS-----", "REPLACE-ECH-KEY-BASE64", "-----END ECH KEYS-----"],
          },
        } : {}),
      };
    } else if (s.tls === "reality") {
      const rHost = s.fields.reality_handshake_server || "www.microsoft.com";
      const rPort = parseInt(s.fields.reality_handshake_port) || 443;
      inbound.tls = {
        enabled: true,
        server_name: rHost,
        reality: {
          enabled: true,
          handshake: { server: rHost, server_port: rPort },
          private_key: "REPLACE-REALITY-PRIV",
          short_id: ["REPLACE-HEX"],
        },
        ...(s.addons.has("utls") ? { utls: { enabled: true, fingerprint: "chrome" } } : {}),
      };
    }

    if (s.transport === "ws") {
      inbound.transport = {
        type: "ws",
        path: "/ray",
        ...(s.addons.has("cdn") ? { headers: { Host: "cdn.example.com" } } : {}),
      };
    } else if (s.transport === "grpc") {
      inbound.transport = { type: "grpc", service_name: "proto" };
    } else if (s.transport === "mkcp") {
      inbound.transport = { type: "mkcp", congestion: true };
    } else if (s.transport === "quic" && s.protocol !== "hy2") {
      inbound.transport = { type: "quic" };
    }

    if (s.addons.has("padding")) {
      inbound.multiplex = { enabled: true, padding: true };
    }
    return inbound;
  }

  function fingerprintOf(s) {
    const parts = [s.protocol, s.transport, s.tls !== "none" ? s.tls : null].filter(Boolean);
    const adds = [...s.addons];
    return parts.join("+") + (adds.length ? ` [${adds.join(",")}]` : "");
  }

  // ---------- JSON 语法着色（纯函数） ----------
  function colorize(json) {
    return json
      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
      .replace(/"([^"]+)":/g, '<span class="k">"$1"</span>:')
      .replace(/: "([^"]+)"/g, ': <span class="s">"$1"</span>')
      .replace(/: (-?\d+(?:\.\d+)?)/g, ': <span class="n">$1</span>');
  }

  // ====================================================================
  // Alpine store
  // ====================================================================
  Alpine.store("composer", {
    groups: GROUPS,
    state: { protocol: null, transport: null, tls: null, addons: new Set(), fields: { tls_server_name: "vpn.example.com", reality_handshake_server: "www.microsoft.com", reality_handshake_port: 443 } },

    init() {},

    // ----- 查询 -----
    isSelected(group, id) {
      if (group === "addons") return this.state.addons.has(id);
      return this.state[group] === id;
    },

    canSelect(group, id) {
      return checkRule(group, id, this.state) === null;
    },

    disabledReason(group, id) {
      return checkRule(group, id, this.state);
    },

    // ----- 操作 -----
    toggle(group, id) {
      if (!this.canSelect(group, id)) return;
      if (group === "addons") {
        const next = new Set(this.state.addons);
        if (next.has(id)) next.delete(id);
        else next.add(id);
        this.state.addons = next;   // 整体替换以触发 Alpine 响应
      } else {
        this.state[group] = (this.state[group] === id) ? null : id;
      }
    },

    reset() {
      this.state.protocol = null;
      this.state.transport = null;
      this.state.tls = null;
      this.state.addons = new Set();
      this.state.fields.tls_server_name = "vpn.example.com";
      this.state.fields.reality_handshake_server = "www.microsoft.com";
      this.state.fields.reality_handshake_port = 443;
    },

    // ----- 派生 -----
    get missing() {
      const m = [];
      if (!this.state.protocol)  m.push("协议");
      if (!this.state.transport) m.push("传输");
      if (!this.state.tls)       m.push("TLS");
      return m;
    },

    get conflicts() {
      const c = [];
      const s = this.state;
      const push = (r) => { if (r) c.push(r); };
      if (s.protocol)  push(checkRule("protocol", s.protocol, s));
      if (s.transport) push(checkRule("transport", s.transport, s));
      if (s.tls)       push(checkRule("tls", s.tls, s));
      for (const id of s.addons) push(checkRule("addons", id, s));
      return [...new Set(c)];
    },

    get isReady() {
      return this.missing.length === 0 && this.conflicts.length === 0;
    },

    get fingerprint() {
      return fingerprintOf(this.state);
    },

    get coloredJSON() {
      if (!this.isReady) return "（请完成必选项并解决冲突）";
      return colorize(JSON.stringify(this.buildConfig(), null, 2));
    },

    // ----- 公开给 lab-client.js -----
    buildConfig() {
      return buildConfig(this.state);
    },

    copyJSON(btn) {
      navigator.clipboard.writeText(JSON.stringify(this.buildConfig(), null, 2)).then(() => {
        const old = btn.textContent;
        btn.textContent = "已复制 ✓";
        setTimeout(() => { btn.textContent = old; }, 1200);
      });
    },
  });
});

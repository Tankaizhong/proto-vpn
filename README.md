# Proto — 多协议 / 多加密 / 多混淆 VPN 方案

> 一个可编排的 VPN 数据面与控制面设计，通过解耦 **传输 / 加密 / 混淆 / 控制** 四层，
> 允许每条会话自由组合协议，并具备动态切换、抗 DPI、抗主动探测的能力。

---

## 目录

- [项目简介](#项目简介)
- [特性](#特性)
- [整体架构](#整体架构)
- [分层说明](#分层说明)
- [快速开始](#快速开始)
- [配置示例](#配置示例)
- [部署建议](#部署建议)
- [性能与评估](#性能与评估)
- [威胁模型](#威胁模型)
- [路线图](#路线图)
- [常见问题](#常见问题)
- [合规声明](#合规声明)
- [参考资料](#参考资料)

## 仓库文件

| 路径 | 说明 |
|---|---|
| [`scripts/deploy.sh`](./scripts/deploy.sh) | 三入口（VLESS-Reality / Trojan-WS-TLS / Hysteria2）一键部署脚本 |
| [`docs/rotation-strategy.md`](./docs/rotation-strategy.md) | 协议轮换与链路选择策略，含评分函数、状态机、完整伪代码 |
| [`docs/subscription-format.md`](./docs/subscription-format.md) | 客户端订阅格式、Ed25519 签名与密钥轮换规范 |
| [`src/proto/subscription.py`](./src/proto/subscription.py) | 订阅 JWS Compact Ed25519 签发 / 校验库（按上文规范实现） |
| [`src/proto/rotation.py`](./src/proto/rotation.py) | 客户端轮换策略引擎：EWMA 评分 + 四态状态机 + 迟滞切换 |
| [`src/proto/bundle.py`](./src/proto/bundle.py) | 订阅 payload 校验 + 构造 `Selector/Config`（串联订阅与轮换） |
| [`scripts/sign_subscription.py`](./scripts/sign_subscription.py) | CLI：生成密钥 / 签发订阅 / 校验 token |
| [`tests/test_subscription.py`](./tests/test_subscription.py) | 订阅模块单元测试 |
| [`tests/test_rotation.py`](./tests/test_rotation.py) | 轮换引擎单元测试 |
| [`tests/test_bundle.py`](./tests/test_bundle.py) | 订阅→轮换集成测试（`python -m pytest tests/ -v` 共 101 例） |

---

## 项目简介

Proto 是一套"多协议并行 + 动态切换 + 流量伪装"的 VPN 参考方案。核心理念：

- **不依赖单一协议**：任何单点被封不会导致整体失效；
- **现代密码学为底**：AEAD + X25519 + 前向安全，不复用历史弱算法；
- **流量外观可定制**：通过真 TLS 1.3 / Reality / uTLS / CDN 域前置抵抗被动与主动探测；
- **策略驱动**：健康探测 + 协议轮换 + 配置订阅，客户端与服务器端持续协商最优链路。

本仓库既是**方案文档**，也可作为基于 [sing-box](https://sing-box.sagernet.org/) / [Xray-core](https://github.com/XTLS/Xray-core) 的编排模板。

---

## 特性

- 同时监听 **TCP/443 (TLS)** 与 **UDP/443 (QUIC / Hysteria2)**，自动回退；
- 支持 **VLESS-Reality / Trojan-WS-TLS / Hysteria2 / Shadowsocks-2022** 等主流协议；
- **uTLS 指纹模拟**：ClientHello 可伪装为 Chrome / Firefox / Safari；
- **Reality**：借用真实站点 TLS 握手，主动探测流量被透明转发到真站，零暴露；
- **CDN / 域前置**：WebSocket 或 gRPC 承载，IP 与域名解耦；
- **协议轮换**：按时间或字节阈值切换组合，削弱长期指纹统计；
- **短期证书与密钥轮换**：ACME 自动化，TTL ≤ 90 天；
- **可观测性**：统一 Prometheus 指标、结构化日志、RTT/丢包/切换事件。

---

## 整体架构

```
┌──────────────────────────────────────────────────────┐
│  控制面 (Control Plane)                               │
│  · 用户鉴权     · 配置分发     · 健康打分             │
│  · 协议编排     · 证书/密钥轮换 · 审计日志            │
└──────────────────────────────────────────────────────┘
                         │ 订阅 / gRPC
┌──────────────────────────────────────────────────────┐
│  数据面 (Data Plane)                                  │
│                                                      │
│  L7 隧道  │ VMess │ VLESS │ Trojan │ SS-2022 │       │
│  ─────────┼───────┴───────┴────────┴─────────┤       │
│  混淆伪装 │ TLS1.3 / Reality / uTLS / WS / gRPC │    │
│  ─────────┼───────────────────────────────────┤      │
│  加密     │ AES-256-GCM │ ChaCha20-Poly1305   │      │
│  ─────────┼───────────────────────────────────┤      │
│  传输     │ TCP │ QUIC │ Hysteria2 │ mKCP     │      │
│  ─────────┴────┴──────┴───────────┴──────────┘      │
└──────────────────────────────────────────────────────┘
```

---

## 分层说明

### 1. 传输层（Transport）

| 模式 | 适用场景 | 代价 |
|---|---|---|
| TCP + TLS | 通用，穿透强 | 队头阻塞 |
| QUIC / HTTP/3 | 移动网络、低延迟 | 易被运营商 QoS |
| Hysteria2 | 高丢包跨境链路 | UDP 易被封 |
| mKCP + FEC | 抗丢包 | 流量膨胀 ~30% |
| WebSocket / gRPC | 走 CDN | 额外封装开销 |

### 2. 加密层（Crypto）

- **AEAD**：AES-256-GCM（支持 AES-NI）、ChaCha20-Poly1305（移动端）；
- **密钥交换**：X25519 + HKDF，一次一密；
- **前向安全**：会话密钥不可从长期密钥推导；
- **重放防御**：时间戳 + nonce 滑动窗口；
- **禁用**：CFB、RC4-MD5、明文 VMess alterID 等历史弱组合。

### 3. 混淆 / 伪装层

| 技术 | 作用 |
|---|---|
| 真 TLS 1.3 + uTLS | 规避 JA3 / JA4 指纹 |
| Reality | 偷用真实站握手，主动探测转真站 |
| WebSocket / gRPC + CDN | IP 与域名解耦，抗 IP 封禁 |
| 流量整形 / padding | 削弱长度与时序指纹 |

### 4. 控制面

- **多入口 (multi-inbound)**：同一实例并行开三种以上协议；
- **健康探测**：客户端定期测 RTT/丢包，打分后切链路；
- **协议轮换**：按时间或字节阈值重协商；
- **差异化下发**：按 ASN / 地区下发不同入口组合；
- **证书与密钥轮换**：ACME 自动化，短 TTL。

---

## 快速开始

> 当前阶段推荐基于 **sing-box** 搭三入口跑通，再按需替换数据面。

### 环境要求

- Linux x86_64 或 arm64（内核 ≥ 5.10，支持 BBR）；
- 一个已解析到服务器的域名（用于 ACME）；
- 开放端口：TCP/443、UDP/443；
- CPU：AES-NI 支持可获得最佳 AES-GCM 吞吐。

### 安装（一键脚本）

仓库提供了服务器端一键部署脚本，自动完成 sing-box 安装、ACME 证书签发、凭据生成、
配置落盘、内核调优、防火墙放行与服务启用：

```bash
sudo DOMAIN=vpn.example.com bash scripts/deploy.sh
```

可选环境变量见 [`scripts/deploy.sh`](./scripts/deploy.sh) 头部注释。
部署完成后参数写入 `/etc/sing-box/deploy-summary.txt`（权限 600）。

### 客户端

按平台选择（均支持 sing-box 核心）：

- macOS / iOS：sing-box、Stash
- Windows：sing-box、Nekoray
- Android：sing-box、NekoBox
- Linux：sing-box CLI

---

## 配置示例

以下示例展示三入口并行的服务器端配置骨架，**仅供参考**，生产环境需按自身域名、证书、用户体系调整。

```jsonc
{
  "log": { "level": "info", "timestamp": true },

  "inbounds": [
    {
      "type": "vless",
      "tag": "vless-reality",
      "listen": "::",
      "listen_port": 443,
      "users": [{ "uuid": "REPLACE-WITH-UUID", "flow": "xtls-rprx-vision" }],
      "tls": {
        "enabled": true,
        "server_name": "www.microsoft.com",
        "reality": {
          "enabled": true,
          "handshake": { "server": "www.microsoft.com", "server_port": 443 },
          "private_key": "REPLACE",
          "short_id": ["REPLACE"]
        }
      }
    },
    {
      "type": "trojan",
      "tag": "trojan-ws",
      "listen": "::",
      "listen_port": 8443,
      "users": [{ "password": "REPLACE" }],
      "tls": {
        "enabled": true,
        "certificate_path": "/etc/ssl/fullchain.pem",
        "key_path": "/etc/ssl/privkey.pem"
      },
      "transport": { "type": "ws", "path": "/ray" }
    },
    {
      "type": "hysteria2",
      "tag": "hy2",
      "listen": "::",
      "listen_port": 443,
      "users": [{ "password": "REPLACE" }],
      "tls": {
        "enabled": true,
        "certificate_path": "/etc/ssl/fullchain.pem",
        "key_path": "/etc/ssl/privkey.pem"
      }
    }
  ],

  "outbounds": [
    { "type": "direct", "tag": "direct" },
    { "type": "block",  "tag": "block"  }
  ]
}
```

客户端订阅结构与签名规范见 [`docs/subscription-format.md`](./docs/subscription-format.md)。
协议轮换的评分函数、状态机与完整伪代码见 [`docs/rotation-strategy.md`](./docs/rotation-strategy.md)。

---

## 部署建议

1. **分三阶段演进**
   - 阶段一：sing-box 三入口跑通可用性与自动回退；
   - 阶段二：加策略引擎（健康打分、协议轮换、配置订阅）；
   - 阶段三：若确需私有协议指纹与审计集成，再考虑 Rust/Go 自研数据面，**复用 rustls / BoringSSL，不自造密码学**。

2. **多地域部署**
   - 至少两个地区的入口节点，不同 ASN；
   - 通过控制面差异化下发，避免单一指纹集中。

3. **证书与密钥**
   - ACME 自动签发与续期；
   - 长期密钥与短期会话密钥分离，短期密钥 ≤ 30 天轮换。

4. **可观测性**
   - Prometheus：`rtt`、`loss`、`bps`、`switch_count`、`handshake_fail`；
   - 结构化日志（JSON）+ 集中审计；
   - 健康降级告警。

5. **内核与网络**
   - `net.core.default_qdisc=fq`、`net.ipv4.tcp_congestion_control=bbr`；
   - UDP buffer 提升：`net.core.rmem_max` / `wmem_max`；
   - MTU 按 QUIC 建议值调优，避免分片。

---

## 性能与评估

### 收益

| 维度 | 评估 |
|---|---|
| 抗封锁 | 多协议并行 + Reality/uTLS 伪装，被动 DPI 命中率显著下降 |
| 可用性 | 单协议 ~95% → 组合方案 ~99.5% SLA |
| 性能 | QUIC / Hysteria2 在跨境高丢包链路吞吐是 TCP 的 2–5 倍 |
| 安全 | AEAD + PFS + 短期密钥，符合 TLS 1.3 现代标准 |
| 扩展性 | 协议插件化接入，不改核心 |

### 代价

| 维度 | 评估 |
|---|---|
| 复杂度 | 配置与运维门槛高，客户端实现量大 |
| 攻击面 | 协议越多潜在漏洞面越大（历史上 VMess / trojan-go 均出过识别漏洞） |
| CPU / 内存 | 多监听 + QUIC 用户态栈，单核 QPS 下降 20–40% |
| 流量开销 | mKCP/FEC 最多 +40%；WebSocket/gRPC 每包额外几十字节 |
| 指纹集中风险 | 所有用户共用同一 uTLS 指纹或同一 Reality 目标站，反而形成新特征 |

### 参考性能（千兆链路，无丢包）

| 方案 | 吞吐 | 备注 |
|---|---|---|
| WireGuard 纯净 | ~900 Mbps | 基线 |
| VLESS-Reality-TCP | ~700–800 Mbps | 伪装开销小 |
| Trojan-WS-TLS | ~500–600 Mbps | WS + TLS 叠加 |
| Hysteria2 | 视链路波动 | 高丢包跨境可反超 WireGuard 2× 以上 |

---

## 威胁模型

| 对手能力 | OpenVPN | WireGuard | 本方案 |
|---|---|---|---|
| 被动 DPI（协议指纹） | 易识别 | 易识别（固定握手） | 难（TLS / Reality 伪装） |
| 主动探测（发探测包） | 暴露 | 暴露 | Reality 回真站，低暴露 |
| 流量分析（时序/长度） | 中 | 中 | 需 padding / 整形缓解 |
| 端点封锁（IP 封禁） | 失效 | 失效 | CDN / 域前置可缓解 |
| 证书 / 密钥泄露 | 长期风险 | 长期风险 | 短 TTL + 轮换，影响面小 |

不在威胁模型覆盖范围：

- 端点主机被攻陷（应由 OS 加固与最小化权限处理）；
- 客户端设备上的恶意软件；
- 法律层面的强制交出凭据。

---

## 路线图

- [x] 方案文档与参考架构
- [x] sing-box 三入口一键部署脚本
- [x] 客户端订阅格式与签名
- [x] 策略引擎（健康打分 + 协议轮换）设计与伪代码
- [ ] Prometheus 指标与 Grafana 仪表盘
- [ ] 证书 / 密钥自动化轮换
- [ ] 端到端集成测试（DPI 模拟 + 主动探测回放）
- [ ] 可选：Rust 数据面原型

---

## 常见问题

**Q1：为什么不直接用 WireGuard？**
WireGuard 性能最好，但握手包有固定特征，在主动探测与 DPI 严苛的网络环境下容易被识别与封锁。本方案把 WireGuard 视作"理想基线"，但面对需要抗审查的场景时必须叠加混淆层。

**Q2：Reality 与传统 TLS 自签证书相比好在哪？**
自签证书的服务器在被主动探测时会暴露异常（证书异常、TLS 指纹异常、无真实内容响应）。Reality 直接转发探测到真实站点，探测方看到的是真站的证书与响应，几乎不可区分。

**Q3：为什么要协议轮换？**
即使单次会话无法识别，长期流量的统计特征（包长分布、时序模式）仍可能暴露。轮换可打散特征，增加识别成本。

**Q4：是否建议自研协议？**
不建议。除非你有强需求，否则使用 sing-box / Xray-core 的成熟实现更安全，社区修复与协议演进更快。

---

## 合规声明

本项目仅用于：

- 合法授权范围内的隐私保护与网络安全研究；
- 企业远程办公、跨区域内网访问等合规场景；
- 学习密码学、网络协议与流量分析的教学用途。

在部署与使用前，**请确保你已取得所在司法辖区与目标网络的合法授权**。作者与贡献者不对任何违反当地法律法规的使用行为负责。

---

## 参考资料

- sing-box: https://sing-box.sagernet.org/
- Xray-core (Reality / VLESS / XTLS-Vision): https://github.com/XTLS/Xray-core
- Hysteria2: https://v2.hysteria.network/
- uTLS: https://github.com/refraction-networking/utls
- TLS 1.3 (RFC 8446)
- QUIC (RFC 9000) / HTTP/3 (RFC 9114)
- Shadowsocks-2022 规范

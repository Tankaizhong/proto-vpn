# 客户端订阅格式与签名规范

> 控制面下发、客户端消费的订阅数据的**线上格式**、**签名方式**与**验证流程**。
> 设计目标：简单、可审计、抗重放、可轮换密钥。

---

## 1. 设计目标

| 目标 | 实现 |
|---|---|
| 机密性 | HTTPS（TLS 1.3）传输；敏感字段加密到用户（可选） |
| 完整性 | Ed25519 签名，覆盖整个 payload |
| 真实性 | 密钥通过 pinset 固定，防 MITM 签发 |
| 抗重放 | `iat` / `exp` + `nonce` 窗口 |
| 可轮换 | `kid` 标识签名密钥，支持平滑迁移 |
| 易解析 | JWS Compact（`a.b.c`），广泛库支持 |

---

## 2. 消息格式

订阅是一份 **JWS Compact** 序列化结构：

```
<protected>.<payload>.<signature>
```

各段 base64url 编码（去掉 `=` 填充）。

### 2.1 Protected Header

```json
{
  "alg": "EdDSA",
  "typ": "proto-sub+jwt",
  "kid": "proto-sign-2026-04"
}
```

- `alg`：固定 `EdDSA`（Ed25519），**客户端必须拒绝其他算法**；
- `kid`：当前使用的签名密钥 ID；
- `typ`：标识本协议类型。

### 2.2 Payload

```json
{
  "v": 1,
  "iss": "proto.example.com",
  "sub": "user-12345",
  "iat": 1745308800,
  "nbf": 1745308800,
  "exp": 1745312400,
  "jti": "0f3a7c1e-...-b92d",
  "policy": {
    "rotation": {
      "strategy": "hybrid",
      "min_hold_seconds": 60,
      "switch_margin": 0.15,
      "rotation_window_seconds": 1800,
      "rotation_bytes": 536870912
    },
    "probe": { "interval_seconds": 30, "timeout_ms": 1500 },
    "scoring": {
      "w_rtt": 0.35, "w_loss": 0.30, "w_bps": 0.20, "w_stab": 0.15,
      "rtt_max_ms": 400, "bps_ref_bps": 50000000
    },
    "cooldown": { "base_seconds": 30, "max_seconds": 600 }
  },
  "endpoints": [
    {
      "id": "ep-reality-hk-01",
      "proto": "vless-reality",
      "host": "a.example.com",
      "port": 443,
      "weight": 5,
      "params": {
        "uuid": "f6c7a9...-....-....",
        "flow": "xtls-rprx-vision",
        "sni": "www.microsoft.com",
        "public_key": "mG...=",
        "short_id": "9b3c..."
      }
    },
    {
      "id": "ep-trojan-sg-01",
      "proto": "trojan-ws-tls",
      "host": "b.example.com",
      "port": 8443,
      "weight": 3,
      "params": {
        "password": "redacted-or-envelope-encrypted",
        "sni": "b.example.com",
        "ws_path": "/ray"
      }
    },
    {
      "id": "ep-hy2-jp-01",
      "proto": "hysteria2",
      "host": "c.example.com",
      "port": 443,
      "weight": 2,
      "params": {
        "password": "redacted-or-envelope-encrypted",
        "sni": "c.example.com"
      }
    }
  ],
  "trust": {
    "current_kid": "proto-sign-2026-04",
    "pubkey_pinset": [
      { "kid": "proto-sign-2026-04", "key": "ed25519:MCowBQY...==", "not_after": 1753084800 },
      { "kid": "proto-sign-2026-07", "key": "ed25519:MCowBQY...==", "not_after": 1760860800 }
    ],
    "next_rotation_hint": 1752998400
  },
  "next_refresh_after": 1745311200
}
```

#### 字段说明

| 字段 | 必填 | 说明 |
|---|---|---|
| `v` | ✅ | 格式版本，当前 `1` |
| `iss` | ✅ | 签发方（控制面域名） |
| `sub` | ✅ | 用户标识（不可为空字符串） |
| `iat` / `nbf` / `exp` | ✅ | 签发 / 生效 / 失效（unix 秒） |
| `jti` | ✅ | 唯一 ID，UUIDv4，用于重放检测 |
| `policy` | ✅ | 策略配置，见 [rotation-strategy.md](./rotation-strategy.md) |
| `endpoints[]` | ✅ | 端点列表（至少 1 个） |
| `trust.pubkey_pinset` | ✅ | 当前及下一轮签名密钥 |
| `trust.current_kid` | ✅ | 应与 Protected Header 的 `kid` 一致 |
| `trust.next_rotation_hint` | ❌ | 预计下一次密钥轮换时间 |
| `next_refresh_after` | ✅ | 客户端最早何时再拉取（限流） |

### 2.3 Signature

```
signature = Ed25519(private_key_of_kid,
                   ASCII(base64url(protected) + "." + base64url(payload)))
```

---

## 3. 传输

### 3.1 拉取

```
GET /v1/subscription?token=<opaque> HTTP/1.1
Host: cfg.example.com
Accept: application/jose
If-None-Match: <etag>
```

- 必须 HTTPS + TLS 1.3；
- 建议启用 HPKP / 证书 pin（与 `pubkey_pinset` 独立）；
- 支持 `ETag` 缓存。

### 3.2 响应

```
HTTP/1.1 200 OK
Content-Type: application/jose
Cache-Control: private, max-age=60
ETag: "7c8e..."

<protected>.<payload>.<signature>
```

---

## 4. 验证流程（客户端必须实现）

```python
def verify(token_str: str, pinset: list[PinnedKey],
           seen_jti: set, clock_skew: int = 60) -> Payload:
    # 1. 解析三段式
    protected_b64, payload_b64, sig_b64 = token_str.split(".")
    header  = json.loads(b64url_decode(protected_b64))
    payload = json.loads(b64url_decode(payload_b64))
    sig     = b64url_decode(sig_b64)

    # 2. 算法白名单
    if header["alg"] != "EdDSA":
        reject("bad_alg")

    # 3. 查 kid 对应公钥
    key = next((p for p in pinset if p.kid == header["kid"]), None)
    if not key:
        reject("unknown_kid")
    if key.not_after and time.now() > key.not_after:
        reject("kid_expired")

    # 4. 验签
    signing_input = (protected_b64 + "." + payload_b64).encode("ascii")
    if not ed25519_verify(key.pub, signing_input, sig):
        reject("bad_signature")

    # 5. 时间窗
    now = time.now()
    if payload["nbf"] - clock_skew > now: reject("not_yet_valid")
    if payload["exp"] + clock_skew < now: reject("expired")

    # 6. 重放
    if payload["jti"] in seen_jti: reject("replay")
    seen_jti.add(payload["jti"])   # 持久化到本地，保留至 exp

    # 7. 一致性
    if payload["trust"]["current_kid"] != header["kid"]:
        reject("kid_mismatch")

    # 8. 版本
    if payload["v"] != 1:
        reject("unsupported_version")

    return payload
```

### 验证失败行为

| 失败类型 | 客户端行为 |
|---|---|
| `bad_alg` / `bad_signature` / `unknown_kid` | 立即丢弃，不降级使用旧订阅 |
| `expired` / `not_yet_valid` | 若本地缓存仍有效，继续使用；否则拒绝 |
| `replay` | 丢弃，但不告警（可能是重复请求） |
| `unsupported_version` | 提示升级客户端 |

---

## 5. 敏感字段的二次加密（可选）

对于 `endpoints[].params.password` 等高敏感字段，可额外做**用户级封装**，让即便控制面被入侵也无法直接获取可用凭据：

1. 客户端首次注册时生成 X25519 密钥对，公钥 `user_pub` 上交；
2. 控制面用 `user_pub` 做 ECDH + HKDF 派生对称密钥，AES-256-GCM 加密 password；
3. 字段值改为：`enc:x25519+aes256gcm:<b64(eph_pub)>:<b64(nonce)>:<b64(ct||tag)>`；
4. 客户端用自己的私钥解密。

权衡：增加复杂度，但让**签发方也看不到明文凭据**。

---

## 6. 密钥轮换

### 6.1 pinset 机制

订阅里始终携带**当前 + 下一轮**密钥。客户端行为：

1. 首次激活：pinset 从**带外渠道**（二维码 / 手动输入 / TOFU）获得；
2. 每次收到新订阅：合并其 `trust.pubkey_pinset`，扩展本地 pinset；
3. 不接受**非 pinset 内**的 `kid`，无论签名是否有效。

### 6.2 轮换流程

```
T0: 用 K_old 签发，pinset = [K_old, K_new]        # 提前 N 天引入 K_new
T1: 用 K_new 签发，pinset = [K_old, K_new]        # 过渡期
T2: 用 K_new 签发，pinset = [K_new, K_next]       # K_old 退役
```

- 过渡期建议 ≥ 1 个客户端刷新周期的 3 倍；
- 若 K_old 泄露：立即切换到 K_new，并推送带 `revoked_kids` 的一次性撤销订阅（见 §7）。

---

## 7. 撤销（Revocation）

### 7.1 订阅级

每次签发带 `exp`（建议 ≤ 1h），失效后客户端自动重新拉取。短 TTL 天然是撤销手段。

### 7.2 密钥级

紧急情况下，控制面下发**撤销公告**：

```json
{
  "v": 1,
  "type": "revocation",
  "iss": "proto.example.com",
  "iat": 1745308800,
  "revoked_kids": ["proto-sign-2026-04"],
  "signed_by_kid": "proto-sign-2026-07"
}
```

用**未被撤销**的密钥签名。客户端：

1. 从本地 pinset 移除 `revoked_kids`；
2. 丢弃所有仍由被撤销 kid 签发的缓存订阅；
3. 用剩余 pinset 重新拉取。

---

## 8. 示例

### 8.1 Protected Header（base64url 前）

```json
{"alg":"EdDSA","typ":"proto-sub+jwt","kid":"proto-sign-2026-04"}
```

### 8.2 Payload（base64url 前，截取）

见 §2.2。

### 8.3 完整 token（示意）

```
eyJhbGciOiJFZERTQSIsInR5cCI6InByb3RvLXN1Yitqd3QiLCJraWQiOiJwcm90by1zaWduLTIwMjYtMDQifQ.eyJ2IjoxLCJpc3MiOi...（payload base64url）....sSqJ3nFvHCZ1o...（signature base64url）
```

---

## 9. 兼容性与演进

- `v` 字段递增时，**Payload 内部字段可增删**，但 `v=1` 客户端遇到未知字段应**忽略而非拒绝**（除非字段出现在 `critical` 列表中）。
- 未来如需添加"关键变更"（如新增强制字段），可在 Protected Header 增加 `crit: ["field"]` 使旧客户端显式失败。

---

## 10. 不做的事

| 不做 | 理由 |
|---|---|
| 不用 RSA / HMAC | HMAC 需对称秘密分发，RSA 签名过大 |
| 不用自研签名算法 | Ed25519 成熟、实现库广泛、抗时序攻击 |
| 不在订阅中下发**长期**用户凭据明文 | 见 §5，高价值字段应二次封装 |
| 不使用 URL 参数携带完整 token | 避免日志泄露 |
| 不信任首次 TOFU 之后的 pinset 降级 | pinset 只增不减，除非显式撤销 |

# 协议轮换与链路选择策略

> 控制面与客户端侧的核心逻辑：在**可用性**与**抗指纹**之间动态取舍。
> 目标是做到"平时用最优，出事立刻切，长期不发胖"。

---

## 1. 目标与边界

| 目标 | 说明 |
|---|---|
| 可用性 | 任一协议/节点故障，客户端在 ≤ 5 秒内无感切换 |
| 抗指纹 | 避免长期驻留同一协议 → 削弱流量统计识别 |
| 稳定性 | 避免频繁抖动（flapping），带宽测量具足够置信度 |
| 成本 | 探测与切换开销不超过总带宽的 1% |

不在策略层处理的问题（由更底层/更外层负责）：

- 握手失败的根因分析 → 由日志与告警处理；
- 协议本身的安全性 → 由数据面与密码学层保证；
- 用户可见的 UI 切换提示 → 由客户端 UI 层处理。

---

## 2. 指标采集

每个端点（Endpoint）持续维护以下指标（EWMA 平滑，α=0.3）：

| 指标 | 来源 | 单位 | 备注 |
|---|---|---|---|
| `rtt` | 探测包 / 真实握手 | ms | 握手 RTT 优先，空闲时用主动探测 |
| `loss` | 探测 + 真实流 | 0–1 | 最近 N 次探测丢失率 |
| `bps` | 真实流 | bits/s | 仅在被选中时测 |
| `hs_fail` | 握手事件 | 次数 | 连续握手失败计数 |
| `last_ok` | 时间戳 | unix ts | 最近一次成功时间 |

---

## 3. 评分函数

单端点得分 `S ∈ [0, 1]`：

```
S = w_rtt  * f_rtt(rtt)
  + w_loss * f_loss(loss)
  + w_bps  * f_bps(bps)
  + w_stab * stability(recent_ok_ratio)

f_rtt(x)   = clamp(1 - x / RTT_MAX, 0, 1)          # 默认 RTT_MAX = 400ms
f_loss(x)  = (1 - x)^2                             # 丢失影响非线性放大
f_bps(x)   = min(log1p(x/BPS_REF) / log1p(1), 1)   # 默认 BPS_REF = 50 Mbps
stability  = 最近 N 次探测中成功的比例
```

默认权重：`w_rtt=0.35, w_loss=0.30, w_bps=0.20, w_stab=0.15`。

---

## 4. 状态机

每个端点处于以下状态之一：

```
           probe_ok
   ┌──────────────────────┐
   ▼                      │
┌───────┐  degrade   ┌────────┐
│healthy│──────────▶│degraded│
└───────┘            └────────┘
   ▲                      │ hs_fail >= F
   │ recovered            ▼
   │                 ┌────────┐
   │◀────────────────│cooldown│
   │                 └────────┘
   │                      │ cooldown_until timeout
   │                      ▼
   │                 ┌────────┐
   └─────────────────│  dead  │  (超过最大退避后永久降级)
                     └────────┘
```

- **healthy**：正常参与选择；
- **degraded**：评分低于阈值但可用，降低权重但仍保留；
- **cooldown**：最近失败，指数退避期内不参选；
- **dead**：退避达到 `cooldown_max` 仍失败 → 等待下一次配置刷新。

---

## 5. 选择与切换

三种基础策略：

| 策略 | 触发条件 | 场景 |
|---|---|---|
| `rtt_score` | 纯按得分选 | 追求性能 |
| `round_robin` | 按权重顺序 | 调试 / 基线 |
| `time_window` | 每 N 秒强制切换 | 抗指纹优先 |
| `hybrid`（默认） | 得分 + 时间/字节阈值 | 生产推荐 |

核心迟滞（hysteresis）规则：

1. **最小保持时长** `min_hold`（默认 60s）：切换后至少驻留该时长；
2. **切换边际** `switch_margin`（默认 15%）：候选得分需显著优于当前；
3. **强制轮换**：`hybrid` 下，达到 `rotation_window` 或 `rotation_bytes` 即使得分相近也切换一次，削弱长期指纹。

---

## 6. 伪代码

```python
# ============== 数据结构 ==============
class Endpoint:
    id: str
    proto: str            # vless | trojan | hysteria2 | ...
    host: str
    port: int
    weight: float = 1.0

    # 运行期
    state: str = "healthy"     # healthy | degraded | cooldown | dead
    score: float = 1.0
    rtt_ewma: float = 0.0      # ms
    loss_ewma: float = 0.0     # 0..1
    bps_ewma: float = 0.0      # bits/s
    hs_fail: int = 0
    last_ok: float = 0.0
    cooldown_until: float = 0.0

class Selector:
    endpoints: list[Endpoint]
    strategy: str                 # rtt_score | round_robin | time_window | hybrid
    current: Endpoint | None = None
    last_switch: float = 0.0
    bytes_since_switch: int = 0

    cfg = {
        "min_hold":        60,         # s
        "switch_margin":   0.15,
        "rotation_window": 1800,       # s
        "rotation_bytes":  512 * 1024 * 1024,
        "probe_interval":  30,         # s
        "cooldown_base":   30,         # s
        "cooldown_max":    600,        # s
        "degrade_score":   0.40,
        "alpha":           0.30,       # EWMA
        "rtt_max":         400.0,
        "bps_ref":         50_000_000,
    }

# ============== 评分 ==============
def compute_score(ep, cfg):
    f_rtt  = max(0.0, 1.0 - ep.rtt_ewma / cfg["rtt_max"])
    f_loss = (1.0 - ep.loss_ewma) ** 2
    f_bps  = min(log1p(ep.bps_ewma / cfg["bps_ref"]) / log1p(1.0), 1.0)
    f_stab = recent_ok_ratio(ep)
    return 0.35*f_rtt + 0.30*f_loss + 0.20*f_bps + 0.15*f_stab

# ============== 探测循环 ==============
def probe_loop(selector):
    while True:
        now = time.now()
        for ep in selector.endpoints:
            if ep.state == "cooldown" and now < ep.cooldown_until:
                continue
            rtt_ms, ok = tiny_probe(ep)     # TLS handshake / QUIC ping
            update_metrics(ep, rtt_ms, ok, selector.cfg)
            ep.score = compute_score(ep, selector.cfg)
            update_state(ep, selector.cfg)
        maybe_switch(selector)
        sleep(selector.cfg["probe_interval"])

def update_metrics(ep, rtt, ok, cfg):
    a = cfg["alpha"]
    if ok:
        ep.rtt_ewma  = a * rtt + (1 - a) * ep.rtt_ewma if ep.rtt_ewma else rtt
        ep.loss_ewma = a * 0  + (1 - a) * ep.loss_ewma
        ep.hs_fail   = 0
        ep.last_ok   = time.now()
    else:
        ep.loss_ewma = a * 1 + (1 - a) * ep.loss_ewma
        ep.hs_fail  += 1

def update_state(ep, cfg):
    now = time.now()
    if ep.state == "cooldown" and now >= ep.cooldown_until:
        ep.state = "degraded"
    if ep.hs_fail >= 3:
        backoff = min(cfg["cooldown_base"] * (2 ** (ep.hs_fail - 3)),
                      cfg["cooldown_max"])
        ep.cooldown_until = now + backoff
        ep.state = "cooldown" if backoff < cfg["cooldown_max"] else "dead"
        return
    if ep.score < cfg["degrade_score"]:
        ep.state = "degraded"
    else:
        ep.state = "healthy"

# ============== 切换决策 ==============
def maybe_switch(sel):
    now = time.now()
    cfg = sel.cfg

    # 1. 当前不可用 → 立即切
    if sel.current is None or sel.current.state in ("cooldown", "dead"):
        best = pick_best(sel, exclude_states=("cooldown", "dead"))
        if best:
            do_switch(sel, best, reason="current_unavailable")
        return

    # 2. 迟滞：最小保持
    if now - sel.last_switch < cfg["min_hold"]:
        return

    # 3. 强制轮换（抗指纹）
    if sel.strategy in ("time_window", "hybrid"):
        if now - sel.last_switch >= cfg["rotation_window"]:
            alt = pick_different(sel, sel.current)
            if alt: do_switch(sel, alt, reason="time_window_rotation")
            return
    if sel.strategy == "hybrid":
        if sel.bytes_since_switch >= cfg["rotation_bytes"]:
            alt = pick_different(sel, sel.current)
            if alt: do_switch(sel, alt, reason="bytes_rotation")
            return

    # 4. 分数显著更优 → 切
    best = pick_best(sel)
    if best and best.id != sel.current.id:
        if best.score > sel.current.score * (1 + cfg["switch_margin"]):
            do_switch(sel, best, reason="better_score")

def pick_best(sel, exclude_states=()):
    cands = [e for e in sel.endpoints if e.state not in exclude_states]
    if not cands: return None
    return max(cands, key=lambda e: e.score * e.weight)

def pick_different(sel, cur):
    cands = [e for e in sel.endpoints
             if e.id != cur.id and e.state in ("healthy", "degraded")]
    if not cands: return None
    # 权重采样，避免每次都切到同一备选
    return weighted_random(cands, key=lambda e: e.score * e.weight)

def do_switch(sel, target, reason):
    log("switch", from_=sel.current.id if sel.current else None,
        to=target.id, reason=reason, score=target.score)
    sel.current = target
    sel.last_switch = time.now()
    sel.bytes_since_switch = 0
    open_new_tunnel(target)                 # 建连
    drain_and_close_old(soft_timeout=5)     # 老隧道软关闭

# ============== 数据路径钩子 ==============
def on_bytes_transferred(sel, n):
    sel.bytes_since_switch += n

def on_handshake_fail(sel, ep):
    ep.hs_fail += 1
    update_state(ep, sel.cfg)
    if ep is sel.current:
        maybe_switch(sel)
```

---

## 7. 配置示例

客户端订阅中的策略字段（详见 [subscription-format.md](./subscription-format.md)）：

```json
{
  "policy": {
    "rotation": {
      "strategy": "hybrid",
      "min_hold_seconds": 60,
      "switch_margin": 0.15,
      "rotation_window_seconds": 1800,
      "rotation_bytes": 536870912
    },
    "probe": {
      "interval_seconds": 30,
      "timeout_ms": 1500,
      "parallel": true
    },
    "scoring": {
      "w_rtt": 0.35, "w_loss": 0.30, "w_bps": 0.20, "w_stab": 0.15,
      "rtt_max_ms": 400, "bps_ref_bps": 50000000
    },
    "cooldown": {
      "base_seconds": 30,
      "max_seconds": 600
    }
  }
}
```

---

## 8. 观测与调参建议

暴露的 Prometheus 指标：

| 指标 | 类型 | 说明 |
|---|---|---|
| `proto_endpoint_score` | Gauge | 每端点当前得分 |
| `proto_endpoint_rtt_ms` | Gauge | EWMA RTT |
| `proto_endpoint_loss_ratio` | Gauge | EWMA 丢失率 |
| `proto_endpoint_state` | Gauge | 0=healthy 1=degraded 2=cooldown 3=dead |
| `proto_switch_total` | Counter | 切换次数（按 reason 分标签） |
| `proto_handshake_fail_total` | Counter | 握手失败次数 |

调参经验：

- **抖动多？** 增大 `min_hold` 或 `switch_margin`；
- **切得慢？** 缩短 `probe_interval`，或把 `min_hold` 调到 30s；
- **指纹风险高？** 降 `rotation_window` 到 600s，启用 `rotation_bytes`；
- **弱网用户多？** 提高 `w_loss` 到 0.4，降低 `w_bps`；
- **部分节点总被选中？** 调整 `weight` 或检查是否某节点评分被异常放大。

---

## 9. 与实现映射

- **sing-box** 自身支持 `urltest` outbound，可实现简化版 `rtt_score`；
- 本策略的完整形态（带 hysteresis + 强制轮换 + cooldown）需在**客户端代理层**或**独立策略引擎**中实现；
- 推荐先用 sing-box 的 `urltest` + `fallback` 跑通基本可用性，再在外层加策略引擎做轮换与抗指纹。

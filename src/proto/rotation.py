"""Client-side endpoint selection and rotation policy.

Implements the scoring / state machine / hysteresis rules specified in
docs/rotation-strategy.md. Pure logic — no network I/O — so it can be
unit-tested deterministically.

Time and RNG are both injected: every function that needs "now" takes a
`now` float (unix seconds), and `pick_different` takes an optional
`random.Random` instance. Tests drive time explicitly and seed the RNG.
"""

from __future__ import annotations

import math
import random
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable, Sequence

__all__ = [
    "EndpointState",
    "Config",
    "Endpoint",
    "Selector",
    "SwitchDecision",
    "compute_score",
    "update_metrics",
    "update_state",
    "pick_best",
    "pick_different",
    "maybe_switch",
    "on_bytes_transferred",
    "on_handshake_fail",
]


class EndpointState(str, Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    COOLDOWN = "cooldown"
    DEAD = "dead"


@dataclass
class Config:
    """Tunable policy parameters — defaults match docs/rotation-strategy.md."""

    min_hold: float = 60.0                      # seconds
    switch_margin: float = 0.15                 # 15% score advantage
    rotation_window: float = 1800.0             # seconds
    rotation_bytes: int = 512 * 1024 * 1024     # 512 MB
    probe_interval: float = 30.0
    cooldown_base: float = 30.0
    cooldown_max: float = 600.0
    degrade_score: float = 0.40
    alpha: float = 0.30                         # EWMA smoothing factor
    rtt_max: float = 400.0                      # ms
    bps_ref: float = 50_000_000.0               # bits/s
    hs_fail_threshold: int = 3
    stability_window: int = 10                  # recent probes to track

    w_rtt: float = 0.35
    w_loss: float = 0.30
    w_bps: float = 0.20
    w_stab: float = 0.15


@dataclass
class Endpoint:
    """A single proxy endpoint with its live metrics and state."""

    id: str
    proto: str
    host: str
    port: int
    weight: float = 1.0

    state: EndpointState = EndpointState.HEALTHY
    score: float = 1.0
    rtt_ewma: float = 0.0
    loss_ewma: float = 0.0
    bps_ewma: float = 0.0
    hs_fail: int = 0
    last_ok: float = 0.0
    cooldown_until: float = 0.0
    _probes: deque[bool] = field(default_factory=lambda: deque(maxlen=10))

    def stability(self) -> float:
        if not self._probes:
            return 1.0
        return sum(1 for p in self._probes if p) / len(self._probes)


@dataclass
class Selector:
    endpoints: list[Endpoint]
    strategy: str = "hybrid"                    # rtt_score | round_robin | time_window | hybrid
    current: Endpoint | None = None
    last_switch: float = 0.0
    bytes_since_switch: int = 0


@dataclass
class SwitchDecision:
    target: Endpoint
    reason: str


def compute_score(ep: Endpoint, cfg: Config) -> float:
    """Weighted score ∈ [0,1] per §3 of rotation-strategy.md.

    rtt_ewma == 0.0 is treated as a sentinel meaning "never successfully
    measured" — f_rtt contributes 0 in that case, so a never-successful
    endpoint can't outscore a slow-but-working one on RTT alone.
    """
    f_rtt = 0.0 if ep.rtt_ewma <= 0.0 else max(0.0, 1.0 - ep.rtt_ewma / cfg.rtt_max)
    f_loss = (1.0 - ep.loss_ewma) ** 2
    # log1p(x)/log1p(1) normalizes so f_bps(bps_ref) ≈ 1.0
    f_bps = min(math.log1p(ep.bps_ewma / cfg.bps_ref) / math.log1p(1.0), 1.0)
    f_stab = ep.stability()
    return (
        cfg.w_rtt * f_rtt
        + cfg.w_loss * f_loss
        + cfg.w_bps * f_bps
        + cfg.w_stab * f_stab
    )


def update_metrics(
    ep: Endpoint,
    rtt_ms: float,
    ok: bool,
    cfg: Config,
    now: float,
    *,
    bps: float | None = None,
) -> None:
    """EWMA-update metrics from a probe outcome."""
    a = cfg.alpha
    if ep._probes.maxlen != cfg.stability_window:
        # Re-bind deque if config changed
        ep._probes = deque(ep._probes, maxlen=cfg.stability_window)
    ep._probes.append(bool(ok))

    if ok:
        ep.rtt_ewma = rtt_ms if ep.rtt_ewma == 0.0 else a * rtt_ms + (1 - a) * ep.rtt_ewma
        ep.loss_ewma = (1 - a) * ep.loss_ewma
        ep.hs_fail = 0
        ep.last_ok = now
    else:
        ep.loss_ewma = a * 1.0 + (1 - a) * ep.loss_ewma
        ep.hs_fail += 1

    if bps is not None:
        ep.bps_ewma = bps if ep.bps_ewma == 0.0 else a * bps + (1 - a) * ep.bps_ewma


def update_state(ep: Endpoint, cfg: Config, now: float) -> None:
    """Transition state per §4 of the spec."""
    if ep.state == EndpointState.COOLDOWN and now >= ep.cooldown_until:
        ep.state = EndpointState.DEGRADED

    if ep.hs_fail >= cfg.hs_fail_threshold:
        extra = ep.hs_fail - cfg.hs_fail_threshold
        backoff = min(cfg.cooldown_base * (2 ** extra), cfg.cooldown_max)
        ep.cooldown_until = now + backoff
        ep.state = EndpointState.DEAD if backoff >= cfg.cooldown_max else EndpointState.COOLDOWN
        return

    ep.state = EndpointState.DEGRADED if ep.score < cfg.degrade_score else EndpointState.HEALTHY


def pick_best(
    endpoints: Iterable[Endpoint],
    *,
    exclude_states: Sequence[EndpointState] = (),
) -> Endpoint | None:
    cands = [e for e in endpoints if e.state not in exclude_states]
    if not cands:
        return None
    return max(cands, key=lambda e: e.score * e.weight)


def pick_different(
    endpoints: Iterable[Endpoint],
    current: Endpoint,
    *,
    rng: random.Random | None = None,
) -> Endpoint | None:
    """Score-weighted random pick excluding `current`, cooldown, and dead."""
    rng = rng or random
    cands = [
        e for e in endpoints
        if e.id != current.id and e.state in (EndpointState.HEALTHY, EndpointState.DEGRADED)
    ]
    if not cands:
        return None
    weights = [max(e.score * e.weight, 1e-6) for e in cands]
    return rng.choices(cands, weights=weights, k=1)[0]


def maybe_switch(
    sel: Selector,
    cfg: Config,
    now: float,
    *,
    rng: random.Random | None = None,
) -> SwitchDecision | None:
    """Decide whether to switch current endpoint. Mutates `sel` if so."""
    # 1. Current unavailable → switch immediately
    if sel.current is None or sel.current.state in (EndpointState.COOLDOWN, EndpointState.DEAD):
        best = pick_best(sel.endpoints, exclude_states=(EndpointState.COOLDOWN, EndpointState.DEAD))
        if best is not None:
            return _do_switch(sel, best, "current_unavailable", now)
        return None

    # 2. Min hold — no switching allowed yet
    if now - sel.last_switch < cfg.min_hold:
        return None

    # 3. Forced rotation (anti-fingerprint)
    if sel.strategy in ("time_window", "hybrid"):
        if now - sel.last_switch >= cfg.rotation_window:
            alt = pick_different(sel.endpoints, sel.current, rng=rng)
            if alt is not None:
                return _do_switch(sel, alt, "time_window_rotation", now)
            return None
    if sel.strategy == "hybrid":
        if sel.bytes_since_switch >= cfg.rotation_bytes:
            alt = pick_different(sel.endpoints, sel.current, rng=rng)
            if alt is not None:
                return _do_switch(sel, alt, "bytes_rotation", now)
            return None

    # 4. Score advantage beyond switch_margin
    if sel.strategy in ("rtt_score", "hybrid"):
        best = pick_best(sel.endpoints, exclude_states=(EndpointState.COOLDOWN, EndpointState.DEAD))
        if best is not None and best.id != sel.current.id:
            if best.score > sel.current.score * (1 + cfg.switch_margin):
                return _do_switch(sel, best, "better_score", now)

    return None


def _do_switch(sel: Selector, target: Endpoint, reason: str, now: float) -> SwitchDecision:
    sel.current = target
    sel.last_switch = now
    sel.bytes_since_switch = 0
    return SwitchDecision(target=target, reason=reason)


def on_bytes_transferred(sel: Selector, n: int) -> None:
    sel.bytes_since_switch += n


def on_handshake_fail(sel: Selector, ep: Endpoint, cfg: Config, now: float) -> None:
    ep.hs_fail += 1
    update_state(ep, cfg, now)

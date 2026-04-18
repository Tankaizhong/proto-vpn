"""Glue layer: verified subscription payload → rotation Selector + Config.

After ``proto.subscription.verify_subscription`` returns a VerifyResult, the
payload is trusted JSON but still needs to be schema-checked before its
values are fed into ``proto.rotation``. This module does that:

    >>> from proto.subscription import verify_subscription
    >>> from proto.bundle import build_selector
    >>> result = verify_subscription(token, pinset)
    >>> selector, cfg = build_selector(result.payload)

``build_selector`` raises ``SchemaError`` on any structural problem so the
caller can fall back to a cached subscription per §verification step 5 of
the spec.
"""

from __future__ import annotations

from typing import Any

from proto.rotation import Config, Endpoint, Selector

__all__ = [
    "SchemaError",
    "validate_payload",
    "build_selector",
    "build_config",
    "build_endpoints",
    "ALLOWED_PROTOS",
    "ALLOWED_STRATEGIES",
]


# Whitelist keeps the client from ever wiring up an inbound type it can't
# drive. Add new protocols here only after corresponding client support lands.
ALLOWED_PROTOS = frozenset({"vless-reality", "trojan-ws-tls", "hysteria2"})
ALLOWED_STRATEGIES = frozenset({"rtt_score", "round_robin", "time_window", "hybrid"})


class SchemaError(ValueError):
    """Raised when a subscription payload does not match the expected shape."""


def _require(obj: Any, path: str, type_: type | tuple[type, ...]) -> Any:
    """Navigate `path` (dotted keys), assert the leaf value isinstance(type_)."""
    node: Any = obj
    for part in path.split("."):
        if not isinstance(node, dict):
            raise SchemaError(f"expected object at {path!r}, got {type(node).__name__}")
        if part not in node:
            raise SchemaError(f"missing required field {path!r}")
        node = node[part]
    if not isinstance(node, type_):
        name = type_.__name__ if isinstance(type_, type) else "|".join(t.__name__ for t in type_)
        raise SchemaError(f"field {path!r} must be {name}, got {type(node).__name__}")
    return node


def _optional(obj: Any, path: str, type_: type | tuple[type, ...], default: Any) -> Any:
    node: Any = obj
    for part in path.split("."):
        if not isinstance(node, dict) or part not in node:
            return default
        node = node[part]
    if not isinstance(node, type_):
        name = type_.__name__ if isinstance(type_, type) else "|".join(t.__name__ for t in type_)
        raise SchemaError(f"field {path!r} must be {name}, got {type(node).__name__}")
    return node


def validate_payload(payload: dict[str, Any]) -> None:
    """Schema-check a verified subscription payload. Raises SchemaError."""
    if not isinstance(payload, dict):
        raise SchemaError("payload must be a JSON object")

    _require(payload, "v", int)
    endpoints = _require(payload, "endpoints", list)
    if not endpoints:
        raise SchemaError("endpoints[] must contain at least one entry")

    seen_ids: set[str] = set()
    for i, ep in enumerate(endpoints):
        if not isinstance(ep, dict):
            raise SchemaError(f"endpoints[{i}] must be an object")
        ep_id = _require(ep, "id", str)
        if not ep_id:
            raise SchemaError(f"endpoints[{i}].id must be non-empty")
        if ep_id in seen_ids:
            raise SchemaError(f"duplicate endpoint id: {ep_id!r}")
        seen_ids.add(ep_id)
        proto = _require(ep, "proto", str)
        if proto not in ALLOWED_PROTOS:
            raise SchemaError(f"endpoints[{i}].proto {proto!r} not in {sorted(ALLOWED_PROTOS)}")
        _require(ep, "host", str)
        port = _require(ep, "port", int)
        if not 1 <= port <= 65535:
            raise SchemaError(f"endpoints[{i}].port {port} out of range")
        weight = _optional(ep, "weight", (int, float), 1.0)
        if weight <= 0:
            raise SchemaError(f"endpoints[{i}].weight must be > 0, got {weight}")

    strategy = _optional(payload, "policy.rotation.strategy", str, "hybrid")
    if strategy not in ALLOWED_STRATEGIES:
        raise SchemaError(
            f"policy.rotation.strategy {strategy!r} not in {sorted(ALLOWED_STRATEGIES)}"
        )


def build_config(payload: dict[str, Any]) -> Config:
    """Merge payload.policy into a rotation.Config, keeping library defaults
    for any field the payload does not specify."""
    validate_payload(payload)
    defaults = Config()

    return Config(
        min_hold=float(_optional(payload, "policy.rotation.min_hold_seconds", (int, float), defaults.min_hold)),
        switch_margin=float(_optional(payload, "policy.rotation.switch_margin", (int, float), defaults.switch_margin)),
        rotation_window=float(_optional(payload, "policy.rotation.rotation_window_seconds", (int, float), defaults.rotation_window)),
        rotation_bytes=int(_optional(payload, "policy.rotation.rotation_bytes", int, defaults.rotation_bytes)),
        probe_interval=float(_optional(payload, "policy.probe.interval_seconds", (int, float), defaults.probe_interval)),
        cooldown_base=float(_optional(payload, "policy.cooldown.base_seconds", (int, float), defaults.cooldown_base)),
        cooldown_max=float(_optional(payload, "policy.cooldown.max_seconds", (int, float), defaults.cooldown_max)),
        rtt_max=float(_optional(payload, "policy.scoring.rtt_max_ms", (int, float), defaults.rtt_max)),
        bps_ref=float(_optional(payload, "policy.scoring.bps_ref_bps", (int, float), defaults.bps_ref)),
        w_rtt=float(_optional(payload, "policy.scoring.w_rtt", (int, float), defaults.w_rtt)),
        w_loss=float(_optional(payload, "policy.scoring.w_loss", (int, float), defaults.w_loss)),
        w_bps=float(_optional(payload, "policy.scoring.w_bps", (int, float), defaults.w_bps)),
        w_stab=float(_optional(payload, "policy.scoring.w_stab", (int, float), defaults.w_stab)),
    )


def build_endpoints(payload: dict[str, Any]) -> list[Endpoint]:
    """Convert payload.endpoints[] into rotation.Endpoint instances."""
    validate_payload(payload)
    out: list[Endpoint] = []
    for ep in payload["endpoints"]:
        out.append(
            Endpoint(
                id=ep["id"],
                proto=ep["proto"],
                host=ep["host"],
                port=ep["port"],
                weight=float(ep.get("weight", 1.0)),
            )
        )
    return out


def build_selector(payload: dict[str, Any]) -> tuple[Selector, Config]:
    """One-shot: validate payload and produce a ready-to-use (Selector, Config)."""
    cfg = build_config(payload)
    endpoints = build_endpoints(payload)
    strategy = _optional(payload, "policy.rotation.strategy", str, "hybrid")
    return Selector(endpoints=endpoints, strategy=strategy, current=None), cfg

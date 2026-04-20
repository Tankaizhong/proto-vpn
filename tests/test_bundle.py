"""Tests for proto.bundle — payload schema validation and selector build."""

from __future__ import annotations

import copy
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from proto.bundle import (  # noqa: E402
    ALLOWED_PROTOS,
    ALLOWED_STRATEGIES,
    SchemaError,
    build_config,
    build_endpoints,
    build_selector,
    validate_payload,
)
from proto.rotation import Config, Selector  # noqa: E402


def _sample() -> dict:
    return {
        "v": 1,
        "iss": "proto.example.com",
        "sub": "user-1",
        "policy": {
            "rotation": {
                "strategy": "hybrid",
                "min_hold_seconds": 45,
                "switch_margin": 0.25,
                "rotation_window_seconds": 900,
                "rotation_bytes": 256 * 1024 * 1024,
            },
            "probe": {"interval_seconds": 20, "timeout_ms": 1000},
            "scoring": {
                "w_rtt": 0.4, "w_loss": 0.3, "w_bps": 0.2, "w_stab": 0.1,
                "rtt_max_ms": 500, "bps_ref_bps": 100_000_000,
            },
            "cooldown": {"base_seconds": 20, "max_seconds": 300},
        },
        "endpoints": [
            {
                "id": "ep-a",
                "proto": "vless-reality",
                "host": "a.example.com",
                "port": 443,
                "weight": 5,
                "params": {"uuid": "x", "flow": "xtls-rprx-vision", "sni": "www.microsoft.com"},
            },
            {
                "id": "ep-b",
                "proto": "hysteria2",
                "host": "b.example.com",
                "port": 443,
                "weight": 2,
                "params": {"password": "pw"},
            },
        ],
    }


class ValidatePayloadTests(unittest.TestCase):
    def test_valid_payload_passes(self) -> None:
        validate_payload(_sample())

    def test_missing_v_rejected(self) -> None:
        p = _sample()
        del p["v"]
        with self.assertRaises(SchemaError):
            validate_payload(p)

    def test_missing_endpoints_rejected(self) -> None:
        p = _sample()
        del p["endpoints"]
        with self.assertRaises(SchemaError):
            validate_payload(p)

    def test_empty_endpoints_rejected(self) -> None:
        p = _sample()
        p["endpoints"] = []
        with self.assertRaises(SchemaError):
            validate_payload(p)

    def test_duplicate_endpoint_id_rejected(self) -> None:
        p = _sample()
        p["endpoints"][1]["id"] = p["endpoints"][0]["id"]
        with self.assertRaises(SchemaError) as ctx:
            validate_payload(p)
        self.assertIn("duplicate", str(ctx.exception))

    def test_unknown_proto_rejected(self) -> None:
        p = _sample()
        p["endpoints"][0]["proto"] = "openvpn"
        with self.assertRaises(SchemaError):
            validate_payload(p)

    def test_bad_port_rejected(self) -> None:
        p = _sample()
        p["endpoints"][0]["port"] = 70000
        with self.assertRaises(SchemaError):
            validate_payload(p)
        p["endpoints"][0]["port"] = 0
        with self.assertRaises(SchemaError):
            validate_payload(p)

    def test_non_positive_weight_rejected(self) -> None:
        p = _sample()
        p["endpoints"][0]["weight"] = 0
        with self.assertRaises(SchemaError):
            validate_payload(p)

    def test_unknown_strategy_rejected(self) -> None:
        p = _sample()
        p["policy"]["rotation"]["strategy"] = "aggressive"
        with self.assertRaises(SchemaError):
            validate_payload(p)

    def test_payload_not_object(self) -> None:
        with self.assertRaises(SchemaError):
            validate_payload("not a dict")  # type: ignore[arg-type]

    def test_endpoint_not_object(self) -> None:
        p = _sample()
        p["endpoints"][0] = "not-an-object"
        with self.assertRaises(SchemaError):
            validate_payload(p)

    def test_empty_endpoint_id_rejected(self) -> None:
        p = _sample()
        p["endpoints"][0]["id"] = ""
        with self.assertRaises(SchemaError):
            validate_payload(p)

    def test_empty_endpoint_host_rejected(self) -> None:
        p = _sample()
        p["endpoints"][0]["host"] = ""
        with self.assertRaises(SchemaError) as ctx:
            validate_payload(p)
        self.assertIn("host", str(ctx.exception))

    def test_missing_policy_uses_defaults(self) -> None:
        """policy is not required — defaults apply."""
        p = _sample()
        del p["policy"]
        validate_payload(p)  # must not raise

    def test_wrong_type_port_rejected(self) -> None:
        """port present but wrong type → _require type-mismatch branch."""
        p = _sample()
        p["endpoints"][0]["port"] = "443"
        with self.assertRaises(SchemaError) as ctx:
            validate_payload(p)
        self.assertIn("port", str(ctx.exception))
        self.assertIn("int", str(ctx.exception))

    def test_wrong_type_weight_rejected(self) -> None:
        """weight present but wrong type → _optional type-mismatch branch (tuple type_)."""
        p = _sample()
        p["endpoints"][0]["weight"] = "heavy"
        with self.assertRaises(SchemaError) as ctx:
            validate_payload(p)
        self.assertIn("weight", str(ctx.exception))
        self.assertIn("int|float", str(ctx.exception))


class BuildConfigTests(unittest.TestCase):
    def test_policy_fields_propagate(self) -> None:
        cfg = build_config(_sample())
        self.assertEqual(cfg.min_hold, 45.0)
        self.assertEqual(cfg.switch_margin, 0.25)
        self.assertEqual(cfg.rotation_window, 900.0)
        self.assertEqual(cfg.rotation_bytes, 256 * 1024 * 1024)
        self.assertEqual(cfg.probe_interval, 20.0)
        self.assertEqual(cfg.rtt_max, 500.0)
        self.assertEqual(cfg.w_rtt, 0.4)

    def test_missing_policy_returns_defaults(self) -> None:
        p = _sample()
        del p["policy"]
        cfg = build_config(p)
        defaults = Config()
        self.assertEqual(cfg.min_hold, defaults.min_hold)
        self.assertEqual(cfg.switch_margin, defaults.switch_margin)
        self.assertEqual(cfg.rtt_max, defaults.rtt_max)

    def test_partial_policy_merges_defaults(self) -> None:
        p = _sample()
        p["policy"] = {"rotation": {"min_hold_seconds": 120}}
        cfg = build_config(p)
        defaults = Config()
        self.assertEqual(cfg.min_hold, 120.0)
        # Everything else falls back to defaults
        self.assertEqual(cfg.switch_margin, defaults.switch_margin)
        self.assertEqual(cfg.cooldown_base, defaults.cooldown_base)

    def test_wrong_type_policy_field_raises(self) -> None:
        """A policy numeric field given a string → _optional type-mismatch in build_config."""
        p = _sample()
        p["policy"]["rotation"]["min_hold_seconds"] = "slow"
        with self.assertRaises(SchemaError) as ctx:
            build_config(p)
        self.assertIn("min_hold", str(ctx.exception))


class BuildEndpointsTests(unittest.TestCase):
    def test_fields_map_through(self) -> None:
        eps = build_endpoints(_sample())
        self.assertEqual(len(eps), 2)
        self.assertEqual(eps[0].id, "ep-a")
        self.assertEqual(eps[0].proto, "vless-reality")
        self.assertEqual(eps[0].host, "a.example.com")
        self.assertEqual(eps[0].port, 443)
        self.assertEqual(eps[0].weight, 5.0)
        self.assertEqual(eps[1].id, "ep-b")
        self.assertEqual(eps[1].proto, "hysteria2")

    def test_default_weight(self) -> None:
        p = _sample()
        del p["endpoints"][0]["weight"]
        eps = build_endpoints(p)
        self.assertEqual(eps[0].weight, 1.0)


class BuildSelectorTests(unittest.TestCase):
    def test_full_roundtrip(self) -> None:
        sel, cfg = build_selector(_sample())
        self.assertIsInstance(sel, Selector)
        self.assertIsInstance(cfg, Config)
        self.assertEqual(sel.strategy, "hybrid")
        self.assertEqual(len(sel.endpoints), 2)
        self.assertIsNone(sel.current)

    def test_default_strategy_when_policy_missing(self) -> None:
        p = _sample()
        del p["policy"]
        sel, _ = build_selector(p)
        self.assertEqual(sel.strategy, "hybrid")

    def test_invalid_payload_raises(self) -> None:
        p = _sample()
        p["endpoints"][0]["proto"] = "l2tp"
        with self.assertRaises(SchemaError):
            build_selector(p)


class IntegrationTests(unittest.TestCase):
    """End-to-end: sign → verify → build → select."""

    def test_end_to_end(self) -> None:
        from proto.subscription import (
            Pinset,
            SigningKey,
            sign_subscription,
            verify_subscription,
        )
        from proto.rotation import compute_score, maybe_switch, update_metrics

        key = SigningKey.generate("kid-1")
        pinset = Pinset()
        pinset.add(key.public())

        token = sign_subscription(key, _sample())
        result = verify_subscription(token, pinset)
        sel, cfg = build_selector(result.payload)

        # Simulate a probe to endpoint a, then pick best
        update_metrics(sel.endpoints[0], rtt_ms=30, ok=True, cfg=cfg, now=0.0)
        sel.endpoints[0].score = compute_score(sel.endpoints[0], cfg)
        dec = maybe_switch(sel, cfg, now=1.0)
        self.assertIsNotNone(dec)
        self.assertEqual(dec.target.id, "ep-a")


class AllowlistConstantsTests(unittest.TestCase):
    def test_allowed_protos_populated(self) -> None:
        self.assertIn("vless-reality", ALLOWED_PROTOS)
        self.assertIn("trojan-ws-tls", ALLOWED_PROTOS)
        self.assertIn("hysteria2", ALLOWED_PROTOS)

    def test_allowed_strategies_match_rotation_module(self) -> None:
        self.assertEqual(
            ALLOWED_STRATEGIES,
            frozenset({"rtt_score", "round_robin", "time_window", "hybrid"}),
        )


if __name__ == "__main__":
    unittest.main()

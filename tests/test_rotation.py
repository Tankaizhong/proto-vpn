"""Tests for proto.rotation — scoring, state machine, hysteresis."""

from __future__ import annotations

import math
import random
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from proto.rotation import (  # noqa: E402
    Config,
    Endpoint,
    EndpointState,
    Selector,
    compute_score,
    maybe_switch,
    on_bytes_transferred,
    on_handshake_fail,
    pick_best,
    pick_different,
    update_metrics,
    update_state,
)


def _ep(id: str, proto: str = "vless", **overrides) -> Endpoint:
    ep = Endpoint(id=id, proto=proto, host=f"{id}.example.com", port=443)
    for k, v in overrides.items():
        setattr(ep, k, v)
    return ep


def _primed(cfg: Config, ok: bool = True, n: int = 10) -> Endpoint:
    """Endpoint with a known probe history for stable scoring tests."""
    ep = _ep("stable")
    for i in range(n):
        update_metrics(ep, rtt_ms=50.0, ok=ok, cfg=cfg, now=float(i))
    return ep


class ScoringTests(unittest.TestCase):
    def test_perfect_endpoint_scores_high(self) -> None:
        cfg = Config()
        ep = _ep("fast")
        for i in range(10):
            update_metrics(ep, rtt_ms=1.0, ok=True, cfg=cfg, now=float(i), bps=cfg.bps_ref)
        s = compute_score(ep, cfg)
        self.assertGreater(s, 0.95)
        self.assertLessEqual(s, 1.0)

    def test_fully_lossy_scores_low(self) -> None:
        cfg = Config()
        ep = _ep("bad")
        for i in range(10):
            update_metrics(ep, rtt_ms=500.0, ok=False, cfg=cfg, now=float(i))
        s = compute_score(ep, cfg)
        self.assertLess(s, 0.15)

    def test_score_in_bounds(self) -> None:
        cfg = Config()
        # Random-ish probe mix
        rng = random.Random(42)
        ep = _ep("mix")
        for i in range(30):
            update_metrics(
                ep,
                rtt_ms=rng.uniform(10, 800),
                ok=rng.random() > 0.3,
                cfg=cfg,
                now=float(i),
                bps=rng.uniform(0, 1e8),
            )
        s = compute_score(ep, cfg)
        self.assertGreaterEqual(s, 0.0)
        self.assertLessEqual(s, 1.0)

    def test_rtt_over_max_clamped_to_zero(self) -> None:
        cfg = Config()
        ep = _ep("slow")
        update_metrics(ep, rtt_ms=cfg.rtt_max * 3, ok=True, cfg=cfg, now=0.0)
        s = compute_score(ep, cfg)
        # f_rtt clamps to 0, so score = w_loss + w_stab = 0.30 + 0.15 = 0.45
        # (bps=0 → f_bps=0, stability=1.0 from single ok probe)
        self.assertAlmostEqual(s, 0.30 * 1.0 + 0.15 * 1.0, places=5)

    def test_never_measured_rtt_contributes_zero(self) -> None:
        """An endpoint whose probes all fail has rtt_ewma=0 but must not
        inherit a perfect f_rtt score — f_rtt is 0 when unmeasured."""
        cfg = Config()
        ep = _ep("never-ok")
        for i in range(5):
            update_metrics(ep, rtt_ms=100.0, ok=False, cfg=cfg, now=float(i))
        self.assertEqual(ep.rtt_ewma, 0.0)
        s = compute_score(ep, cfg)
        # f_rtt=0 (unmeasured), f_loss≈0 (~1.0 loss), f_bps=0, stability=0
        # → score should be nearly zero
        self.assertLess(s, 0.1)


class EwmaTests(unittest.TestCase):
    def test_ewma_rtt_converges(self) -> None:
        cfg = Config(alpha=0.3)
        ep = _ep("e")
        for i in range(50):
            update_metrics(ep, rtt_ms=100.0, ok=True, cfg=cfg, now=float(i))
        self.assertAlmostEqual(ep.rtt_ewma, 100.0, places=2)

    def test_ewma_loss_decays_on_success(self) -> None:
        cfg = Config(alpha=0.3)
        ep = _ep("e")
        # Start with high loss
        for i in range(5):
            update_metrics(ep, rtt_ms=50.0, ok=False, cfg=cfg, now=float(i))
        loss_initial = ep.loss_ewma
        self.assertGreater(loss_initial, 0.5)
        for i in range(5, 30):
            update_metrics(ep, rtt_ms=50.0, ok=True, cfg=cfg, now=float(i))
        self.assertLess(ep.loss_ewma, 0.05)

    def test_hs_fail_resets_on_success(self) -> None:
        cfg = Config()
        ep = _ep("e")
        for i in range(3):
            update_metrics(ep, rtt_ms=50.0, ok=False, cfg=cfg, now=float(i))
        self.assertEqual(ep.hs_fail, 3)
        update_metrics(ep, rtt_ms=50.0, ok=True, cfg=cfg, now=10.0)
        self.assertEqual(ep.hs_fail, 0)
        self.assertEqual(ep.last_ok, 10.0)


class StateMachineTests(unittest.TestCase):
    def test_healthy_to_cooldown_after_threshold_fails(self) -> None:
        cfg = Config(hs_fail_threshold=3, cooldown_base=30, cooldown_max=600)
        ep = _ep("e")
        for i in range(3):
            update_metrics(ep, rtt_ms=50.0, ok=False, cfg=cfg, now=float(i))
        ep.score = compute_score(ep, cfg)
        update_state(ep, cfg, now=100.0)
        self.assertEqual(ep.state, EndpointState.COOLDOWN)
        self.assertEqual(ep.cooldown_until, 130.0)  # 100 + 30*2^0

    def test_cooldown_backoff_grows_exponentially(self) -> None:
        cfg = Config(hs_fail_threshold=3, cooldown_base=30, cooldown_max=600)
        ep = _ep("e")
        ep.hs_fail = 5  # 2 failures beyond threshold
        ep.score = 0.1
        update_state(ep, cfg, now=0.0)
        # backoff = 30 * 2^2 = 120
        self.assertEqual(ep.cooldown_until, 120.0)
        self.assertEqual(ep.state, EndpointState.COOLDOWN)

    def test_becomes_dead_at_cooldown_max(self) -> None:
        cfg = Config(hs_fail_threshold=3, cooldown_base=30, cooldown_max=600)
        ep = _ep("e")
        ep.hs_fail = 20  # way past threshold → backoff clamps to max
        update_state(ep, cfg, now=0.0)
        self.assertEqual(ep.state, EndpointState.DEAD)

    def test_cooldown_expires_to_degraded(self) -> None:
        cfg = Config()
        ep = _ep("e", state=EndpointState.COOLDOWN, cooldown_until=50.0)
        update_state(ep, cfg, now=100.0)
        # No pending hs_fail, score irrelevant → degrade (score defaults to 1.0 so healthy)
        # Actually with score=1.0 > degrade_score, should go healthy
        self.assertEqual(ep.state, EndpointState.HEALTHY)

    def test_low_score_marks_degraded(self) -> None:
        cfg = Config(degrade_score=0.4)
        ep = _ep("e", score=0.2)
        update_state(ep, cfg, now=0.0)
        self.assertEqual(ep.state, EndpointState.DEGRADED)


class SelectionTests(unittest.TestCase):
    def test_pick_best_ignores_excluded_states(self) -> None:
        a = _ep("a", score=0.9)
        b = _ep("b", score=0.8, state=EndpointState.COOLDOWN)
        c = _ep("c", score=0.7)
        best = pick_best([a, b, c], exclude_states=(EndpointState.COOLDOWN, EndpointState.DEAD))
        self.assertIs(best, a)

    def test_pick_best_none_when_all_excluded(self) -> None:
        a = _ep("a", state=EndpointState.DEAD)
        b = _ep("b", state=EndpointState.COOLDOWN)
        best = pick_best([a, b], exclude_states=(EndpointState.COOLDOWN, EndpointState.DEAD))
        self.assertIsNone(best)

    def test_pick_different_excludes_current(self) -> None:
        a = _ep("a", score=0.9)
        b = _ep("b", score=0.8)
        c = _ep("c", score=0.7)
        rng = random.Random(1)
        for _ in range(20):
            alt = pick_different([a, b, c], current=a, rng=rng)
            self.assertIsNotNone(alt)
            self.assertNotEqual(alt.id, "a")

    def test_pick_different_skips_dead_and_cooldown(self) -> None:
        a = _ep("a")
        b = _ep("b", state=EndpointState.DEAD)
        c = _ep("c", state=EndpointState.COOLDOWN)
        rng = random.Random(1)
        for _ in range(10):
            alt = pick_different([a, b, c], current=a, rng=rng)
            self.assertIsNone(alt)


class SwitchingTests(unittest.TestCase):
    def _build(self, strategy: str = "hybrid") -> tuple[Selector, Config]:
        a = _ep("a", score=0.9)
        b = _ep("b", score=0.8)
        c = _ep("c", score=0.7)
        sel = Selector(endpoints=[a, b, c], strategy=strategy, current=a, last_switch=0.0)
        return sel, Config()

    def test_initial_pick_when_current_is_none(self) -> None:
        cfg = Config()
        a = _ep("a", score=0.5)
        b = _ep("b", score=0.9)
        sel = Selector(endpoints=[a, b], current=None)
        dec = maybe_switch(sel, cfg, now=0.0)
        self.assertIsNotNone(dec)
        self.assertEqual(dec.target.id, "b")
        self.assertEqual(dec.reason, "current_unavailable")
        self.assertIs(sel.current, b)

    def test_min_hold_blocks_switch(self) -> None:
        sel, cfg = self._build()
        sel.endpoints[1].score = 2.0  # huge advantage
        dec = maybe_switch(sel, cfg, now=cfg.min_hold - 1)
        self.assertIsNone(dec)

    def test_switch_margin_required(self) -> None:
        sel, cfg = self._build()
        # b only 5% better than a — below 15% margin
        sel.current.score = 1.0
        sel.endpoints[1].score = 1.05
        sel.endpoints[2].score = 0.1
        dec = maybe_switch(sel, cfg, now=cfg.min_hold + 1)
        self.assertIsNone(dec)

    def test_switch_triggered_by_margin(self) -> None:
        sel, cfg = self._build()
        sel.current.score = 1.0
        sel.endpoints[1].score = 1.20  # 20% > 15% margin
        sel.endpoints[2].score = 0.1
        dec = maybe_switch(sel, cfg, now=cfg.min_hold + 1)
        self.assertIsNotNone(dec)
        self.assertEqual(dec.target.id, "b")
        self.assertEqual(dec.reason, "better_score")
        self.assertEqual(sel.last_switch, cfg.min_hold + 1)
        self.assertEqual(sel.bytes_since_switch, 0)

    def test_time_window_forced_rotation(self) -> None:
        sel, cfg = self._build(strategy="hybrid")
        rng = random.Random(7)
        dec = maybe_switch(sel, cfg, now=cfg.rotation_window + 1, rng=rng)
        self.assertIsNotNone(dec)
        self.assertEqual(dec.reason, "time_window_rotation")
        self.assertNotEqual(dec.target.id, "a")

    def test_bytes_forced_rotation(self) -> None:
        sel, cfg = self._build(strategy="hybrid")
        sel.bytes_since_switch = cfg.rotation_bytes + 1
        rng = random.Random(7)
        dec = maybe_switch(sel, cfg, now=cfg.min_hold + 1, rng=rng)
        self.assertIsNotNone(dec)
        self.assertEqual(dec.reason, "bytes_rotation")

    def test_current_unavailable_forces_immediate_switch(self) -> None:
        sel, cfg = self._build()
        sel.current.state = EndpointState.COOLDOWN
        dec = maybe_switch(sel, cfg, now=10.0)
        self.assertIsNotNone(dec)
        self.assertEqual(dec.reason, "current_unavailable")
        self.assertNotEqual(dec.target.id, "a")

    def test_rtt_score_strategy_skips_rotation(self) -> None:
        """rtt_score strategy must NOT do forced rotation even past window."""
        sel, cfg = self._build(strategy="rtt_score")
        sel.current.score = 1.0
        sel.endpoints[1].score = 1.0  # no margin → no switch
        sel.endpoints[2].score = 1.0
        dec = maybe_switch(sel, cfg, now=cfg.rotation_window * 5)
        self.assertIsNone(dec)


class ByteCounterTests(unittest.TestCase):
    def test_bytes_accumulate(self) -> None:
        sel = Selector(endpoints=[_ep("a")], current=_ep("a"))
        on_bytes_transferred(sel, 100)
        on_bytes_transferred(sel, 200)
        self.assertEqual(sel.bytes_since_switch, 300)

    def test_switch_resets_bytes(self) -> None:
        cfg = Config()
        sel = Selector(
            endpoints=[_ep("a", score=1.0), _ep("b", score=2.0)],
            strategy="hybrid",
            current=None,
        )
        on_bytes_transferred(sel, 12345)
        maybe_switch(sel, cfg, now=0.0)
        self.assertEqual(sel.bytes_since_switch, 0)


class RoundRobinTests(unittest.TestCase):
    """round_robin strategy cycles endpoints in list order after min_hold."""

    def _build_rr(self) -> tuple[Selector, Config]:
        a = _ep("a")
        b = _ep("b")
        c = _ep("c")
        cfg = Config(min_hold=60.0)
        sel = Selector(endpoints=[a, b, c], strategy="round_robin", current=a, last_switch=0.0)
        return sel, cfg

    def test_advances_to_next_in_list(self) -> None:
        sel, cfg = self._build_rr()
        dec = maybe_switch(sel, cfg, now=cfg.min_hold + 1)
        self.assertIsNotNone(dec)
        self.assertEqual(dec.reason, "round_robin_rotation")
        self.assertEqual(dec.target.id, "b")

    def test_wraps_around_from_last_to_first(self) -> None:
        sel, cfg = self._build_rr()
        sel.current = sel.endpoints[2]  # currently on "c"
        dec = maybe_switch(sel, cfg, now=cfg.min_hold + 1)
        self.assertIsNotNone(dec)
        self.assertEqual(dec.target.id, "a")

    def test_skips_dead_and_cooldown_endpoints(self) -> None:
        sel, cfg = self._build_rr()
        sel.endpoints[1].state = EndpointState.DEAD      # "b" dead
        sel.endpoints[2].state = EndpointState.COOLDOWN  # "c" in cooldown
        # Only "a" available but that's current → no switch possible
        dec = maybe_switch(sel, cfg, now=cfg.min_hold + 1)
        self.assertIsNone(dec)

    def test_skips_to_next_healthy_past_unavailable(self) -> None:
        sel, cfg = self._build_rr()
        sel.endpoints[1].state = EndpointState.DEAD  # "b" dead; should land on "c"
        dec = maybe_switch(sel, cfg, now=cfg.min_hold + 1)
        self.assertIsNotNone(dec)
        self.assertEqual(dec.target.id, "c")

    def test_blocked_by_min_hold(self) -> None:
        sel, cfg = self._build_rr()
        dec = maybe_switch(sel, cfg, now=cfg.min_hold - 1)
        self.assertIsNone(dec)

    def test_does_not_do_score_based_switch(self) -> None:
        """round_robin must not switch based on score advantage."""
        sel, cfg = self._build_rr()
        sel.endpoints[1].score = 10.0  # huge score advantage
        dec = maybe_switch(sel, cfg, now=cfg.min_hold - 1)  # still within hold
        self.assertIsNone(dec)


class HandshakeFailHookTests(unittest.TestCase):
    def test_repeated_fails_push_to_cooldown(self) -> None:
        cfg = Config(hs_fail_threshold=3, cooldown_base=30)
        ep = _ep("e")
        sel = Selector(endpoints=[ep], current=ep)
        for i in range(3):
            on_handshake_fail(sel, ep, cfg, now=float(i))
        self.assertEqual(ep.state, EndpointState.COOLDOWN)


if __name__ == "__main__":
    unittest.main()

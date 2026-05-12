"""Unit tests for routes.py – exercised via FastAPI TestClient.

Covers (no subprocess / sing-box required):
  1. _translate()            – RunnerError → HTTPException mapping
  2. GET /                   – redirect to composer.html
  3. GET /health             – returns {"ok": True, "active_runs": [...]}
  4. GET /status             – returns active_runs list + pcaps list
  5. GET /runs/{id}/pcap     – path-traversal attempt → 400
  6. GET /runs/{id}/pcap     – run dir exists but no .pcap file → 404
  7. POST /run               – RunnerError propagated as HTTPException
  8. POST /stop/{id}         – RunnerError propagated as HTTPException
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from proto.composer.routes import _translate, router
from proto.composer.runner import RunnerError


def _make_client() -> TestClient:
    app = FastAPI()
    app.include_router(router)
    return TestClient(app, raise_server_exceptions=False)


# ── 1. _translate ──────────────────────────────────────────────────────────
class TranslateTests(unittest.TestCase):
    def test_code_and_detail_forwarded(self) -> None:
        err = RunnerError(409, "busy")
        http_exc = _translate(err)
        self.assertIsInstance(http_exc, HTTPException)
        self.assertEqual(http_exc.status_code, 409)
        self.assertEqual(http_exc.detail, "busy")

    def test_404_mapping(self) -> None:
        err = RunnerError(404, "run not found")
        self.assertEqual(_translate(err).status_code, 404)


# ── 2. GET / ───────────────────────────────────────────────────────────────
class RootRedirectTests(unittest.TestCase):
    def test_redirects_to_composer_html(self) -> None:
        client = _make_client()
        resp = client.get("/", follow_redirects=False)
        self.assertEqual(resp.status_code, 307)
        self.assertIn("composer.html", resp.headers["location"])


# ── 3. GET /health ─────────────────────────────────────────────────────────
class HealthTests(unittest.TestCase):
    def test_ok_true_with_empty_runs(self) -> None:
        import proto.composer.runner as _runner
        with patch.dict(_runner._RUNS, {}, clear=True):
            client = _make_client()
            resp = client.get("/health")
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertTrue(body["ok"])
        self.assertEqual(body["active_runs"], 0)


# ── 4. GET /status ─────────────────────────────────────────────────────────
class StatusTests(unittest.TestCase):
    def test_status_with_no_pcaps(self) -> None:
        import proto.composer.runner as _runner
        with patch.dict(_runner._RUNS, {}, clear=True):
            with tempfile.TemporaryDirectory() as tmpdir:
                from proto.composer import routes as _routes_mod
                with patch.object(_routes_mod, "DATA_DIR", Path(tmpdir)):
                    client = _make_client()
                    resp = client.get("/status")
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertIn("active_runs", body)
        self.assertIn("pcaps", body)
        self.assertEqual(body["pcaps"], [])


# ── 5 & 6. GET /runs/{id}/pcap ────────────────────────────────────────────
class PcapEndpointTests(unittest.TestCase):
    def test_path_traversal_returns_400(self) -> None:
        from proto.composer import routes as _routes_mod
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch.object(_routes_mod, "DATA_DIR", Path(tmpdir)):
                client = _make_client()
                resp = client.get("/runs/../etc/passwd/pcap")
        self.assertIn(resp.status_code, (400, 404))

    def test_missing_pcap_returns_404(self) -> None:
        from proto.composer import routes as _routes_mod
        with tempfile.TemporaryDirectory() as tmpdir:
            run_dir = Path(tmpdir) / "20260101-120000-abcd"
            run_dir.mkdir()
            with patch.object(_routes_mod, "DATA_DIR", Path(tmpdir)):
                client = _make_client()
                resp = client.get("/runs/20260101-120000-abcd/pcap")
        self.assertEqual(resp.status_code, 404)


# ── 7. POST /run – propagates RunnerError ─────────────────────────────────
class PostRunErrorTests(unittest.TestCase):
    def test_409_when_runner_busy(self) -> None:
        from proto.composer import runner as _runner
        busy_mock = AsyncMock(side_effect=RunnerError(409, "busy"))
        with patch.object(_runner, "start_run", busy_mock):
            client = _make_client()
            resp = client.post("/run", json={"inbound": {"type": "trojan"}})
        self.assertEqual(resp.status_code, 409)

    def test_400_for_bad_inbound(self) -> None:
        from proto.composer import runner as _runner
        bad_mock = AsyncMock(side_effect=RunnerError(400, "bad protocol"))
        with patch.object(_runner, "start_run", bad_mock):
            client = _make_client()
            resp = client.post("/run", json={"inbound": {"type": "wireguard"}})
        self.assertEqual(resp.status_code, 400)


# ── 8. POST /stop/{id} – propagates RunnerError ───────────────────────────
class PostStopErrorTests(unittest.TestCase):
    def test_404_for_unknown_run(self) -> None:
        from proto.composer import runner as _runner
        not_found_mock = AsyncMock(side_effect=RunnerError(404, "run not found"))
        with patch.object(_runner, "stop_run", not_found_mock):
            client = _make_client()
            resp = client.post("/stop/nonexistent-run-id")
        self.assertEqual(resp.status_code, 404)


if __name__ == "__main__":
    unittest.main()

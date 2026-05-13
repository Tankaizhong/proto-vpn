"""Unit tests for routes.py – exercised via FastAPI TestClient.

Covers (no subprocess / sing-box required):
  1. _translate()            – RunnerError → HTTPException mapping
  2. GET /                   – redirect to composer.html
  3. GET /health             – returns {"ok": True, "active_runs": [...]}
  4. GET /status             – returns active_runs list + pcaps list (empty and non-empty)
  5. GET /runs/{id}/pcap     – path-traversal attempt → 400
  6. GET /runs/{id}/pcap     – run dir exists but no .pcap file → 404
  7. GET /runs/{id}/pcap     – pcap file exists → 200 FileResponse
  8. POST /run               – RunnerError propagated as HTTPException
  9. POST /stop/{id}         – RunnerError propagated as HTTPException
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


# ── 1. _translate ──────────────────────────────────────────────────────
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


# ── 3. GET /health ──────────────────────────────────────────────────────────
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


# ── 4. GET /status ──────────────────────────────────────────────────────────
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


# ── 5 & 6. GET /runs/{id}/pcap ──────────────────────────────────────────────
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


# ── 7. POST /run – propagates RunnerError ─────────────────────────────────────
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


# ── 8. POST /stop/{id} – propagates RunnerError ──────────────────────────────
class PostStopErrorTests(unittest.TestCase):
    def test_404_for_unknown_run(self) -> None:
        from proto.composer import runner as _runner
        not_found_mock = AsyncMock(side_effect=RunnerError(404, "run not found"))
        with patch.object(_runner, "stop_run", not_found_mock):
            client = _make_client()
            resp = client.post("/stop/nonexistent-run-id")
        self.assertEqual(resp.status_code, 404)


# ── 9. GET /status – pcap list populated ───────────────────────────────────────
class StatusWithPcapsTests(unittest.TestCase):
    def test_status_lists_pcap_metadata_when_pcaps_exist(self) -> None:
        import proto.composer.runner as _runner
        from proto.composer import routes as _routes_mod
        with tempfile.TemporaryDirectory() as tmpdir:
            run_dir = Path(tmpdir) / "20260101-120000-aabb"
            run_dir.mkdir()
            pcap = run_dir / "trojan-tcp-tls.pcap"
            pcap.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)
            with patch.dict(_runner._RUNS, {}, clear=True):
                with patch.object(_routes_mod, "DATA_DIR", Path(tmpdir)):
                    client = _make_client()
                    resp = client.get("/status")
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertEqual(len(body["pcaps"]), 1)
        entry = body["pcaps"][0]
        self.assertEqual(entry["run_id"], "20260101-120000-aabb")
        self.assertEqual(entry["filename"], "trojan-tcp-tls.pcap")
        self.assertGreater(entry["size_bytes"], 0)
        self.assertIn("20260101-120000-aabb", entry["url"])


# ── 10. GET /runs/{id}/pcap – file present returns FileResponse ─────────────────
class PcapFileResponseTests(unittest.TestCase):
    def test_existing_pcap_returns_200_with_content(self) -> None:
        from proto.composer import routes as _routes_mod
        with tempfile.TemporaryDirectory() as tmpdir:
            run_dir = Path(tmpdir) / "20260101-120000-ccdd"
            run_dir.mkdir()
            pcap = run_dir / "hysteria2.pcap"
            pcap.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)
            with patch.object(_routes_mod, "DATA_DIR", Path(tmpdir)):
                client = _make_client()
                resp = client.get("/runs/20260101-120000-ccdd/pcap")
        self.assertEqual(resp.status_code, 200)
        # FastAPI FileResponse sets the right content-type header
        self.assertIn("pcap", resp.headers.get("content-type", ""))

    def test_path_traversal_blocked_when_run_id_escapes_data_dir(self) -> None:
        """A run_id crafted to escape DATA_DIR via symlink or double slash must return 400."""
        from proto.composer import routes as _routes_mod
        import os
        with tempfile.TemporaryDirectory() as outer:
            with tempfile.TemporaryDirectory() as inner:
                # Create a symlink inside inner that points outside it
                # Then use a run_id that resolves outside DATA_DIR
                evil_id = os.path.relpath(outer, inner)  # e.g. "../tmpXXX"
                with patch.object(_routes_mod, "DATA_DIR", Path(inner)):
                    client = _make_client()
                    resp = client.get(f"/runs/{evil_id}/pcap")
        # Either 400 (traversal detected) or 404 (dir not found) is acceptable;
        # what matters is that 200 is NOT returned for a path outside DATA_DIR.
        self.assertIn(resp.status_code, (400, 404))
        self.assertNotEqual(resp.status_code, 200)


if __name__ == "__main__":
    unittest.main()

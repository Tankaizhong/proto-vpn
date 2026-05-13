"""Unit tests for the main start_run() execution path in runner.py.

Covers lines 296-366 (directory creation → process spawn → RunInfo registration):
  1. server config invalid  → RunnerError 400 at line 311
  2. client config invalid  → RunnerError 400 at line 312-313
  3. tcpdump not found      → RunnerError 500 at line 321-322
  4. tcpdump dies on start  → RunnerError 500 at line 327-331
  5. sing-box server dies   → RunnerError 500 at line 337-339
  6. sing-box client dies   → RunnerError 500 at line 344-347
  7. success path           → run registered in _RUNS, correct dict returned
"""
from __future__ import annotations

import subprocess
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import proto.composer.runner as _runner_mod
from proto.composer.runner import RunnerError, start_run


def _fake_proc(poll_result=None):
    """Return a minimal Popen-like object."""
    p = MagicMock()
    p.poll.return_value = poll_result
    p.args = ["dummy"]
    return p


def _patch_all(
    *,
    server_check_err=None,
    client_check_err=None,
    tcpdump_missing=False,
    tcpdump_poll=None,
    server_poll=None,
    client_poll=None,
):
    """Return a stack of patches that replaces every external dependency in start_run."""
    patches = [
        patch("proto.composer.runner.DATA_DIR", new_callable=lambda: (lambda: Path(tempfile.mkdtemp()))),
        patch("proto.composer.runner._prepare_secrets", return_value={}),
        patch("proto.composer.runner.build_server_config", return_value={"tag": "test"}),
        patch("proto.composer.runner.build_client_config", return_value={"tag": "test"}),
    ]
    return patches


class StartRunConfigCheckTests(unittest.IsolatedAsyncioTestCase):
    """Branches: server/client config validation failures (lines 310-313)."""

    async def _run(self, server_err=None, client_err=None):
        with tempfile.TemporaryDirectory() as tmpdir:
            data_dir = Path(tmpdir)
            with (
                patch.dict(_runner_mod._RUNS, {}, clear=True),
                patch("proto.composer.runner.DATA_DIR", data_dir),
                patch("proto.composer.runner._prepare_secrets", return_value={}),
                patch("proto.composer.runner.build_server_config", return_value={}),
                patch("proto.composer.runner.build_client_config", return_value={}),
                patch(
                    "proto.composer.runner._check_singbox_config",
                    side_effect=[server_err, client_err],
                ),
                patch("asyncio.sleep", AsyncMock()),
            ):
                return await start_run({"type": "trojan", "tag": "trojan-tls"}, 30)

    async def test_server_config_invalid_raises_400(self) -> None:
        with self.assertRaises(RunnerError) as ctx:
            await self._run(server_err="bad server config")
        self.assertEqual(ctx.exception.code, 400)
        self.assertIn("server config invalid", ctx.exception.message)

    async def test_client_config_invalid_raises_400(self) -> None:
        with self.assertRaises(RunnerError) as ctx:
            await self._run(server_err=None, client_err="bad client config")
        self.assertEqual(ctx.exception.code, 400)
        self.assertIn("client config invalid", ctx.exception.message)


class StartRunTcpdumpTests(unittest.IsolatedAsyncioTestCase):
    """Branches: tcpdump not found / dies on start (lines 319-331)."""

    async def _run_with_tcpdump(self, *, missing=False, poll_result=None):
        with tempfile.TemporaryDirectory() as tmpdir:
            data_dir = Path(tmpdir)
            fake_td = _fake_proc(poll_result=poll_result)

            def _spawn_td(pcap, log):
                if missing:
                    raise FileNotFoundError("tcpdump not found")
                return fake_td

            with (
                patch.dict(_runner_mod._RUNS, {}, clear=True),
                patch("proto.composer.runner.DATA_DIR", data_dir),
                patch("proto.composer.runner._prepare_secrets", return_value={}),
                patch("proto.composer.runner.build_server_config", return_value={}),
                patch("proto.composer.runner.build_client_config", return_value={}),
                patch("proto.composer.runner._check_singbox_config", return_value=None),
                patch("proto.composer.runner._spawn_tcpdump", side_effect=_spawn_td),
                patch("asyncio.sleep", AsyncMock()),
            ):
                return await start_run({"type": "trojan", "tag": "trojan-tls"}, 30)

    async def test_tcpdump_not_found_raises_500(self) -> None:
        with self.assertRaises(RunnerError) as ctx:
            await self._run_with_tcpdump(missing=True)
        self.assertEqual(ctx.exception.code, 500)
        self.assertIn("tcpdump", ctx.exception.message)

    async def test_tcpdump_dies_immediately_raises_500(self) -> None:
        with self.assertRaises(RunnerError) as ctx:
            await self._run_with_tcpdump(poll_result=1)
        self.assertEqual(ctx.exception.code, 500)
        self.assertIn("tcpdump", ctx.exception.message)


class StartRunSingboxTests(unittest.IsolatedAsyncioTestCase):
    """Branches: sing-box server or client dies on start (lines 333-347)."""

    async def _run_singbox(self, *, server_poll=None, client_poll=None):
        with tempfile.TemporaryDirectory() as tmpdir:
            data_dir = Path(tmpdir)
            td_proc = _fake_proc(poll_result=None)
            server_proc = _fake_proc(poll_result=server_poll)
            client_proc = _fake_proc(poll_result=client_poll)
            singbox_calls = [server_proc, client_proc]

            with (
                patch.dict(_runner_mod._RUNS, {}, clear=True),
                patch("proto.composer.runner.DATA_DIR", data_dir),
                patch("proto.composer.runner._prepare_secrets", return_value={}),
                patch("proto.composer.runner.build_server_config", return_value={}),
                patch("proto.composer.runner.build_client_config", return_value={}),
                patch("proto.composer.runner._check_singbox_config", return_value=None),
                patch("proto.composer.runner._spawn_tcpdump", return_value=td_proc),
                patch("proto.composer.runner._spawn_singbox", side_effect=singbox_calls),
                patch("asyncio.sleep", AsyncMock()),
            ):
                return await start_run({"type": "trojan", "tag": "trojan-tls"}, 30)

    async def test_server_proc_dies_raises_500(self) -> None:
        with self.assertRaises(RunnerError) as ctx:
            await self._run_singbox(server_poll=1)
        self.assertEqual(ctx.exception.code, 500)
        self.assertIn("server", ctx.exception.message)

    async def test_client_proc_dies_raises_500(self) -> None:
        with self.assertRaises(RunnerError) as ctx:
            await self._run_singbox(server_poll=None, client_poll=1)
        self.assertEqual(ctx.exception.code, 500)
        self.assertIn("client", ctx.exception.message)


class StartRunSuccessTests(unittest.IsolatedAsyncioTestCase):
    """Happy path: run registered, correct dict keys returned (lines 353-372)."""

    async def test_success_returns_run_dict_and_registers_run(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            data_dir = Path(tmpdir)
            td_proc = _fake_proc(poll_result=None)
            server_proc = _fake_proc(poll_result=None)
            client_proc = _fake_proc(poll_result=None)
            traffic_proc = _fake_proc(poll_result=None)

            with (
                patch.dict(_runner_mod._RUNS, {}, clear=True),
                patch("proto.composer.runner.DATA_DIR", data_dir),
                patch("proto.composer.runner._prepare_secrets", return_value={}),
                patch("proto.composer.runner.build_server_config", return_value={}),
                patch("proto.composer.runner.build_client_config", return_value={}),
                patch("proto.composer.runner._check_singbox_config", return_value=None),
                patch("proto.composer.runner._spawn_tcpdump", return_value=td_proc),
                patch("proto.composer.runner._spawn_singbox", side_effect=[server_proc, client_proc]),
                patch("proto.composer.runner._spawn_traffic", return_value=traffic_proc),
                patch("asyncio.sleep", AsyncMock()),
                patch("asyncio.create_task"),
            ):
                result = await start_run({"type": "trojan", "tag": "trojan-tls"}, 30)

                # Result dict shape
                self.assertEqual(result["status"], "running")
                self.assertEqual(result["duration"], 30)
                self.assertIn("run_id", result)
                self.assertIn("pcap_url", result)
                self.assertIn("stop_url", result)

                # RunInfo registered (check while patch.dict is still active)
                run_id = result["run_id"]
                self.assertIn(run_id, _runner_mod._RUNS)
                info = _runner_mod._RUNS[run_id]
                self.assertEqual(info.fingerprint, "trojan-tls")
                self.assertEqual(len(info.procs), 4)

    async def test_fingerprint_falls_back_to_type_when_no_tag(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            data_dir = Path(tmpdir)
            procs = [_fake_proc(poll_result=None) for _ in range(4)]

            with (
                patch.dict(_runner_mod._RUNS, {}, clear=True),
                patch("proto.composer.runner.DATA_DIR", data_dir),
                patch("proto.composer.runner._prepare_secrets", return_value={}),
                patch("proto.composer.runner.build_server_config", return_value={}),
                patch("proto.composer.runner.build_client_config", return_value={}),
                patch("proto.composer.runner._check_singbox_config", return_value=None),
                patch("proto.composer.runner._spawn_tcpdump", return_value=procs[0]),
                patch("proto.composer.runner._spawn_singbox", side_effect=[procs[1], procs[2]]),
                patch("proto.composer.runner._spawn_traffic", return_value=procs[3]),
                patch("asyncio.sleep", AsyncMock()),
                patch("asyncio.create_task"),
            ):
                result = await start_run({"type": "vmess"}, 60)
                run_id = result["run_id"]
                self.assertEqual(_runner_mod._RUNS[run_id].fingerprint, "vmess")


if __name__ == "__main__":
    unittest.main()

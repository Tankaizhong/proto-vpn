"""Unit tests for pure/non-subprocess logic in runner.py.

Covers (no sing-box / tcpdump / openssl required):
  1. _pcap_filename  – tag present, tag absent, unsafe chars
  2. _is_tcpdump     – list args, string args, non-tcpdump
  3. RunnerError     – code + message attributes
  4. list_active()   – empty and non-empty _RUNS
  5. start_run()     – 409 when a run is already active
  6. start_run()     – 400 for an unsupported protocol
  7. stop_run()      – 404 for an unknown run_id
  8. _terminate()    – graceful shutdown ordering and error tolerance
  9. stop_run()      – success path: pcap exists / pcap absent
 10. shutdown_all()  – delegates to stop_run for each active run
 11. _auto_stop()    – fires stop after delay; no-op if run already gone
"""
from __future__ import annotations

import asyncio
import time
import types
import unittest
from pathlib import Path
from unittest.mock import patch

from proto.composer.runner import (
    RunInfo,
    RunnerError,
    _is_tcpdump,
    _pcap_filename,
    _terminate,
    list_active,
    shutdown_all,
    start_run,
    stop_run,
)
import proto.composer.runner as _runner_mod


# ── 1. _pcap_filename ──────────────────────────────────────────────────
class PcapFilenameTests(unittest.TestCase):
    def test_tag_is_used_when_present(self) -> None:
        self.assertEqual(_pcap_filename({"type": "trojan", "tag": "trojan-tcp-tls"}), "trojan-tcp-tls.pcap")

    def test_type_fallback_when_no_tag(self) -> None:
        self.assertEqual(_pcap_filename({"type": "hysteria2"}), "hysteria2.pcap")

    def test_empty_tag_falls_back_to_type(self) -> None:
        self.assertEqual(_pcap_filename({"type": "vless", "tag": ""}), "vless.pcap")

    def test_unsafe_chars_replaced(self) -> None:
        result = _pcap_filename({"type": "x", "tag": "foo bar/baz"})
        self.assertNotIn(" ", result)
        self.assertNotIn("/", result)
        self.assertTrue(result.endswith(".pcap"))

    def test_fallback_capture_when_all_empty(self) -> None:
        self.assertEqual(_pcap_filename({}), "capture.pcap")


# ── 2. _is_tcpdump ───────────────────────────────────────────────────
class IsTcpdumpTests(unittest.TestCase):
    def _fake_proc(self, args):
        p = types.SimpleNamespace(args=args)
        return p

    def test_list_args_ending_in_tcpdump(self) -> None:
        self.assertTrue(_is_tcpdump(self._fake_proc(["tcpdump", "-i", "lo"])))

    def test_list_args_full_path(self) -> None:
        self.assertTrue(_is_tcpdump(self._fake_proc(["/usr/bin/tcpdump", "-w", "out.pcap"])))

    def test_list_args_not_tcpdump(self) -> None:
        self.assertFalse(_is_tcpdump(self._fake_proc(["sing-box", "run", "-c", "cfg.json"])))

    def test_string_args_contains_tcpdump(self) -> None:
        self.assertTrue(_is_tcpdump(self._fake_proc("tcpdump -i lo -w out.pcap")))

    def test_string_args_no_tcpdump(self) -> None:
        self.assertFalse(_is_tcpdump(self._fake_proc("sing-box run -c cfg.json")))

    def test_empty_list(self) -> None:
        self.assertFalse(_is_tcpdump(self._fake_proc([])))


# ── 3. RunnerError ─────────────────────────────────────────────────────
class RunnerErrorTests(unittest.TestCase):
    def test_code_and_message_stored(self) -> None:
        err = RunnerError(409, "busy")
        self.assertEqual(err.code, 409)
        self.assertEqual(err.message, "busy")

    def test_is_exception(self) -> None:
        self.assertIsInstance(RunnerError(500, "oops"), Exception)

    def test_str_is_message(self) -> None:
        self.assertEqual(str(RunnerError(404, "not found")), "not found")


# ── 4. list_active ──────────────────────────────────────────────────────
class ListActiveTests(unittest.TestCase):
    def test_empty_when_no_runs(self) -> None:
        with patch.dict(_runner_mod._RUNS, {}, clear=True):
            self.assertEqual(list_active(), [])

    def test_returns_summary_for_each_run(self) -> None:
        fake_run = RunInfo(
            run_id="20260101-120000-abcd",
            started=time.time() - 10,
            duration=30,
        )
        with patch.dict(_runner_mod._RUNS, {"20260101-120000-abcd": fake_run}, clear=True):
            result = list_active()
        self.assertEqual(len(result), 1)
        entry = result[0]
        self.assertEqual(entry["run_id"], "20260101-120000-abcd")
        self.assertEqual(entry["duration"], 30)
        self.assertGreaterEqual(entry["elapsed_sec"], 10)


# ── 5 & 6. start_run – pre-subprocess checks ────────────────────────────
class StartRunErrorTests(unittest.IsolatedAsyncioTestCase):
    async def test_409_when_run_already_active(self) -> None:
        fake_run = RunInfo(run_id="x", started=time.time(), duration=30)
        with patch.dict(_runner_mod._RUNS, {"x": fake_run}, clear=True):
            with self.assertRaises(RunnerError) as ctx:
                await start_run({"type": "trojan"}, 30)
        self.assertEqual(ctx.exception.code, 409)

    async def test_400_for_unsupported_protocol(self) -> None:
        with patch.dict(_runner_mod._RUNS, {}, clear=True):
            with self.assertRaises(RunnerError) as ctx:
                await start_run({"type": "wireguard", "tag": "wg"}, 30)
        self.assertEqual(ctx.exception.code, 400)


# ── 7. stop_run – not-found check ─────────────────────────────────────────
class StopRunErrorTests(unittest.IsolatedAsyncioTestCase):
    async def test_404_for_unknown_run_id(self) -> None:
        with patch.dict(_runner_mod._RUNS, {}, clear=True):
            with self.assertRaises(RunnerError) as ctx:
                await stop_run("nonexistent-run-id")
        self.assertEqual(ctx.exception.code, 404)


# ── 8. _terminate – ordering and error tolerance ──────────────────────────
class TerminateTests(unittest.TestCase):
    def _fake_proc(self, *, is_tcpdump: bool, already_dead: bool = False):
        """Return a namespace whose interface matches what _terminate uses."""
        import types, subprocess
        p = types.SimpleNamespace(
            args=["tcpdump", "-i", "lo"] if is_tcpdump else ["sing-box", "run"],
            _terminated=False,
            _killed=False,
        )

        def _poll():
            return 0 if already_dead else None

        def _terminate_fn():
            p._terminated = True

        def _kill_fn():
            p._killed = True

        def _wait_fn(timeout=None):
            pass

        p.poll = _poll
        p.terminate = _terminate_fn
        p.kill = _kill_fn
        p.wait = _wait_fn
        return p

    def test_non_tcpdump_procs_terminated_before_tcpdump(self) -> None:
        server = self._fake_proc(is_tcpdump=False)
        tcpdump = self._fake_proc(is_tcpdump=True)
        _terminate([server, tcpdump])
        self.assertTrue(server._terminated)
        self.assertTrue(tcpdump._terminated)

    def test_already_dead_proc_not_terminated(self) -> None:
        dead = self._fake_proc(is_tcpdump=False, already_dead=True)
        _terminate([dead])
        self.assertFalse(dead._terminated)

    def test_empty_proc_list_does_not_raise(self) -> None:
        _terminate([])  # must not raise

    def test_terminate_exception_is_swallowed(self) -> None:
        import types
        p = types.SimpleNamespace(args=["sing-box", "run"])
        p.poll = lambda: None
        p.terminate = lambda: (_ for _ in ()).throw(OSError("gone"))
        p.wait = lambda timeout=None: None
        _terminate([p])  # should not propagate OSError

    def test_non_tcpdump_wait_timeout_triggers_kill(self) -> None:
        """When wait() raises TimeoutExpired for a non-tcpdump proc, kill() is called."""
        import types, subprocess
        p = types.SimpleNamespace(args=["sing-box", "run"], _killed=False)
        p.poll = lambda: None
        p.terminate = lambda: None

        def _wait(timeout=None):
            raise subprocess.TimeoutExpired(cmd=["sing-box"], timeout=timeout)

        p.wait = _wait
        p.kill = lambda: setattr(p, "_killed", True)
        _terminate([p])
        self.assertTrue(p._killed)

    def test_tcpdump_wait_timeout_triggers_kill(self) -> None:
        """When wait() raises TimeoutExpired for tcpdump, kill() is called."""
        import types, subprocess
        p = types.SimpleNamespace(args=["tcpdump", "-i", "lo"], _killed=False)
        p.poll = lambda: None
        p.terminate = lambda: None

        def _wait(timeout=None):
            raise subprocess.TimeoutExpired(cmd=["tcpdump"], timeout=timeout)

        p.wait = _wait
        p.kill = lambda: setattr(p, "_killed", True)
        _terminate([p])
        self.assertTrue(p._killed)

    def test_tcpdump_terminate_exception_is_swallowed(self) -> None:
        """OSError from tcpdump.terminate() must not propagate."""
        import types
        p = types.SimpleNamespace(args=["tcpdump", "-i", "lo"])
        p.poll = lambda: None
        p.terminate = lambda: (_ for _ in ()).throw(OSError("gone"))
        p.wait = lambda timeout=None: None
        _terminate([p])  # must not raise


# ── 9. stop_run – success path ─────────────────────────────────────────────
class StopRunSuccessTests(unittest.IsolatedAsyncioTestCase):
    async def test_stop_run_returns_summary_when_run_exists(self) -> None:
        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            fake_run = RunInfo(
                run_id="20260101-000000-beef",
                started=time.time() - 5,
                duration=30,
                procs=[],
                pcap_path=Path(tmpdir) / "test.pcap",
                run_dir=Path(tmpdir),
                log_dir=Path(tmpdir) / "logs",
                fingerprint="trojan",
            )
            with patch.dict(_runner_mod._RUNS, {"20260101-000000-beef": fake_run}, clear=True):
                result = await stop_run("20260101-000000-beef", reason="manual")
        self.assertEqual(result["run_id"], "20260101-000000-beef")
        self.assertEqual(result["status"], "stopped")
        self.assertEqual(result["reason"], "manual")
        self.assertEqual(result["pcap_size_bytes"], 0)  # pcap doesn't exist on disk
        self.assertGreaterEqual(result["elapsed_sec"], 5)

    async def test_stop_run_pcap_size_nonzero_when_file_exists(self) -> None:
        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            pcap = Path(tmpdir) / "capture.pcap"
            pcap.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)  # fake pcap bytes
            fake_run = RunInfo(
                run_id="20260101-000000-cafe",
                started=time.time() - 1,
                duration=30,
                procs=[],
                pcap_path=pcap,
                run_dir=Path(tmpdir),
                log_dir=Path(tmpdir) / "logs",
                fingerprint="vmess",
            )
            with patch.dict(_runner_mod._RUNS, {"20260101-000000-cafe": fake_run}, clear=True):
                result = await stop_run("20260101-000000-cafe")
        self.assertGreater(result["pcap_size_bytes"], 0)
        self.assertEqual(result["fingerprint"], "vmess")


# ── 10. shutdown_all ─────────────────────────────────────────────────────────
class ShutdownAllTests(unittest.IsolatedAsyncioTestCase):
    async def test_shutdown_all_stops_all_active_runs(self) -> None:
        fake_run = RunInfo(
            run_id="20260101-000000-dead",
            started=time.time(),
            duration=30,
            procs=[],
            pcap_path=Path("/nonexistent/capture.pcap"),
            run_dir=Path("/nonexistent"),
            log_dir=Path("/nonexistent/logs"),
            fingerprint="trojan",
        )
        with patch.dict(_runner_mod._RUNS, {"20260101-000000-dead": fake_run}, clear=True):
            await shutdown_all()
            self.assertEqual(len(_runner_mod._RUNS), 0)

    async def test_shutdown_all_tolerates_stop_error(self) -> None:
        """shutdown_all must not propagate exceptions from individual stop_run calls."""
        from unittest.mock import AsyncMock
        with patch.object(_runner_mod, "stop_run", AsyncMock(side_effect=RunnerError(500, "oops"))):
            fake_run = RunInfo(
                run_id="20260101-000000-face",
                started=time.time(),
                duration=30,
            )
            with patch.dict(_runner_mod._RUNS, {"20260101-000000-face": fake_run}, clear=True):
                await shutdown_all()  # should not raise


# ── 11. _auto_stop ──────────────────────────────────────────────────────────
class AutoStopTests(unittest.IsolatedAsyncioTestCase):
    async def test_auto_stop_calls_stop_run_after_delay(self) -> None:
        from unittest.mock import AsyncMock
        stop_mock = AsyncMock()
        with patch.object(_runner_mod, "stop_run", stop_mock):
            fake_run = RunInfo(
                run_id="20260101-000000-a1b2",
                started=time.time(),
                duration=0,
            )
            with patch.dict(_runner_mod._RUNS, {"20260101-000000-a1b2": fake_run}, clear=True):
                await _runner_mod._auto_stop("20260101-000000-a1b2", 0)
        stop_mock.assert_awaited_once_with("20260101-000000-a1b2", reason="timeout")

    async def test_auto_stop_no_op_when_run_already_gone(self) -> None:
        from unittest.mock import AsyncMock
        stop_mock = AsyncMock()
        with patch.object(_runner_mod, "stop_run", stop_mock):
            with patch.dict(_runner_mod._RUNS, {}, clear=True):
                await _runner_mod._auto_stop("nonexistent-run-id", 0)
        stop_mock.assert_not_awaited()

    async def test_auto_stop_swallows_stop_run_exception(self) -> None:
        """_auto_stop must not propagate RunnerError if stop_run fails."""
        from unittest.mock import AsyncMock
        stop_mock = AsyncMock(side_effect=RunnerError(500, "oops"))
        with patch.object(_runner_mod, "stop_run", stop_mock):
            fake_run = RunInfo(
                run_id="20260101-000000-ffff",
                started=time.time(),
                duration=0,
            )
            with patch.dict(_runner_mod._RUNS, {"20260101-000000-ffff": fake_run}, clear=True):
                await _runner_mod._auto_stop("20260101-000000-ffff", 0)  # must not raise


if __name__ == "__main__":
    unittest.main()

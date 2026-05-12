"""Unit tests for pure/non-subprocess logic in runner.py.

Covers (no sing-box / tcpdump / openssl required):
  1. _pcap_filename  – tag present, tag absent, unsafe chars
  2. _is_tcpdump     – list args, string args, non-tcpdump
  3. RunnerError     – code + message attributes
  4. list_active()   – empty and non-empty _RUNS
  5. start_run()     – 409 when a run is already active
  6. start_run()     – 400 for an unsupported protocol
  7. stop_run()      – 404 for an unknown run_id
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
    list_active,
    start_run,
    stop_run,
)
import proto.composer.runner as _runner_mod


# ── 1. _pcap_filename ──────────────────────────────────────────────────────
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


# ── 2. _is_tcpdump ─────────────────────────────────────────────────────────
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


# ── 3. RunnerError ─────────────────────────────────────────────────────────
class RunnerErrorTests(unittest.TestCase):
    def test_code_and_message_stored(self) -> None:
        err = RunnerError(409, "busy")
        self.assertEqual(err.code, 409)
        self.assertEqual(err.message, "busy")

    def test_is_exception(self) -> None:
        self.assertIsInstance(RunnerError(500, "oops"), Exception)

    def test_str_is_message(self) -> None:
        self.assertEqual(str(RunnerError(404, "not found")), "not found")


# ── 4. list_active ─────────────────────────────────────────────────────────
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


# ── 5 & 6. start_run – pre-subprocess checks ──────────────────────────────
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


if __name__ == "__main__":
    unittest.main()

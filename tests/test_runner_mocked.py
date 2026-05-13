"""Unit tests for subprocess-dependent and internal branches in runner.py.

All external calls are mocked; no sing-box / tcpdump / openssl needed.
Covers:
  1. _check_singbox_config  – success / stderr / stdout fallback paths (lines 66-70)
  2. _terminate             – kill() exception swallowing for both proc types (119-120, 133-134)
  3. _gen_reality_keypair   – success, non-zero returncode, missing keys (171-187)
  4. _gen_ech_keypair        – success, non-zero returncode, missing PEM (199-226)
  5. _gen_self_signed_cert  – success, non-zero returncode (231-244)
  6. _spawn_tcpdump/_spawn_singbox/_spawn_traffic – Popen is called (139, 146, 153-160)
  7. _prepare_secrets       – all protocol and TLS branches (249-279)
"""
from __future__ import annotations

import subprocess
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from proto.composer.runner import (
    RunnerError,
    _check_singbox_config,
    _gen_ech_keypair,
    _gen_reality_keypair,
    _gen_self_signed_cert,
    _prepare_secrets,
    _spawn_singbox,
    _spawn_tcpdump,
    _spawn_traffic,
    _terminate,
)


# ── 1. _check_singbox_config ─────────────────────────────────────────────
class CheckSingboxConfigTests(unittest.TestCase):
    def test_returns_none_on_success(self) -> None:
        fake = types.SimpleNamespace(returncode=0, stderr="", stdout="")
        with patch("subprocess.run", return_value=fake):
            self.assertIsNone(_check_singbox_config(Path("/tmp/cfg.json")))

    def test_returns_stderr_on_failure(self) -> None:
        fake = types.SimpleNamespace(returncode=1, stderr="bad config", stdout="")
        with patch("subprocess.run", return_value=fake):
            self.assertEqual(_check_singbox_config(Path("/tmp/cfg.json")), "bad config")

    def test_falls_back_to_stdout_when_stderr_empty(self) -> None:
        fake = types.SimpleNamespace(returncode=1, stderr="", stdout="syntax error")
        with patch("subprocess.run", return_value=fake):
            self.assertEqual(_check_singbox_config(Path("/tmp/cfg.json")), "syntax error")


# ── 2. _terminate – kill() exception swallowing ─────────────────────────────
class TerminateKillExceptionTests(unittest.TestCase):
    def _make_proc(self, *, is_tcpdump: bool):
        p = types.SimpleNamespace(
            args=["tcpdump", "-i", "lo"] if is_tcpdump else ["sing-box", "run"],
        )
        p.poll = lambda: None
        p.terminate = lambda: None
        p.wait = lambda timeout=None: (_ for _ in ()).throw(
            subprocess.TimeoutExpired(cmd=p.args, timeout=timeout)
        )
        p.kill = lambda: (_ for _ in ()).throw(OSError("process gone"))
        return p

    def test_non_tcpdump_kill_exception_is_swallowed(self) -> None:
        _terminate([self._make_proc(is_tcpdump=False)])  # must not raise

    def test_tcpdump_kill_exception_is_swallowed(self) -> None:
        _terminate([self._make_proc(is_tcpdump=True)])  # must not raise


# ── 3. _gen_reality_keypair ───────────────────────────────────────────────
class GenRealityKeypairTests(unittest.TestCase):
    def test_success_parses_priv_and_pub(self) -> None:
        fake = types.SimpleNamespace(
            returncode=0,
            stdout="PrivateKey: priv123\nPublicKey: pub456\n",
            stderr="",
        )
        with patch("subprocess.run", return_value=fake):
            priv, pub = _gen_reality_keypair()
        self.assertEqual(priv, "priv123")
        self.assertEqual(pub, "pub456")

    def test_raises_runner_error_on_nonzero_returncode(self) -> None:
        fake = types.SimpleNamespace(returncode=1, stdout="", stderr="not found")
        with patch("subprocess.run", return_value=fake):
            with self.assertRaises(RunnerError) as ctx:
                _gen_reality_keypair()
        self.assertEqual(ctx.exception.code, 500)

    def test_raises_when_keys_absent_from_output(self) -> None:
        fake = types.SimpleNamespace(returncode=0, stdout="unexpected output\n", stderr="")
        with patch("subprocess.run", return_value=fake):
            with self.assertRaises(RunnerError) as ctx:
                _gen_reality_keypair()
        self.assertEqual(ctx.exception.code, 500)


# ── 4. _gen_ech_keypair ───────────────────────────────────────────────────
class GenEchKeypairTests(unittest.TestCase):
    _GOOD_OUTPUT = (
        "-----BEGIN ECH KEYS-----\n"
        "FAKEKEYBASE64\n"
        "-----END ECH KEYS-----\n"
        "-----BEGIN ECH CONFIGS-----\n"
        "FAKECFGBASE64\n"
        "-----END ECH CONFIGS-----\n"
    )

    def test_success_returns_key_and_config_lines(self) -> None:
        fake = types.SimpleNamespace(returncode=0, stdout=self._GOOD_OUTPUT, stderr="")
        with patch("subprocess.run", return_value=fake):
            key_lines, config_lines = _gen_ech_keypair("vpn.example.com")
        self.assertTrue(any("BEGIN ECH KEYS" in l for l in key_lines))
        self.assertTrue(any("BEGIN ECH CONFIGS" in l for l in config_lines))
        self.assertTrue(any("END ECH KEYS" in l for l in key_lines))
        self.assertTrue(any("END ECH CONFIGS" in l for l in config_lines))

    def test_raises_on_nonzero_returncode(self) -> None:
        fake = types.SimpleNamespace(returncode=1, stdout="", stderr="sing-box not found")
        with patch("subprocess.run", return_value=fake):
            with self.assertRaises(RunnerError) as ctx:
                _gen_ech_keypair("vpn.example.com")
        self.assertEqual(ctx.exception.code, 500)

    def test_raises_when_pem_blocks_missing(self) -> None:
        fake = types.SimpleNamespace(returncode=0, stdout="no pem blocks here\n", stderr="")
        with patch("subprocess.run", return_value=fake):
            with self.assertRaises(RunnerError) as ctx:
                _gen_ech_keypair("vpn.example.com")
        self.assertEqual(ctx.exception.code, 500)


# ── 5. _gen_self_signed_cert ──────────────────────────────────────────────
class GenSelfSignedCertTests(unittest.TestCase):
    def test_success_returns_cert_and_key_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            run_dir = Path(tmpdir)
            fake = types.SimpleNamespace(returncode=0, stdout="", stderr="")
            with patch("subprocess.run", return_value=fake):
                cert, key = _gen_self_signed_cert(run_dir)
        self.assertEqual(cert.name, "cert.pem")
        self.assertEqual(key.name, "key.pem")

    def test_raises_on_openssl_failure(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            run_dir = Path(tmpdir)
            fake = types.SimpleNamespace(returncode=1, stdout="", stderr="openssl error")
            with patch("subprocess.run", return_value=fake):
                with self.assertRaises(RunnerError) as ctx:
                    _gen_self_signed_cert(run_dir)
        self.assertEqual(ctx.exception.code, 500)


# ── 6. _spawn_* functions – confirm Popen is invoked ─────────────────────
class SpawnFunctionTests(unittest.TestCase):
    def test_spawn_tcpdump_calls_popen(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            pcap = Path(tmpdir) / "test.pcap"
            fake_proc = MagicMock()
            with patch("subprocess.Popen", return_value=fake_proc) as mock_popen:
                result = _spawn_tcpdump(pcap, subprocess.DEVNULL)
            mock_popen.assert_called_once()
            cmd = mock_popen.call_args[0][0]
            self.assertIn("tcpdump", cmd[0])
        self.assertIs(result, fake_proc)

    def test_spawn_singbox_calls_popen(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg = Path(tmpdir) / "server.json"
            cfg.write_text("{}")
            fake_proc = MagicMock()
            with patch("subprocess.Popen", return_value=fake_proc) as mock_popen:
                result = _spawn_singbox(cfg, subprocess.DEVNULL)
            mock_popen.assert_called_once()
            cmd = mock_popen.call_args[0][0]
            self.assertIn("sing-box", cmd[0])
        self.assertIs(result, fake_proc)

    def test_spawn_traffic_calls_popen_with_bash(self) -> None:
        fake_proc = MagicMock()
        with patch("subprocess.Popen", return_value=fake_proc) as mock_popen:
            result = _spawn_traffic(subprocess.DEVNULL)
        mock_popen.assert_called_once()
        cmd = mock_popen.call_args[0][0]
        self.assertEqual(cmd[0], "bash")
        self.assertIs(result, fake_proc)


# ── 7. _prepare_secrets – all protocol and TLS branches ────────────────────
class PrepareSecretsTests(unittest.TestCase):
    def _run(self, inbound: dict) -> dict:
        with tempfile.TemporaryDirectory() as tmpdir:
            return _prepare_secrets(inbound, Path(tmpdir))

    def test_shadowsocks_generates_password(self) -> None:
        secrets = self._run({"type": "shadowsocks"})
        self.assertIn("password", secrets)
        self.assertNotIn("uuid", secrets)

    def test_trojan_generates_password(self) -> None:
        secrets = self._run({"type": "trojan"})
        self.assertIn("password", secrets)

    def test_hysteria2_generates_password(self) -> None:
        secrets = self._run({"type": "hysteria2"})
        self.assertIn("password", secrets)

    def test_vless_generates_uuid(self) -> None:
        secrets = self._run({"type": "vless"})
        self.assertIn("uuid", secrets)
        self.assertNotIn("password", secrets)

    def test_vmess_generates_uuid(self) -> None:
        secrets = self._run({"type": "vmess"})
        self.assertIn("uuid", secrets)

    def test_no_tls_produces_no_cert_fields(self) -> None:
        secrets = self._run({"type": "trojan"})
        self.assertNotIn("cert_path", secrets)
        self.assertNotIn("reality_priv", secrets)

    def test_tls_with_reality_generates_keypair_and_short_id(self) -> None:
        inbound = {
            "type": "vless",
            "tls": {"enabled": True, "reality": {"handshake": {"server": "x.example.com"}}},
        }
        with patch(
            "proto.composer.runner._gen_reality_keypair", return_value=("priv_k", "pub_k")
        ):
            secrets = self._run(inbound)
        self.assertEqual(secrets["reality_priv"], "priv_k")
        self.assertEqual(secrets["reality_pub"], "pub_k")
        self.assertIn("short_id", secrets)
        self.assertNotIn("cert_path", secrets)

    def test_tls_without_reality_generates_cert_and_key(self) -> None:
        inbound = {
            "type": "trojan",
            "tls": {"enabled": True, "server_name": "vpn.example.com"},
        }
        fake_openssl = types.SimpleNamespace(returncode=0, stdout="", stderr="")
        with patch("subprocess.run", return_value=fake_openssl):
            secrets = self._run(inbound)
        self.assertIn("cert_path", secrets)
        self.assertIn("key_path", secrets)
        self.assertNotIn("ech_key_lines", secrets)

    def test_tls_without_reality_with_ech_generates_ech_keys(self) -> None:
        inbound = {
            "type": "trojan",
            "tls": {
                "enabled": True,
                "server_name": "vpn.example.com",
                "ech": {"enabled": True},
            },
        }
        fake_openssl = types.SimpleNamespace(returncode=0, stdout="", stderr="")
        fake_ech = (
            ["-----BEGIN ECH KEYS-----", "key", "-----END ECH KEYS-----"],
            ["-----BEGIN ECH CONFIGS-----", "cfg", "-----END ECH CONFIGS-----"],
        )
        with patch("subprocess.run", return_value=fake_openssl):
            with patch("proto.composer.runner._gen_ech_keypair", return_value=fake_ech):
                secrets = self._run(inbound)
        self.assertEqual(secrets["ech_key_lines"], fake_ech[0])
        self.assertEqual(secrets["ech_config_lines"], fake_ech[1])


if __name__ == "__main__":
    unittest.main()

"""
Cover two branch edges left at 99% after the prior test pass:

  runner.py:123->122  – _terminate: tcpdump process already exited (poll()!=None)
  runner.py:257->261  – _prepare_secrets: unknown protocol type, no auth secret set
"""
import types
import tempfile
import unittest
from pathlib import Path

from proto.composer.runner import _terminate, _prepare_secrets


# ── _terminate: already-dead tcpdump skips terminate() ────────────────────────
class TerminateDeadTcpdumpTests(unittest.TestCase):
    def _make_tcpdump_proc(self, *, already_dead: bool):
        p = types.SimpleNamespace(
            args=["tcpdump", "-i", "lo", "-w", "out.pcap"],
            _terminated=False,
        )
        p.poll = lambda: (0 if already_dead else None)
        p.terminate = lambda: setattr(p, "_terminated", True)
        p.wait = lambda timeout=None: None
        p.kill = lambda: None
        return p

    def test_already_dead_tcpdump_is_not_terminated(self) -> None:
        """Branch 123->122: poll() returns non-None, so terminate() must not be called."""
        dead = self._make_tcpdump_proc(already_dead=True)
        _terminate([dead])
        self.assertFalse(dead._terminated)

    def test_alive_tcpdump_is_terminated(self) -> None:
        """Positive control: alive tcpdump is still terminated."""
        alive = self._make_tcpdump_proc(already_dead=False)
        _terminate([alive])
        self.assertTrue(alive._terminated)


# ── _prepare_secrets: unknown protocol produces no auth credential ─────────────
class PrepareSecretsUnknownProtoTests(unittest.TestCase):
    def test_unknown_proto_yields_no_password_or_uuid(self) -> None:
        """Branch 257->261: no if/elif matches, so secrets has no auth keys."""
        with tempfile.TemporaryDirectory() as tmpdir:
            secrets = _prepare_secrets({"type": "wireguard"}, Path(tmpdir))
        self.assertNotIn("password", secrets)
        self.assertNotIn("uuid", secrets)

    def test_unknown_proto_with_tls_still_generates_cert(self) -> None:
        """Unknown proto + TLS: cert is still generated even without an auth credential."""
        from unittest.mock import patch
        inbound = {"type": "wireguard", "tls": {"enabled": True, "server_name": "x.test"}}
        fake_openssl = types.SimpleNamespace(returncode=0, stdout="", stderr="")
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("subprocess.run", return_value=fake_openssl):
                secrets = _prepare_secrets(inbound, Path(tmpdir))
        self.assertIn("cert_path", secrets)
        self.assertNotIn("password", secrets)
        self.assertNotIn("uuid", secrets)


if __name__ == "__main__":
    unittest.main()

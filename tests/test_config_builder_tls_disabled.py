"""Tests for config_builder branches when tls block is present but enabled=False.

Covers branches not exercised by other test files:

1. _inject_server_tls early-return when tls.enabled=False:
   The inbound tls block is left unchanged (not overwritten with cert/key paths).

2. build_client_config produces no tls block in the outbound when the inbound
   tls.enabled is False — even though a tls dict exists on the inbound.

3. build_client_config with no "transport" key: no transport field appears in
   the client outbound (transport-absent branch).

4. _vless_inject when the inbound carries no "users" key at all:
   the or [{}] default is used and no flow is inserted in the result.
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from proto.composer.config_builder import build_client_config, build_server_config
from proto.composer.settings import SERVER_PORT


# ── helpers ────────────────────────────────────────────────────────────────────

def _trojan_tls_disabled_inbound() -> dict:
    """Trojan inbound where tls dict is present but enabled=False."""
    return {
        "type": "trojan",
        "tag": "trojan-tcp-notls",
        "listen": "::",
        "listen_port": 443,
        "users": [{"password": "placeholder"}],
        "tls": {
            "enabled": False,
            "server_name": "vpn.example.com",
        },
    }


def _trojan_no_transport_inbound() -> dict:
    """Trojan inbound with TLS but no transport key."""
    return {
        "type": "trojan",
        "tag": "trojan-tcp-tls",
        "listen": "::",
        "listen_port": 443,
        "users": [{"password": "placeholder"}],
        "tls": {
            "enabled": True,
            "server_name": "vpn.example.com",
            "certificate_path": "/tmp/cert.pem",
            "key_path": "/tmp/key.pem",
        },
    }


def _vless_no_users_inbound() -> dict:
    """VLESS inbound with no users key at all (tests the or [{}] default branch)."""
    return {
        "type": "vless",
        "tag": "vless-no-users",
    }


def _secrets_plain() -> dict:
    return {
        "password": "pw",
        "cert_path": "/tmp/cert.pem",
        "key_path": "/tmp/key.pem",
    }


def _secrets_tls() -> dict:
    return {
        "password": "pw",
        "cert_path": "/tmp/cert.pem",
        "key_path": "/tmp/key.pem",
    }


# ── 1 & 2. tls.enabled=False ──────────────────────────────────────────────────

class TlsDisabledTests(unittest.TestCase):
    """When the inbound carries tls.enabled=False, cert injection is skipped."""

    def test_server_inbound_tls_block_unchanged_when_disabled(self) -> None:
        """_inject_server_tls returns early; cert_path/key_path NOT overwritten."""
        cfg = build_server_config(_trojan_tls_disabled_inbound(), _secrets_plain())
        inb_tls = cfg["inbounds"][0]["tls"]
        # enabled remains False; cert/key fields must NOT be injected
        self.assertFalse(inb_tls["enabled"])
        self.assertNotIn("certificate_path", inb_tls)
        self.assertNotIn("key_path", inb_tls)

    def test_client_outbound_has_no_tls_when_inbound_tls_disabled(self) -> None:
        """build_client_config must not add a tls block when inbound tls.enabled=False."""
        cfg = build_client_config(_trojan_tls_disabled_inbound(), _secrets_plain())
        out = cfg["outbounds"][0]
        self.assertNotIn("tls", out)

    def test_server_listen_port_still_overridden_when_tls_disabled(self) -> None:
        """SERVER_PORT override is protocol-level, independent of TLS status."""
        cfg = build_server_config(_trojan_tls_disabled_inbound(), _secrets_plain())
        self.assertEqual(cfg["inbounds"][0]["listen_port"], SERVER_PORT)


# ── 3. no transport key ───────────────────────────────────────────────────────

class NoTransportTests(unittest.TestCase):
    """When the inbound has no 'transport' key, no transport appears in the outbound."""

    def test_client_outbound_has_no_transport_when_absent_from_inbound(self) -> None:
        cfg = build_client_config(_trojan_no_transport_inbound(), _secrets_tls())
        out = cfg["outbounds"][0]
        self.assertNotIn("transport", out)

    def test_server_inbound_has_no_transport_when_absent(self) -> None:
        cfg = build_server_config(_trojan_no_transport_inbound(), _secrets_tls())
        inb = cfg["inbounds"][0]
        self.assertNotIn("transport", inb)


# ── 4. _vless_inject with no users key ────────────────────────────────────────

class VlessNoUsersKeyTests(unittest.TestCase):
    """_vless_inject must handle a missing 'users' key via the or [{}] default."""

    def test_vless_server_injects_uuid_when_users_key_absent(self) -> None:
        inbound = _vless_no_users_inbound()
        secrets = {"uuid": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"}
        cfg = build_server_config(inbound, secrets)
        users = cfg["inbounds"][0]["users"]
        self.assertEqual(len(users), 1)
        self.assertEqual(users[0]["uuid"], "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
        # No flow was on the inbound so none should appear in output
        self.assertNotIn("flow", users[0])

    def test_vless_client_outbound_has_no_flow_when_users_key_absent(self) -> None:
        inbound = _vless_no_users_inbound()
        secrets = {"uuid": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"}
        cfg = build_client_config(inbound, secrets)
        out = cfg["outbounds"][0]
        self.assertEqual(out["uuid"], "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
        self.assertNotIn("flow", out)


# ── 5. _prepare_secrets skips cert generation when tls.enabled=False ──────────

class PrepareSecretsTlsDisabledTests(unittest.TestCase):
    """_prepare_secrets must not call openssl when tls.enabled=False."""

    def test_no_cert_fields_when_tls_enabled_false(self) -> None:
        from proto.composer.runner import _prepare_secrets
        inbound = {
            "type": "trojan",
            "tls": {"enabled": False},
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            secrets = _prepare_secrets(inbound, Path(tmpdir))
        self.assertIn("password", secrets)
        self.assertNotIn("cert_path", secrets)
        self.assertNotIn("key_path", secrets)
        self.assertNotIn("reality_priv", secrets)
        self.assertNotIn("ech_key_lines", secrets)


if __name__ == "__main__":
    unittest.main()

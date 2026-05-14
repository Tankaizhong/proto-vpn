"""Cover fallback defaults when short_id / server_name are absent from secrets or TLS config."""
from __future__ import annotations

import unittest

from proto.composer.config_builder import build_client_config, build_server_config


def _vless_reality_inbound(*, include_server_name: bool = True) -> dict:
    inb: dict = {
        "type": "vless",
        "tag": "vless-tcp-reality",
        "users": [{"uuid": "00000000-0000-0000-0000-000000000000"}],
        "tls": {
            "enabled": True,
            "reality": {
                "enabled": True,
                "handshake": {"server": "www.microsoft.com", "server_port": 443},
                "private_key": "REPLACE-REALITY-PRIV",
                "short_id": ["REPLACE-HEX"],
            },
        },
    }
    if include_server_name:
        inb["tls"]["server_name"] = "www.microsoft.com"
    return inb


def _secrets_without_short_id() -> dict:
    return {
        "uuid": "00000000-0000-0000-0000-000000000000",
        "reality_priv": "priv-key-placeholder",
        "reality_pub": "pub-key-placeholder",
        # intentionally omit "short_id" to exercise the .get() fallback
    }


def _secrets_with_short_id() -> dict:
    return {**_secrets_without_short_id(), "short_id": "aabbccdd11223344"}


class RealityShortIdDefaultTests(unittest.TestCase):
    def test_server_config_short_id_fallback_when_absent(self) -> None:
        """_inject_server_tls uses '0123456789abcdef' when secrets has no short_id."""
        cfg = build_server_config(_vless_reality_inbound(), _secrets_without_short_id())
        short_ids = cfg["inbounds"][0]["tls"]["reality"]["short_id"]
        self.assertEqual(short_ids, ["0123456789abcdef"])

    def test_server_config_short_id_from_secrets_when_present(self) -> None:
        cfg = build_server_config(_vless_reality_inbound(), _secrets_with_short_id())
        short_ids = cfg["inbounds"][0]["tls"]["reality"]["short_id"]
        self.assertEqual(short_ids, ["aabbccdd11223344"])

    def test_client_config_short_id_fallback_when_absent(self) -> None:
        """build_client_config reality block uses '0123456789abcdef' when secrets has no short_id."""
        cfg = build_client_config(_vless_reality_inbound(), _secrets_without_short_id())
        short_id = cfg["outbounds"][0]["tls"]["reality"]["short_id"]
        self.assertEqual(short_id, "0123456789abcdef")

    def test_client_config_short_id_from_secrets_when_present(self) -> None:
        cfg = build_client_config(_vless_reality_inbound(), _secrets_with_short_id())
        short_id = cfg["outbounds"][0]["tls"]["reality"]["short_id"]
        self.assertEqual(short_id, "aabbccdd11223344")


class ClientTlsServerNameDefaultTests(unittest.TestCase):
    def test_client_tls_server_name_fallback_when_absent(self) -> None:
        """build_client_config uses 'test.local' when server_name is absent from TLS config."""
        cfg = build_client_config(
            _vless_reality_inbound(include_server_name=False),
            _secrets_with_short_id(),
        )
        sn = cfg["outbounds"][0]["tls"]["server_name"]
        self.assertEqual(sn, "test.local")

    def test_client_tls_server_name_taken_from_inbound_when_present(self) -> None:
        cfg = build_client_config(
            _vless_reality_inbound(include_server_name=True),
            _secrets_with_short_id(),
        )
        sn = cfg["outbounds"][0]["tls"]["server_name"]
        self.assertEqual(sn, "www.microsoft.com")


if __name__ == "__main__":
    unittest.main()

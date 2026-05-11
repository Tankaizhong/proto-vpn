"""Verify that user-supplied WS transport path passes through to server/client JSON verbatim."""
from __future__ import annotations

import unittest

from proto.composer.config_builder import build_client_config, build_server_config


def _trojan_ws_inbound(path: str) -> dict:
    return {
        "type": "trojan",
        "tag": "trojan-ws",
        "users": [{"password": "placeholder"}],
        "tls": {
            "enabled": True,
            "server_name": "vpn.example.com",
            "certificate_path": "/tmp/cert.pem",
            "key_path": "/tmp/key.pem",
        },
        "transport": {
            "type": "ws",
            "path": path,
        },
    }


def _secrets() -> dict:
    return {
        "password": "pw",
        "cert_path": "/tmp/cert.pem",
        "key_path": "/tmp/key.pem",
    }


class WsPathTests(unittest.TestCase):
    def test_custom_ws_path_preserved_in_server_config(self) -> None:
        cfg = build_server_config(_trojan_ws_inbound("/custom-path"), _secrets())
        transport = cfg["inbounds"][0]["transport"]
        self.assertEqual(transport["path"], "/custom-path")

    def test_custom_ws_path_mirrored_to_client_config(self) -> None:
        cfg = build_client_config(_trojan_ws_inbound("/custom-path"), _secrets())
        transport = cfg["outbounds"][0]["transport"]
        self.assertEqual(transport["path"], "/custom-path")

    def test_default_ws_path_ray(self) -> None:
        cfg = build_server_config(_trojan_ws_inbound("/ray"), _secrets())
        transport = cfg["inbounds"][0]["transport"]
        self.assertEqual(transport["path"], "/ray")


if __name__ == "__main__":
    unittest.main()

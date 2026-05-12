"""Verify that user-supplied CDN Host header passes through to server/client JSON verbatim."""
from __future__ import annotations

import unittest

from proto.composer.config_builder import build_client_config, build_server_config


def _trojan_ws_cdn_inbound(cdn_host: str) -> dict:
    return {
        "type": "trojan",
        "tag": "trojan-ws-cdn",
        "users": [{"password": "placeholder"}],
        "tls": {
            "enabled": True,
            "server_name": "vpn.example.com",
            "certificate_path": "/tmp/cert.pem",
            "key_path": "/tmp/key.pem",
        },
        "transport": {
            "type": "ws",
            "path": "/ray",
            "headers": {"Host": cdn_host},
        },
    }


def _secrets() -> dict:
    return {
        "password": "pw",
        "cert_path": "/tmp/cert.pem",
        "key_path": "/tmp/key.pem",
    }


class CdnHostTests(unittest.TestCase):
    def test_custom_cdn_host_preserved_in_server_config(self) -> None:
        cfg = build_server_config(_trojan_ws_cdn_inbound("my.cdn.example.com"), _secrets())
        headers = cfg["inbounds"][0]["transport"]["headers"]
        self.assertEqual(headers["Host"], "my.cdn.example.com")

    def test_custom_cdn_host_mirrored_to_client_config(self) -> None:
        cfg = build_client_config(_trojan_ws_cdn_inbound("my.cdn.example.com"), _secrets())
        headers = cfg["outbounds"][0]["transport"]["headers"]
        self.assertEqual(headers["Host"], "my.cdn.example.com")

    def test_default_cdn_host(self) -> None:
        cfg = build_server_config(_trojan_ws_cdn_inbound("cdn.example.com"), _secrets())
        headers = cfg["inbounds"][0]["transport"]["headers"]
        self.assertEqual(headers["Host"], "cdn.example.com")


if __name__ == "__main__":
    unittest.main()

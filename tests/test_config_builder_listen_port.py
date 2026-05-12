"""Verify listen_port contract: backend always enforces SERVER_PORT regardless of frontend value."""
import unittest

from proto.composer.config_builder import build_client_config, build_server_config
from proto.composer.settings import SERVER_PORT


def _trojan_inbound(listen_port: int) -> dict:
    return {
        "type": "trojan",
        "tag": "trojan-tcp-tls",
        "listen": "::",
        "listen_port": listen_port,
        "users": [{"password": "placeholder"}],
        "tls": {
            "enabled": True,
            "server_name": "vpn.example.com",
            "certificate_path": "/tmp/cert.pem",
            "key_path": "/tmp/key.pem",
        },
    }


_SECRETS = {
    "password": "pw",
    "cert_path": "/tmp/cert.pem",
    "key_path": "/tmp/key.pem",
}


class ListenPortTests(unittest.TestCase):
    def test_server_config_enforces_server_port_ignoring_frontend_value(self) -> None:
        # Frontend may pass any display port; runner must always override with SERVER_PORT.
        cfg = build_server_config(_trojan_inbound(9999), _SECRETS)
        self.assertEqual(cfg["inbounds"][0]["listen_port"], SERVER_PORT)

    def test_client_config_uses_server_port_for_outbound(self) -> None:
        cfg = build_client_config(_trojan_inbound(9999), _SECRETS)
        self.assertEqual(cfg["outbounds"][0]["server_port"], SERVER_PORT)


if __name__ == "__main__":
    unittest.main()

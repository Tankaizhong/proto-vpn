"""Tests: Hysteria2 obfs (salamander) password is preserved in server and client configs."""
import unittest

from proto.composer.config_builder import build_server_config, build_client_config
from proto.composer.settings import SERVER_PORT, SOCKS_PORT


_SECRETS = {
    "password":  "test-password-xyz",
    "cert_path": "/tmp/cert.pem",
    "key_path":  "/tmp/key.pem",
}

_INBOUND_WITH_OBFS = {
    "type": "hysteria2",
    "tag":  "hy2-obfs-test",
    "listen": "::",
    "listen_port": 443,
    "users": [{"password": "REPLACE"}],
    "tls": {
        "enabled": True,
        "server_name": "vpn.example.com",
        "certificate_path": "/tmp/cert.pem",
        "key_path": "/tmp/key.pem",
    },
    "obfs": {
        "type": "salamander",
        "password": "my-obfs-secret",
    },
}

_INBOUND_NO_OBFS = {
    "type": "hysteria2",
    "tag":  "hy2-plain",
    "listen": "::",
    "listen_port": 443,
    "users": [{"password": "REPLACE"}],
    "tls": {
        "enabled": True,
        "server_name": "vpn.example.com",
        "certificate_path": "/tmp/cert.pem",
        "key_path": "/tmp/key.pem",
    },
}


class Hy2ObfsTests(unittest.TestCase):

    def test_server_config_preserves_obfs(self):
        cfg = build_server_config(_INBOUND_WITH_OBFS, _SECRETS)
        inb = cfg["inbounds"][0]
        self.assertIn("obfs", inb)
        self.assertEqual(inb["obfs"]["type"], "salamander")
        self.assertEqual(inb["obfs"]["password"], "my-obfs-secret")

    def test_client_config_mirrors_obfs(self):
        cfg = build_client_config(_INBOUND_WITH_OBFS, _SECRETS)
        out = cfg["outbounds"][0]
        self.assertEqual(out["type"], "hysteria2")
        self.assertIn("obfs", out)
        self.assertEqual(out["obfs"]["type"], "salamander")
        self.assertEqual(out["obfs"]["password"], "my-obfs-secret")

    def test_no_obfs_when_field_absent(self):
        srv = build_server_config(_INBOUND_NO_OBFS, _SECRETS)
        cli = build_client_config(_INBOUND_NO_OBFS, _SECRETS)
        self.assertNotIn("obfs", srv["inbounds"][0])
        self.assertNotIn("obfs", cli["outbounds"][0])


if __name__ == "__main__":
    unittest.main()

"""Tests for previously uncovered branches in config_builder:
  - gen_* utility functions (gen_run_id, gen_password, gen_short_secret, gen_uuid, gen_short_id)
  - shadowsocks build_server_config / build_client_config paths (_ss_inject, _ss_outbound)
  - vmess build_server_config path (_vmess_inject)
  - _inject_server_tls early-return when TLS is absent
"""
import base64
import re
import unittest
import uuid as _uuid_mod

from proto.composer.config_builder import (
    build_client_config,
    build_server_config,
    gen_password,
    gen_run_id,
    gen_short_id,
    gen_short_secret,
    gen_uuid,
)
from proto.composer.settings import SERVER_PORT, SOCKS_PORT


_SS_SECRETS = {"password": "dGVzdHBhc3N3b3JkdGVzdHBhc3N3b3JkdGVzdHBhc3M="}

_SS_INBOUND = {
    "type": "shadowsocks",
    "tag": "ss-test",
    "method": "2022-blake3-aes-256-gcm",
    "listen": "::",
    "listen_port": 443,
    "password": "REPLACE",
}

_VMESS_SECRETS = {
    "uuid": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
    "cert_path": "/tmp/cert.pem",
    "key_path": "/tmp/key.pem",
}

_VMESS_INBOUND = {
    "type": "vmess",
    "tag": "vmess-test",
    "listen": "::",
    "listen_port": 443,
    "users": [{"uuid": "REPLACE", "alterId": 0}],
    "tls": {
        "enabled": True,
        "server_name": "vpn.example.com",
        "certificate_path": "/tmp/cert.pem",
        "key_path": "/tmp/key.pem",
    },
}


class GenUtilityTests(unittest.TestCase):

    def test_gen_run_id_format(self):
        run_id = gen_run_id()
        self.assertRegex(run_id, r"^\d{8}-\d{6}-[0-9a-f]{4}$")

    def test_gen_password_decodes_to_32_bytes(self):
        pw = gen_password()
        decoded = base64.b64decode(pw)
        self.assertEqual(len(decoded), 32)

    def test_gen_short_secret_is_24_hex_chars(self):
        s = gen_short_secret()
        self.assertRegex(s, r"^[0-9a-f]{24}$")

    def test_gen_uuid_is_valid_uuid(self):
        u = gen_uuid()
        parsed = _uuid_mod.UUID(u)
        self.assertEqual(str(parsed), u)

    def test_gen_short_id_is_16_hex_chars(self):
        sid = gen_short_id()
        self.assertRegex(sid, r"^[0-9a-f]{16}$")


class ShadowsocksConfigTests(unittest.TestCase):

    def test_server_config_injects_ss_password(self):
        cfg = build_server_config(_SS_INBOUND, _SS_SECRETS)
        inb = cfg["inbounds"][0]
        self.assertEqual(inb["type"], "shadowsocks")
        self.assertEqual(inb["password"], _SS_SECRETS["password"])
        self.assertEqual(inb["listen"], "127.0.0.1")
        self.assertEqual(inb["listen_port"], SERVER_PORT)

    def test_client_config_outbound_mirrors_method_and_password(self):
        cfg = build_client_config(_SS_INBOUND, _SS_SECRETS)
        out = cfg["outbounds"][0]
        self.assertEqual(out["type"], "shadowsocks")
        self.assertEqual(out["password"], _SS_SECRETS["password"])
        self.assertEqual(out["method"], "2022-blake3-aes-256-gcm")
        self.assertEqual(out["server_port"], SERVER_PORT)

    def test_server_config_without_tls_has_no_tls_block(self):
        """_inject_server_tls returns early when inbound has no tls key."""
        cfg = build_server_config(_SS_INBOUND, _SS_SECRETS)
        self.assertNotIn("tls", cfg["inbounds"][0])


class VmessServerConfigTests(unittest.TestCase):

    def test_server_config_injects_vmess_uuid_and_alter_id(self):
        cfg = build_server_config(_VMESS_INBOUND, _VMESS_SECRETS)
        inb = cfg["inbounds"][0]
        self.assertEqual(inb["type"], "vmess")
        users = inb["users"]
        self.assertEqual(len(users), 1)
        self.assertEqual(users[0]["uuid"], _VMESS_SECRETS["uuid"])
        self.assertEqual(users[0]["alterId"], 0)


if __name__ == "__main__":
    unittest.main()

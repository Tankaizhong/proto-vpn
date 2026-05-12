"""补全 config_builder 中此前未被测试覆盖的代码分支。

覆盖目标（均为纯函数，无 subprocess / 文件 IO）：
    1. vless flow 字段：_vless_inject 保留 flow；_vless_outbound 镜像 flow。
    2. multiplex 剥离：build_server_config 对 hysteria2（非 MULTIPLEX_PROTOS）
       剥掉前端传入的 multiplex 字段。
    3. multiplex 镜像：build_client_config 对 vmess（MULTIPLEX_PROTOS）把
       inbound.multiplex 镜像到 client outbound，并强制 protocol="smux"。
    4. utls 镜像：build_client_config 把 inbound.tls.utls 镜像到 client TLS。
    5. 不支持的协议：build_server_config / build_client_config 抛 ValueError。
"""
from __future__ import annotations

import unittest

from proto.composer.config_builder import build_client_config, build_server_config


# ── 公共 secrets 工厂 ───────────────────────────────────────────────────
def _tls_secrets() -> dict:
    return {
        "uuid": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        "cert_path": "/tmp/cert.pem",
        "key_path": "/tmp/key.pem",
    }


def _hy2_secrets() -> dict:
    return {"password": "s3cr3t"}


# ── 1. vless flow 字段透传 ──────────────────────────────────────────────
def _vless_flow_inbound() -> dict:
    return {
        "type": "vless",
        "tag": "vless-reality-flow",
        "users": [{"uuid": "placeholder", "flow": "xtls-rprx-vision"}],
        "tls": {
            "enabled": True,
            "reality": {
                "enabled": True,
                "handshake": {"server": "www.microsoft.com", "server_port": 443},
                "private_key": "FAKE_PRIV",
                "public_key": "FAKE_PUB",
                "short_id": ["aabbccdd11223344"],
            },
        },
    }


def _reality_secrets() -> dict:
    return {
        "uuid": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        "reality_priv": "FAKE_PRIV",
        "reality_pub": "FAKE_PUB",
        "short_id": "aabbccdd11223344",
    }


class VlessFlowTests(unittest.TestCase):
    def test_server_inbound_preserves_flow(self) -> None:
        cfg = build_server_config(_vless_flow_inbound(), _reality_secrets())
        user = cfg["inbounds"][0]["users"][0]
        self.assertEqual(user.get("flow"), "xtls-rprx-vision")

    def test_client_outbound_mirrors_flow(self) -> None:
        cfg = build_client_config(_vless_flow_inbound(), _reality_secrets())
        out = cfg["outbounds"][0]
        self.assertEqual(out.get("flow"), "xtls-rprx-vision")

    def test_no_flow_when_absent(self) -> None:
        inbound = _vless_flow_inbound()
        inbound["users"][0].pop("flow")
        cfg = build_client_config(inbound, _reality_secrets())
        out = cfg["outbounds"][0]
        self.assertNotIn("flow", out)


# ── 2. multiplex 剥离（hy2 不支持） ─────────────────────────────────────
def _hy2_with_multiplex_inbound() -> dict:
    return {
        "type": "hysteria2",
        "tag": "hy2-test",
        "users": [{"password": "placeholder"}],
        "multiplex": {"enabled": True, "max_streams": 4},
        "tls": {
            "enabled": True,
            "server_name": "vpn.example.com",
            "certificate_path": "/tmp/cert.pem",
            "key_path": "/tmp/key.pem",
        },
    }


class MultiplexStripTests(unittest.TestCase):
    def test_multiplex_stripped_from_hy2_server_config(self) -> None:
        inbound = _hy2_with_multiplex_inbound()
        secrets = {"password": "s3cr3t", "cert_path": "/tmp/cert.pem", "key_path": "/tmp/key.pem"}
        cfg = build_server_config(inbound, secrets)
        self.assertNotIn("multiplex", cfg["inbounds"][0])

    def test_multiplex_absent_from_hy2_client_outbound(self) -> None:
        inbound = _hy2_with_multiplex_inbound()
        secrets = {"password": "s3cr3t", "cert_path": "/tmp/cert.pem", "key_path": "/tmp/key.pem"}
        cfg = build_client_config(inbound, secrets)
        self.assertNotIn("multiplex", cfg["outbounds"][0])


# ── 3. multiplex 镜像（vmess） ───────────────────────────────────────────
def _vmess_with_multiplex_inbound() -> dict:
    return {
        "type": "vmess",
        "tag": "vmess-mux",
        "users": [{"uuid": "placeholder", "alterId": 0}],
        "multiplex": {"enabled": True, "max_streams": 8, "protocol": "h2mux"},
        "tls": {
            "enabled": True,
            "server_name": "vpn.example.com",
            "certificate_path": "/tmp/cert.pem",
            "key_path": "/tmp/key.pem",
        },
    }


class MultiplexMirrorTests(unittest.TestCase):
    def test_multiplex_mirrored_to_vmess_client_outbound(self) -> None:
        secrets = {
            "uuid": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            "cert_path": "/tmp/cert.pem",
            "key_path": "/tmp/key.pem",
        }
        cfg = build_client_config(_vmess_with_multiplex_inbound(), secrets)
        out = cfg["outbounds"][0]
        self.assertIn("multiplex", out)
        self.assertTrue(out["multiplex"]["enabled"])
        self.assertEqual(out["multiplex"]["max_streams"], 8)
        # 不管前端传的是什么 protocol，客户端强制 smux
        self.assertEqual(out["multiplex"]["protocol"], "smux")


# ── 4. utls 镜像 ─────────────────────────────────────────────────────────
def _trojan_utls_inbound() -> dict:
    return {
        "type": "trojan",
        "tag": "trojan-utls",
        "users": [{"password": "placeholder"}],
        "tls": {
            "enabled": True,
            "server_name": "vpn.example.com",
            "certificate_path": "/tmp/cert.pem",
            "key_path": "/tmp/key.pem",
            "utls": {"enabled": True, "fingerprint": "chrome"},
        },
    }


class UtlsMirrorTests(unittest.TestCase):
    def test_utls_mirrored_to_client_tls(self) -> None:
        secrets = {
            "password": "pw",
            "cert_path": "/tmp/cert.pem",
            "key_path": "/tmp/key.pem",
        }
        cfg = build_client_config(_trojan_utls_inbound(), secrets)
        client_tls = cfg["outbounds"][0]["tls"]
        self.assertIn("utls", client_tls)
        self.assertEqual(client_tls["utls"]["fingerprint"], "chrome")

    def test_utls_stripped_from_server_inbound(self) -> None:
        """sing-box server-side TLS schema 不识别 utls；build_server_config 应将其移除。"""
        secrets = {
            "password": "pw",
            "cert_path": "/tmp/cert.pem",
            "key_path": "/tmp/key.pem",
        }
        cfg = build_server_config(_trojan_utls_inbound(), secrets)
        server_tls = cfg["inbounds"][0]["tls"]
        self.assertNotIn("utls", server_tls)


# ── 5. 不支持的协议抛 ValueError ─────────────────────────────────────────
class UnsupportedProtocolTests(unittest.TestCase):
    _BAD_INBOUND = {"type": "wireguard", "tag": "bad"}

    def test_build_server_config_raises_for_unknown_proto(self) -> None:
        with self.assertRaises(ValueError):
            build_server_config(self._BAD_INBOUND, {})

    def test_build_client_config_raises_for_unknown_proto(self) -> None:
        with self.assertRaises(ValueError):
            build_client_config(self._BAD_INBOUND, {})


if __name__ == "__main__":
    unittest.main()

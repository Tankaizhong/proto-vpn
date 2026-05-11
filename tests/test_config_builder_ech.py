"""ECH 注入的纯函数测试。

只覆盖 config_builder 中的两个新分支：
    1. _inject_server_tls 把 secrets["ech_key_lines"] 写入 server tls.ech.key，
       并清理掉任何被误带入的 config 字段。
    2. build_client_config 把 secrets["ech_config_lines"] 写入 client tls.ech.config。

不调用 sing-box / subprocess；ECH 密钥对生成本身在 runner._gen_ech_keypair，那条
路径需要真实 sing-box 才能跑，留给端到端测试。
"""
from __future__ import annotations

import unittest

from proto.composer.config_builder import build_client_config, build_server_config


_FAKE_KEY_LINES = [
    "-----BEGIN ECH KEYS-----",
    "FAKEKEYBASE64LINE1",
    "FAKEKEYBASE64LINE2",
    "-----END ECH KEYS-----",
]
_FAKE_CONFIG_LINES = [
    "-----BEGIN ECH CONFIGS-----",
    "FAKECONFIGBASE64LINE1",
    "-----END ECH CONFIGS-----",
]


def _trojan_with_ech_inbound() -> dict:
    return {
        "type": "trojan",
        "tag": "trojan-tcp-tls-ech",
        "users": [{"password": "placeholder"}],
        "tls": {
            "enabled": True,
            "server_name": "vpn.example.com",
            "certificate_path": "/will/be/overwritten",
            "key_path": "/will/be/overwritten",
            "ech": {
                "enabled": True,
                # 前端给的占位 key 必须被替换为真实 PEM 行
                "key": ["REPLACE-ECH-KEY-PEM"],
            },
        },
    }


def _secrets_with_ech() -> dict:
    return {
        "password": "pw",
        "cert_path": "/tmp/cert.pem",
        "key_path": "/tmp/key.pem",
        "ech_key_lines": list(_FAKE_KEY_LINES),
        "ech_config_lines": list(_FAKE_CONFIG_LINES),
    }


class EchInjectionTests(unittest.TestCase):
    def test_server_tls_ech_key_replaced_with_real_pem(self) -> None:
        cfg = build_server_config(_trojan_with_ech_inbound(), _secrets_with_ech())
        tls = cfg["inbounds"][0]["tls"]
        self.assertIn("ech", tls)
        self.assertTrue(tls["ech"]["enabled"])
        self.assertEqual(tls["ech"]["key"], _FAKE_KEY_LINES)
        # server schema 不接受 config / config_path，若误传也应被清掉
        self.assertNotIn("config", tls["ech"])
        self.assertNotIn("config_path", tls["ech"])

    def test_server_tls_ech_stripped_when_config_leaked_in(self) -> None:
        inbound = _trojan_with_ech_inbound()
        # 模拟前端误把 config 字段带过来
        inbound["tls"]["ech"]["config"] = ["leaked"]
        inbound["tls"]["ech"]["config_path"] = "/leaked"
        cfg = build_server_config(inbound, _secrets_with_ech())
        ech = cfg["inbounds"][0]["tls"]["ech"]
        self.assertNotIn("config", ech)
        self.assertNotIn("config_path", ech)

    def test_client_tls_ech_config_mirrored_from_secrets(self) -> None:
        cfg = build_client_config(_trojan_with_ech_inbound(), _secrets_with_ech())
        out_tls = cfg["outbounds"][0]["tls"]
        self.assertIn("ech", out_tls)
        self.assertTrue(out_tls["ech"]["enabled"])
        self.assertEqual(out_tls["ech"]["config"], _FAKE_CONFIG_LINES)
        # 客户端用 ECHConfigList，绝不能泄露 server 的私钥
        self.assertNotIn("key", out_tls["ech"])

    def test_no_ech_block_when_tls_has_no_ech(self) -> None:
        inbound = _trojan_with_ech_inbound()
        inbound["tls"].pop("ech")
        secrets = _secrets_with_ech()
        # 没启用 ECH 时，secrets 里的 ech_* 字段都不应被使用
        server = build_server_config(inbound, secrets)
        client = build_client_config(inbound, secrets)
        self.assertNotIn("ech", server["inbounds"][0]["tls"])
        self.assertNotIn("ech", client["outbounds"][0]["tls"])

    def test_ech_disabled_flag_is_ignored(self) -> None:
        inbound = _trojan_with_ech_inbound()
        inbound["tls"]["ech"]["enabled"] = False
        # enabled=False 时不需要 secrets 里的 ech 行，调用应不抛 KeyError
        secrets = {
            "password": "pw",
            "cert_path": "/tmp/cert.pem",
            "key_path": "/tmp/key.pem",
        }
        server = build_server_config(inbound, secrets)
        client = build_client_config(inbound, secrets)
        # ech 块本身可以保留（用户在配置里写了它），但 key 不应被替换为真实 PEM
        # 也不应在客户端被镜像（镜像只发生在 enabled=True 时）
        self.assertNotIn("ech", client["outbounds"][0]["tls"])
        server_ech = server["inbounds"][0]["tls"].get("ech")
        if server_ech is not None:
            self.assertFalse(server_ech.get("enabled", False))


if __name__ == "__main__":
    unittest.main()

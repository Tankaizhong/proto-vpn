"""Verify that user-supplied gRPC service_name passes through to server/client JSON verbatim."""
from __future__ import annotations

import unittest

from proto.composer.config_builder import build_client_config, build_server_config


def _vless_grpc_inbound(service_name: str) -> dict:
    return {
        "type": "vless",
        "tag": "vless-grpc",
        "users": [{"uuid": "00000000-0000-0000-0000-000000000000"}],
        "tls": {
            "enabled": True,
            "server_name": "vpn.example.com",
            "certificate_path": "/tmp/cert.pem",
            "key_path": "/tmp/key.pem",
        },
        "transport": {
            "type": "grpc",
            "service_name": service_name,
        },
    }


def _secrets() -> dict:
    return {
        "uuid": "00000000-0000-0000-0000-000000000000",
        "cert_path": "/tmp/cert.pem",
        "key_path": "/tmp/key.pem",
    }


class GrpcServiceNameTests(unittest.TestCase):
    def test_custom_service_name_preserved_in_server_config(self) -> None:
        cfg = build_server_config(_vless_grpc_inbound("my-service"), _secrets())
        transport = cfg["inbounds"][0]["transport"]
        self.assertEqual(transport["service_name"], "my-service")

    def test_custom_service_name_mirrored_to_client_config(self) -> None:
        cfg = build_client_config(_vless_grpc_inbound("my-service"), _secrets())
        transport = cfg["outbounds"][0]["transport"]
        self.assertEqual(transport["service_name"], "my-service")

    def test_default_service_name_proto(self) -> None:
        cfg = build_server_config(_vless_grpc_inbound("proto"), _secrets())
        transport = cfg["inbounds"][0]["transport"]
        self.assertEqual(transport["service_name"], "proto")


if __name__ == "__main__":
    unittest.main()

"""把前端 inbound 字典渲染为 sing-box server/client 完整配置。

纯函数 + 系统熵源（secrets/time/uuid）。无 HTTP、无 subprocess、无文件 IO。
凭据/证书的实际生成由 runner.py 完成（subprocess 涉及处），通过
`secrets` 参数传入。本模块只做模板填充与 dispatch。

`secrets` 字典字段（按协议/TLS 模式可选）:
    password       : str  (ss2022 / trojan / hy2)
    uuid           : str  (vless / vmess)
    reality_priv   : str  (vless + reality)
    reality_pub    : str  (vless + reality)
    short_id       : str  (reality)
    cert_path      : str  (非 reality 的 TLS)
    key_path       : str  (非 reality 的 TLS)
"""
from __future__ import annotations

import base64
import secrets as _secrets
import time
import uuid

from .settings import SERVER_PORT, SOCKS_PORT


# ====================================================================
# 通用熵源
# ====================================================================
def gen_run_id() -> str:
    """20260506-013500-a1b2 形式，本地时间 + 4 位 hex 随机后缀。"""
    return time.strftime("%Y%m%d-%H%M%S") + "-" + _secrets.token_hex(2)


def gen_password() -> str:
    """32 字节 base64 —— 满足 2022-blake3-aes-256-gcm 要求。"""
    return base64.b64encode(_secrets.token_bytes(32)).decode()


def gen_short_secret() -> str:
    """24 字符 hex —— 用于 trojan / hy2 / vmess 等接受任意字符串密码的协议。"""
    return _secrets.token_hex(12)


def gen_uuid() -> str:
    """vless / vmess 的用户标识。"""
    return str(uuid.uuid4())


def gen_short_id() -> str:
    """Reality short_id —— 8 字节 hex。"""
    return _secrets.token_hex(8)


# ====================================================================
# 协议 → inbound 凭据注入器
# ====================================================================
def _ss_inject(inb: dict, secrets: dict) -> dict:
    inb["password"] = secrets["password"]
    return inb


def _trojan_inject(inb: dict, secrets: dict) -> dict:
    inb["users"] = [{"password": secrets["password"]}]
    return inb


def _hy2_inject(inb: dict, secrets: dict) -> dict:
    inb["users"] = [{"password": secrets["password"]}]
    return inb


def _vless_inject(inb: dict, secrets: dict) -> dict:
    user: dict = {"uuid": secrets["uuid"]}
    # 保留前端可能给出的 flow 字段（xtls-rprx-vision 等）
    existing = inb.get("users") or [{}]
    if existing[0].get("flow"):
        user["flow"] = existing[0]["flow"]
    inb["users"] = [user]
    return inb


def _vmess_inject(inb: dict, secrets: dict) -> dict:
    inb["users"] = [{"uuid": secrets["uuid"], "alterId": 0}]
    return inb


_INJECTORS = {
    "shadowsocks": _ss_inject,
    "trojan":      _trojan_inject,
    "hysteria2":   _hy2_inject,
    "vless":       _vless_inject,
    "vmess":       _vmess_inject,
}


# ====================================================================
# 协议 → outbound 字段构造器
# ====================================================================
def _ss_outbound(inb: dict, secrets: dict) -> dict:
    return {
        "method": inb.get("method", "2022-blake3-aes-256-gcm"),
        "password": secrets["password"],
    }


def _trojan_outbound(inb: dict, secrets: dict) -> dict:
    return {"password": secrets["password"]}


def _hy2_outbound(inb: dict, secrets: dict) -> dict:
    return {"password": secrets["password"]}


def _vless_outbound(inb: dict, secrets: dict) -> dict:
    out: dict = {"uuid": secrets["uuid"]}
    inbound_user = (inb.get("users") or [{}])[0]
    if inbound_user.get("flow"):
        out["flow"] = inbound_user["flow"]
    return out


def _vmess_outbound(inb: dict, secrets: dict) -> dict:
    return {"uuid": secrets["uuid"], "alterId": 0}


_OUTBOUNDS = {
    "shadowsocks": _ss_outbound,
    "trojan":      _trojan_outbound,
    "hysteria2":   _hy2_outbound,
    "vless":       _vless_outbound,
    "vmess":       _vmess_outbound,
}


# ====================================================================
# TLS / Reality / 证书的 server-side 注入
# ====================================================================
def _inject_server_tls(inb: dict, secrets: dict) -> None:
    tls = inb.get("tls")
    if not tls or not tls.get("enabled"):
        return
    if "reality" in tls:
        # Reality：替换 priv key + short_id 占位符
        tls["reality"]["private_key"] = secrets["reality_priv"]
        tls["reality"]["short_id"] = [secrets.get("short_id", "0123456789abcdef")]
        tls["reality"].pop("public_key", None)
    else:
        # 普通 TLS：覆盖 cert/key 路径为本次 run 自签出来的
        tls["certificate_path"] = secrets["cert_path"]
        tls["key_path"] = secrets["key_path"]


# ====================================================================
# 公开：build_server_config / build_client_config
# ====================================================================
def build_server_config(inbound: dict, secrets: dict) -> dict:
    """渲染服务端配置，强制 listen=127.0.0.1:SERVER_PORT。"""
    proto = inbound.get("type")
    if proto not in _INJECTORS:
        raise ValueError(f"unsupported protocol: {proto}")

    inb = dict(inbound)
    inb["listen"] = "127.0.0.1"
    inb["listen_port"] = SERVER_PORT
    inb = _INJECTORS[proto](inb, secrets)
    _inject_server_tls(inb, secrets)

    return {
        "log": {"level": "info", "timestamp": True},
        "inbounds": [inb],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"final": "direct"},
    }


def build_client_config(inbound: dict, secrets: dict) -> dict:
    """根据 inbound 镜像出对应的 outbound + 本地 SOCKS inbound。"""
    proto = inbound.get("type")
    if proto not in _OUTBOUNDS:
        raise ValueError(f"unsupported protocol: {proto}")

    out: dict = {
        "type": proto,
        "tag": "proxy",
        "server": "127.0.0.1",
        "server_port": SERVER_PORT,
        **_OUTBOUNDS[proto](inbound, secrets),
    }

    # 镜像 transport（ws / grpc / quic / mkcp）
    if "transport" in inbound:
        out["transport"] = dict(inbound["transport"])

    # 镜像 TLS
    src_tls = inbound.get("tls")
    if src_tls and src_tls.get("enabled"):
        client_tls: dict = {
            "enabled": True,
            "server_name": src_tls.get("server_name", "test.local"),
        }
        if "reality" in src_tls:
            client_tls["reality"] = {
                "enabled": True,
                "public_key": secrets["reality_pub"],
                "short_id": secrets.get("short_id", "0123456789abcdef"),
            }
        else:
            # 自签证书：客户端必须 insecure=true 才能握手
            client_tls["insecure"] = True
        if "utls" in src_tls:
            client_tls["utls"] = dict(src_tls["utls"])
        out["tls"] = client_tls

    # multiplex / padding
    if "multiplex" in inbound:
        out["multiplex"] = {**inbound["multiplex"], "protocol": "smux"}

    return {
        "log": {"level": "info", "timestamp": True},
        "inbounds": [{
            "type": "socks", "tag": "socks-in",
            "listen": "127.0.0.1", "listen_port": SOCKS_PORT,
        }],
        "outbounds": [out, {"type": "direct", "tag": "direct"}],
        "route": {"final": "proxy"},
    }

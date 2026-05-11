"""把前端 inbound 字典渲染为 sing-box server/client 完整配置。

纯函数 + 系统熵源（secrets/time/uuid）。无 HTTP、无 subprocess、无文件 IO。
凭据/证书的实际生成由 runner.py 完成（subprocess 涉及处），通过
`secrets` 参数传入。本模块只做模板填充与 dispatch。

`secrets` 字典字段（按协议/TLS 模式可选）:
    password         : str       (ss2022 / trojan / hy2)
    uuid             : str       (vless / vmess)
    reality_priv     : str       (vless + reality)
    reality_pub      : str       (vless + reality)
    short_id         : str       (reality)
    cert_path        : str       (非 reality 的 TLS)
    key_path         : str       (非 reality 的 TLS)
    ech_key_lines    : list[str] (启用 ECH 时的私钥 PEM 行；server 用)
    ech_config_lines : list[str] (启用 ECH 时的 ECHConfigList PEM 行；client 用)
"""
from __future__ import annotations

import base64
import copy
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
    # sing-box outbound 用 alter_id (snake_case) 与 inbound users[].alterId 不一致；
    # 现代 AEAD VMess 默认 alter_id=0，直接省略最稳。
    return {"uuid": secrets["uuid"]}


_OUTBOUNDS = {
    "shadowsocks": _ss_outbound,
    "trojan":      _trojan_outbound,
    "hysteria2":   _hy2_outbound,
    "vless":       _vless_outbound,
    "vmess":       _vmess_outbound,
}

# sing-box 在以下协议上支持 multiplex/smux 字段；其它（hysteria2 自带 QUIC stream
# 多路复用，naive 用 HTTP/2，等）解析时会报 unknown field "multiplex"。
_MULTIPLEX_PROTOS = frozenset({"shadowsocks", "trojan", "vless", "vmess"})


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
    # ECH：把前端占位的 ech.key 替换为本次 run 生成的真实 PEM 行
    if "ech" in tls and tls["ech"].get("enabled"):
        tls["ech"]["key"] = list(secrets["ech_key_lines"])
        # server 侧的 ech 块只接受 key / key_path，移除任何被误带入的 config 字段
        tls["ech"].pop("config", None)
        tls["ech"].pop("config_path", None)
    # sing-box server-side TLS schema 不识别 utls（仅 outbound 用）
    tls.pop("utls", None)


# ====================================================================
# 公开：build_server_config / build_client_config
# ====================================================================
def build_server_config(inbound: dict, secrets: dict) -> dict:
    """渲染服务端配置，强制 listen=127.0.0.1:SERVER_PORT。"""
    proto = inbound.get("type")
    if proto not in _INJECTORS:
        raise ValueError(f"unsupported protocol: {proto}")

    # 深拷贝避免污染入参（_inject_server_tls 会就地修改子结构）
    inb = copy.deepcopy(inbound)
    inb["listen"] = "127.0.0.1"
    inb["listen_port"] = SERVER_PORT
    if proto not in _MULTIPLEX_PROTOS:
        inb.pop("multiplex", None)   # hy2 / 其它不支持 multiplex 的协议
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

    inbound = copy.deepcopy(inbound)  # 防止后续 dict(inbound["transport"]) 等浅引用污染
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
        # ECH：client 用 ECHConfigList（公开），与 server 的 key 是配对的
        if "ech" in src_tls and src_tls["ech"].get("enabled"):
            client_tls["ech"] = {
                "enabled": True,
                "config": list(secrets["ech_config_lines"]),
            }
        out["tls"] = client_tls

    # multiplex / padding（hy2 等不支持 mux 的协议跳过）
    if "multiplex" in inbound and proto in _MULTIPLEX_PROTOS:
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

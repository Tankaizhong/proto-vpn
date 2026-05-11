"""进程编排：tcpdump + sing-box server + sing-box client + 流量发生器。

routes.py / app.py 只调本模块的公开 API，不直接接触 subprocess、文件路径
或 pcap 抓包细节。所有外部命令（sing-box / tcpdump / curl / openssl）的
spawn 全部集中在这里。
"""
from __future__ import annotations

import asyncio
import json
import re
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

from .config_builder import (
    build_client_config,
    build_server_config,
    gen_password,
    gen_run_id,
    gen_short_id,
    gen_short_secret,
    gen_uuid,
)
from .settings import (
    DATA_DIR,
    SERVER_PORT,
    SOCKS_PORT,
    SUPPORTED_PROTOCOLS,
    TRAFFIC_INTERVAL_SEC,
    TRAFFIC_TARGET_URL,
)


# ---------- 错误 ----------
class RunnerError(Exception):
    """server.py / routes.py 把它翻译为 HTTPException."""

    def __init__(self, code: int, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


# ---------- 状态 ----------
@dataclass
class RunInfo:
    run_id: str
    started: float
    duration: int
    procs: list[subprocess.Popen] = field(default_factory=list)
    pcap_path: Path = Path()
    run_dir: Path = Path()
    log_dir: Path = Path()
    fingerprint: str = ""


_RUNS: dict[str, RunInfo] = {}


# ====================================================================
# 内部工具：sing-box / tcpdump / curl / openssl
# ====================================================================
def _check_singbox_config(path: Path) -> str | None:
    r = subprocess.run(
        ["sing-box", "check", "-c", str(path)],
        capture_output=True, text=True,
    )
    return None if r.returncode == 0 else (r.stderr or r.stdout)


_SAFE_NAME_RE = re.compile(r"[^a-z0-9._-]+")


def _pcap_filename(inbound: dict) -> str:
    """从 inbound 的 tag（或 type）派生 pcap 文件名，编码协议+混淆组合。

    例：tag="trojan-tcp-tls-utls" → "trojan-tcp-tls-utls.pcap"
        无 tag → 退化为 "{type}.pcap"
    只保留 [a-z0-9._-]，避免文件系统/URL 兼容问题。
    """
    raw = str(inbound.get("tag") or inbound.get("type") or "capture").strip().lower()
    safe = _SAFE_NAME_RE.sub("-", raw).strip("-.") or "capture"
    return f"{safe}.pcap"


def _is_tcpdump(p: subprocess.Popen) -> bool:
    args = p.args
    if isinstance(args, (list, tuple)) and args:
        return str(args[0]).endswith("tcpdump")
    return isinstance(args, str) and "tcpdump" in args


def _terminate(procs: list[subprocess.Popen]) -> None:
    """优雅关停：先停 traffic/client/server，最后单独停 tcpdump 并等它 flush。

    顺序很关键：tcpdump 必须在所有其他进程退出后才停，否则关停过程中产生的最后
    一批包会丢；tcpdump 收到 SIGTERM 后需要 ~1s 把 BPF buffer 抽干并写 pcap
    trailer，必须 wait 而不是固定 sleep —— 否则 capinfos 会报
    "appears to have been cut short in the middle of a packet"。
    """
    tcpdump_procs = [p for p in procs if _is_tcpdump(p)]
    others = [p for p in procs if not _is_tcpdump(p)]

    for p in reversed(others):
        if p.poll() is None:
            try:
                p.terminate()
            except Exception:
                pass
    for p in others:
        if p.poll() is None:
            try:
                p.wait(timeout=1.5)
            except subprocess.TimeoutExpired:
                try:
                    p.kill()
                except Exception:
                    pass

    for p in tcpdump_procs:
        if p.poll() is None:
            try:
                p.terminate()
            except Exception:
                pass
            try:
                p.wait(timeout=3.0)
            except subprocess.TimeoutExpired:
                try:
                    p.kill()
                except Exception:
                    pass


def _spawn_tcpdump(pcap: Path, log_fp) -> subprocess.Popen:
    # -U: packet-buffered，每个包立即写盘，避免 SIGTERM 后丢失尾部 buffer
    return subprocess.Popen(
        ["tcpdump", "-i", "lo", "-U", "-n", "-w", str(pcap), f"port {SERVER_PORT}"],
        stdout=log_fp, stderr=subprocess.STDOUT,
    )


def _spawn_singbox(cfg: Path, log_fp) -> subprocess.Popen:
    return subprocess.Popen(
        ["sing-box", "run", "-c", str(cfg)],
        stdout=log_fp, stderr=subprocess.STDOUT,
    )


def _spawn_traffic(log_fp) -> subprocess.Popen:
    cmd = (
        f"for i in $(seq 1 9999); do "
        f"curl -sS --max-time 5 --socks5-hostname 127.0.0.1:{SOCKS_PORT} "
        f"{TRAFFIC_TARGET_URL} -o /dev/null "
        f"-w '%{{http_code}} %{{size_download}}B %{{time_total}}s\\n' "
        f"|| echo 'curl-fail'; sleep {TRAFFIC_INTERVAL_SEC}; done"
    )
    return subprocess.Popen(
        ["bash", "-c", cmd],
        stdout=log_fp, stderr=subprocess.STDOUT,
    )


# ====================================================================
# 凭据 / 密钥 / 证书生成（subprocess 唯一入口）
# ====================================================================
def _gen_reality_keypair() -> tuple[str, str]:
    """调 `sing-box generate reality-keypair`，返回 (priv, pub)。"""
    r = subprocess.run(
        ["sing-box", "generate", "reality-keypair"],
        capture_output=True, text=True,
    )
    if r.returncode != 0:
        raise RunnerError(
            500, f"sing-box generate reality-keypair 失败: {r.stderr or r.stdout}"
        )
    priv = pub = ""
    for line in r.stdout.splitlines():
        if line.lower().startswith("privatekey:"):
            priv = line.split(":", 1)[1].strip()
        elif line.lower().startswith("publickey:"):
            pub = line.split(":", 1)[1].strip()
    if not priv or not pub:
        raise RunnerError(500, f"无法从 sing-box 输出解析 Reality 密钥: {r.stdout!r}")
    return priv, pub


def _gen_ech_keypair(server_name: str) -> tuple[list[str], list[str]]:
    """调 `sing-box generate ech-keypair <server_name>`，返回 (key_lines, config_lines)。

    输出有两段 PEM block：
        -----BEGIN ECH CONFIGS-----  ...  -----END ECH CONFIGS-----   # 客户端用
        -----BEGIN ECH KEYS-----     ...  -----END ECH KEYS-----      # 服务端用
    顺序不固定，按 marker 分桶解析；每段保留完整 BEGIN/END 行，便于直接放进
    sing-box 的 tls.ech.key / tls.ech.config 字符串数组。
    """
    r = subprocess.run(
        ["sing-box", "generate", "ech-keypair", server_name],
        capture_output=True, text=True,
    )
    if r.returncode != 0:
        raise RunnerError(
            500,
            f"sing-box generate ech-keypair 失败（需要 sing-box ≥ 1.8）: "
            f"{r.stderr or r.stdout}",
        )

    key_lines: list[str] = []
    config_lines: list[str] = []
    current: list[str] | None = None
    for raw in r.stdout.splitlines():
        line = raw.rstrip()
        if line.startswith("-----BEGIN ECH KEYS"):
            current = key_lines
        elif line.startswith("-----BEGIN ECH CONFIGS"):
            current = config_lines
        if current is not None:
            current.append(line)
        if line.startswith("-----END ECH"):
            current = None

    if not key_lines or not config_lines:
        raise RunnerError(500, f"无法从 sing-box 输出解析 ECH PEM block: {r.stdout!r}")
    return key_lines, config_lines


def _gen_self_signed_cert(run_dir: Path) -> tuple[Path, Path]:
    """openssl 现签 RSA 2048 自签证书，CN=test.local，1 天有效。"""
    cert = run_dir / "cert.pem"
    key = run_dir / "key.pem"
    r = subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", str(key), "-out", str(cert),
            "-days", "1", "-nodes",
            "-subj", "/CN=test.local",
        ],
        capture_output=True, text=True,
    )
    if r.returncode != 0:
        raise RunnerError(500, f"openssl 自签证书失败: {r.stderr or r.stdout}")
    return cert, key


def _prepare_secrets(inbound: dict, run_dir: Path) -> dict:
    """根据 inbound 的协议 + TLS 模式，生成本次 run 所需的全部凭据。"""
    proto = inbound["type"]
    secrets: dict = {}

    # 主鉴权凭据
    if proto == "shadowsocks":
        secrets["password"] = gen_password()
    elif proto in ("trojan", "hysteria2"):
        secrets["password"] = gen_short_secret()
    elif proto in ("vless", "vmess"):
        secrets["uuid"] = gen_uuid()

    # TLS / Reality
    tls_cfg = inbound.get("tls", {})
    if tls_cfg.get("enabled"):
        if "reality" in tls_cfg:
            priv, pub = _gen_reality_keypair()
            secrets["reality_priv"] = priv
            secrets["reality_pub"] = pub
            secrets["short_id"] = gen_short_id()
        else:
            cert, key = _gen_self_signed_cert(run_dir)
            secrets["cert_path"] = str(cert)
            secrets["key_path"] = str(key)
            # ECH 与 Reality 在 schema 上互斥（前端冲突规则已拦截），所以放在 else 分支里
            ech_cfg = tls_cfg.get("ech")
            if ech_cfg and ech_cfg.get("enabled"):
                server_name = tls_cfg.get("server_name") or "vpn.example.com"
                key_lines, config_lines = _gen_ech_keypair(server_name)
                secrets["ech_key_lines"] = key_lines
                secrets["ech_config_lines"] = config_lines
    return secrets


# ====================================================================
# 公开 API
# ====================================================================
async def start_run(inbound: dict, duration: int) -> dict:
    if _RUNS:
        raise RunnerError(409, "另一个实验正在运行，请先停止。")

    proto = inbound.get("type")
    if proto not in SUPPORTED_PROTOCOLS:
        raise RunnerError(
            400,
            f"不支持的协议: {proto}（白名单: {sorted(SUPPORTED_PROTOCOLS)}）",
        )

    run_id = gen_run_id()
    run_dir = DATA_DIR / run_id          # data/<id>/        ← 全产物根
    log_dir = run_dir / "logs"           # data/<id>/logs/   ← 4 个 .log
    run_dir.mkdir()
    log_dir.mkdir()

    secrets = _prepare_secrets(inbound, run_dir)
    server_cfg = build_server_config(inbound, secrets)
    client_cfg = build_client_config(inbound, secrets)
    server_path = run_dir / "server.json"
    client_path = run_dir / "client.json"
    server_path.write_text(json.dumps(server_cfg, indent=2))
    client_path.write_text(json.dumps(client_cfg, indent=2))

    if err := _check_singbox_config(server_path):
        raise RunnerError(400, f"server config invalid: {err}")
    if err := _check_singbox_config(client_path):
        raise RunnerError(400, f"client config invalid: {err}")

    pcap_path = run_dir / _pcap_filename(inbound)
    procs: list[subprocess.Popen] = []

    # 1) tcpdump 先起
    try:
        tcpdump = _spawn_tcpdump(pcap_path, (log_dir / "tcpdump.log").open("w"))
    except FileNotFoundError:
        raise RunnerError(500, "未找到 tcpdump，请先 apt install tcpdump")
    procs.append(tcpdump)
    await asyncio.sleep(0.4)
    if tcpdump.poll() is not None:
        _terminate(procs)
        raise RunnerError(
            500,
            "tcpdump 启动失败（可能权限不足）。请先运行: "
            "sudo setcap cap_net_raw,cap_net_admin+eip $(which tcpdump)",
        )

    # 2) 服务端
    server_proc = _spawn_singbox(server_path, (log_dir / "server.log").open("w"))
    procs.append(server_proc)
    await asyncio.sleep(0.6)
    if server_proc.poll() is not None:
        _terminate(procs)
        raise RunnerError(500, "sing-box server 启动失败，见 logs/server.log")

    # 3) 客户端
    client_proc = _spawn_singbox(client_path, (log_dir / "client.log").open("w"))
    procs.append(client_proc)
    await asyncio.sleep(0.6)
    if client_proc.poll() is not None:
        _terminate(procs)
        raise RunnerError(500, "sing-box client 启动失败，见 logs/client.log")

    # 4) 流量发生器
    traffic_proc = _spawn_traffic((log_dir / "traffic.log").open("w"))
    procs.append(traffic_proc)

    info = RunInfo(
        run_id=run_id,
        started=time.time(),
        duration=duration,
        procs=procs,
        pcap_path=pcap_path,
        run_dir=run_dir,
        log_dir=log_dir,
        fingerprint=inbound.get("tag", proto),
    )
    _RUNS[run_id] = info
    asyncio.create_task(_auto_stop(run_id, duration))

    return {
        "run_id": run_id,
        "status": "running",
        "duration": duration,
        "fingerprint": info.fingerprint,
        "pcap_url": f"/runs/{run_id}/pcap",
        "stop_url": f"/stop/{run_id}",
    }


async def stop_run(run_id: str, reason: str = "manual") -> dict:
    if run_id not in _RUNS:
        raise RunnerError(404, "run not found")
    info = _RUNS.pop(run_id)
    _terminate(info.procs)
    pcap_size = info.pcap_path.stat().st_size if info.pcap_path.exists() else 0
    return {
        "run_id": run_id,
        "status": "stopped",
        "reason": reason,
        "elapsed_sec": round(time.time() - info.started, 1),
        "pcap_url": f"/runs/{run_id}/pcap",
        "pcap_size_bytes": pcap_size,
        "fingerprint": info.fingerprint,
    }


def list_active() -> list[dict]:
    now = time.time()
    return [
        {
            "run_id": r.run_id,
            "fingerprint": r.fingerprint,
            "elapsed_sec": round(now - r.started, 1),
            "duration": r.duration,
        }
        for r in _RUNS.values()
    ]


async def shutdown_all() -> None:
    for rid in list(_RUNS.keys()):
        try:
            await stop_run(rid, reason="shutdown")
        except Exception:
            pass


async def _auto_stop(run_id: str, delay: int) -> None:
    await asyncio.sleep(delay)
    if run_id in _RUNS:
        try:
            await stop_run(run_id, reason="timeout")
        except Exception:
            pass

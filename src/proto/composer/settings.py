"""集中式常量与路径。

其它模块只从这里读取配置，便于改端口/路径时只动一处。
"""
from __future__ import annotations

from pathlib import Path

# ---------- 路径 ----------
# 锚点 = 项目根（src/proto/composer/settings.py → 上溯 4 层）
BASE_DIR: Path = Path(__file__).resolve().parents[3]
WEB_DIR: Path = BASE_DIR / "web"
VAR_DIR: Path = BASE_DIR / "var"
RUNS_DIR: Path = VAR_DIR / "runs"           # 每个 run 一个子目录，pcap/logs/configs 全在里面

# 副作用：保证运行时目录存在
for _d in (VAR_DIR, RUNS_DIR):
    _d.mkdir(exist_ok=True)

# ---------- 端口 (全部 loopback) ----------
SERVER_PORT: int = 8443   # sing-box 服务端 inbound
SOCKS_PORT: int = 1080    # sing-box 客户端 SOCKS inbound
HTTP_PORT: int = 8787     # 本后端 FastAPI

# ---------- 实验策略 ----------
SUPPORTED_PROTOCOLS: frozenset[str] = frozenset({
    "shadowsocks",   # ss2022 (BLAKE3 + AES-256-GCM)
    "trojan",        # password + TLS
    "hysteria2",     # UDP + TLS
    "vless",         # UUID, optional Reality
    "vmess",         # UUID + AEAD
})
DURATION_DEFAULT: int = 30
DURATION_MIN: int = 5
DURATION_MAX: int = 300

# ---------- 流量发生器 ----------
TRAFFIC_TARGET_URL: str = "https://example.com"
TRAFFIC_INTERVAL_SEC: float = 0.5

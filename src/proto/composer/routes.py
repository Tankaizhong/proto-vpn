"""HTTP 路由层。

只做协议适配——把 HTTP 请求翻译成 runner 调用，把 runner 异常翻译成 HTTPException。
所有业务逻辑在 runner.py / config_builder.py。
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse, RedirectResponse
from pydantic import BaseModel, Field

from . import runner
from .settings import (
    DURATION_DEFAULT,
    DURATION_MAX,
    DURATION_MIN,
    DATA_DIR,
)


# ---------- 请求模型 ----------
class RunRequest(BaseModel):
    inbound: dict
    duration: int = Field(
        default=DURATION_DEFAULT, ge=DURATION_MIN, le=DURATION_MAX,
    )


# ---------- 异常翻译 ----------
def _translate(err: runner.RunnerError) -> HTTPException:
    return HTTPException(err.code, err.message)


# ---------- 路由 ----------
router = APIRouter()


@router.get("/")
async def root():
    return RedirectResponse(url="/web/composer.html")


@router.get("/health")
async def health():
    return {"ok": True, "active_runs": len(runner.list_active())}


@router.post("/run")
async def post_run(req: RunRequest):
    try:
        return await runner.start_run(req.inbound, req.duration)
    except runner.RunnerError as e:
        raise _translate(e)


@router.post("/stop/{run_id}")
async def post_stop(run_id: str):
    try:
        return await runner.stop_run(run_id, reason="manual")
    except runner.RunnerError as e:
        raise _translate(e)


@router.get("/status")
async def get_status():
    pcaps = []
    for pcap in sorted(DATA_DIR.glob("*/*.pcap")):
        pcaps.append({
            "run_id": pcap.parent.name,
            "filename": pcap.name,
            "size_bytes": pcap.stat().st_size,
            "url": f"/runs/{pcap.parent.name}/pcap",
        })
    return {
        "active_runs": runner.list_active(),
        "pcaps": pcaps[-20:],
    }


@router.get("/runs/{run_id}/pcap")
async def get_pcap(run_id: str):
    # 防路径穿越：run_id 必须是 DATA_DIR 下的直接子目录
    # （data/<run_id>/，run_id 形如 YYYYMMDD-HHMMSS-XXXX）
    run_dir = (DATA_DIR / run_id).resolve()
    if not str(run_dir).startswith(str(DATA_DIR.resolve())):
        raise HTTPException(400, "invalid run_id")
    pcaps = sorted(run_dir.glob("*.pcap"))
    if not pcaps:
        raise HTTPException(404, "pcap not found")
    pcap = pcaps[0]
    return FileResponse(
        pcap,
        media_type="application/vnd.tcpdump.pcap",
        filename=pcap.name,
    )

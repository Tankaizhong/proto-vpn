"""项目入口：FastAPI 应用装配 + 启动。

只负责：app 实例 + 中间件 + 生命周期 + 路由注册 + 静态托管 + 启动。
路由实现在 src/proto/composer/routes.py，业务在 runner.py / config_builder.py。

启动:
    python3 app.py
    # 或 uvicorn app:app --reload
"""
from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from proto.composer import runner
from proto.composer.routes import router
from proto.composer.settings import HTTP_PORT, WEB_DIR


@asynccontextmanager
async def lifespan(_app: FastAPI):
    yield
    await runner.shutdown_all()


app = FastAPI(title="proto lab", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_methods=["*"], allow_headers=["*"],
)
app.include_router(router)
app.mount("/web", StaticFiles(directory=WEB_DIR, html=True), name="web")


def main() -> None:
    import uvicorn
    print(f"打开浏览器: http://127.0.0.1:{HTTP_PORT}/web/composer.html")
    uvicorn.run(app, host="127.0.0.1", port=HTTP_PORT)


if __name__ == "__main__":
    main()

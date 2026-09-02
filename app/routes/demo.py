from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates

router = APIRouter(tags=["demo"])

templates = Jinja2Templates(directory=str(Path(__file__).resolve().parents[1] / "templates"))


@router.get("/")
def home(request: Request):
    return templates.TemplateResponse(
        request,
        "index.html",
        {
            "title": "AgentCapture - 嵌入式蜜罐与 Agent 检测平台",
            "session_id": getattr(request.state, "session_id", "unknown"),
        },
    )


@router.get("/help")
def help_page(request: Request):
    return RedirectResponse(url="/admin/login", status_code=302)

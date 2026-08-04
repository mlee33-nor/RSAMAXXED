"""FastAPI local dashboard for broker automation."""
from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

from modules.outputs import get_events

app = FastAPI(title="Broker Dashboard")
templates = Jinja2Templates(directory=str(Path(__file__).resolve().parent / "templates"))


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    events = get_events()
    return templates.TemplateResponse("dashboard.html", {"request": request, "events": events})


@app.get("/api/events", response_class=JSONResponse)
async def api_events():
    return get_events()

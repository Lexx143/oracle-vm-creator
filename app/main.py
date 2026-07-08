"""Oracle VM Creator — веб-мастер получения бесплатной ARM VM в Oracle Cloud.

Поддерживает несколько параллельных пользователей: каждому выдаётся свой
токен-ссылка (ACCESS_TOKENS — список через запятую), у каждого токена
изолированная сессия со своими ключами и своей охотой.
"""

import logging
import os
import secrets
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

from . import oci_service, state

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

app = FastAPI(title="Oracle VM Creator", docs_url=None, redoc_url=None)

BASE = Path(__file__).parent
app.mount("/static", StaticFiles(directory=BASE / "static"), name="static")
templates = Jinja2Templates(directory=BASE / "templates")

COOKIE_NAME = "vmc_token"


def _load_tokens():
    raw = ",".join(filter(None, [os.environ.get("ACCESS_TOKENS", ""),
                                 os.environ.get("ACCESS_TOKEN", "")]))
    tokens = []
    for t in raw.split(","):
        t = t.strip()
        if t and t not in tokens:
            tokens.append(t)
    return tokens


TOKENS = _load_tokens()


def _find_token(supplied: str):
    match = None
    for t in TOKENS:
        # проверяем все токены, чтобы время ответа не зависело от места совпадения
        if secrets.compare_digest(supplied, t):
            match = t
    return match


def _supplied_token(request: Request) -> str:
    return request.query_params.get("t") or request.cookies.get(COOKIE_NAME) or ""


def current_session(request: Request) -> state.Session:
    token = _find_token(_supplied_token(request))
    if token is None:
        raise HTTPException(status_code=403, detail="Нет доступа")
    return state.for_token(token)


@app.on_event("startup")
def resume_background_work():
    if TOKENS:
        state.migrate_legacy(TOKENS[0])
    oci_service.resume_all()


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    token = _find_token(_supplied_token(request))
    if token is None:
        return HTMLResponse(
            "<h1 style='font-family:sans-serif'>403 — нужна персональная ссылка</h1>",
            status_code=403,
        )
    response = templates.TemplateResponse(request, "index.html")
    response.set_cookie(COOKIE_NAME, token, httponly=True,
                        max_age=60 * 60 * 24 * 90, samesite="lax")
    return response


@app.get("/api/session")
def get_session(sess: state.Session = Depends(current_session)):
    return sess.get()


@app.post("/api/registration_done")
def registration_done(sess: state.Session = Depends(current_session)):
    public_pem, fingerprint = oci_service.ensure_api_keypair(sess)
    return {"public_key_pem": public_pem, "fingerprint": fingerprint}


class ConfigSnippet(BaseModel):
    snippet: str = Field(min_length=10)


@app.post("/api/submit_config")
def submit_config(body: ConfigSnippet, sess: state.Session = Depends(current_session)):
    try:
        parsed = oci_service.parse_config_snippet(body.snippet)
        ads = oci_service.validate_credentials(sess, parsed)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
    return {"ok": True, "region": parsed["region"], "ads": ads}


@app.post("/api/setup")
def run_setup(sess: state.Session = Depends(current_session)):
    if not sess.get()["oci"]:
        raise HTTPException(status_code=409, detail="Сначала настройте API-ключ (шаг 2).")
    oci_service.run_setup_async(sess)
    return {"ok": True}


class HuntParams(BaseModel):
    display_name: str = Field(default="free-arm-vm", min_length=1, max_length=64)
    ocpus: int = Field(default=4, ge=1, le=4)
    memory_gb: int = Field(default=24, ge=6, le=24)


@app.post("/api/start_hunt")
def start_hunt(body: HuntParams, sess: state.Session = Depends(current_session)):
    st = sess.get()
    if not st["network"]:
        raise HTTPException(status_code=409, detail="Сначала выполните автонастройку (шаг 3).")
    if st["hunt"]["status"] in ("running", "provisioning"):
        return {"ok": True, "already": True}
    oci_service.start_hunt(sess, body.display_name.strip(), body.ocpus, body.memory_gb)
    return {"ok": True}


@app.post("/api/stop_hunt")
def stop_hunt(sess: state.Session = Depends(current_session)):
    oci_service.stop_hunt(sess)
    return {"ok": True}


@app.get("/api/download_key")
def download_key(sess: state.Session = Depends(current_session)):
    st = sess.get()
    if st["hunt"]["status"] != "success" or not sess.ssh_key_file.exists():
        raise HTTPException(status_code=409, detail="Ключ доступен после создания сервера.")
    return FileResponse(sess.ssh_key_file, filename="oracle_vm_key",
                        media_type="application/octet-stream")


@app.post("/api/wipe")
def wipe(sess: state.Session = Depends(current_session)):
    oci_service.stop_hunt(sess)
    sess.wipe()
    return {"ok": True}

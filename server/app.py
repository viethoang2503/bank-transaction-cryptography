import time
from pathlib import Path
from typing import Callable

import segno
from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from tba_core.b64 import b64url_decode, b64url_encode
from tba_core.encoding import encode_qr_payload
from tba_core.signature import public_key_from_raw

from . import auth, transfers, verify
from . import db as dbm
from .config import Settings, settings_from_env

BASE = Path(__file__).resolve().parent
AUTHENTICATOR_DIR = BASE.parent / "authenticator"


class EnrollRequest(BaseModel):
    token: str
    public_key: str


class ConfirmRequest(BaseModel):
    device_id: str
    tx_id: str
    signature: str


def _qr_svg(payload: str) -> str:
    return segno.make(payload, error="m").svg_inline(scale=4)


def create_app(settings: Settings | None = None, clock: Callable[[], int] | None = None) -> FastAPI:
    settings = settings or settings_from_env()
    clock = clock or (lambda: int(time.time()))
    dbm.init_db(settings.db_path)
    seed_conn = dbm.connect(settings.db_path)
    try:
        auth.seed_demo_users(seed_conn)
    finally:
        seed_conn.close()

    app = FastAPI(title="TBA Bank Demo")
    templates = Jinja2Templates(directory=str(BASE / "templates"))
    templates.env.filters["money"] = lambda n: f"{n:,} VND"
    AUTHENTICATOR_DIR.mkdir(exist_ok=True)
    app.mount("/app", StaticFiles(directory=str(AUTHENTICATOR_DIR), html=True), name="app")

    def get_conn():
        conn = dbm.connect(settings.db_path)
        try:
            yield conn
        finally:
            conn.close()

    def current_user(request: Request, conn=Depends(get_conn)):
        token = request.cookies.get("session")
        return auth.user_for_session(conn, token, clock()) if token else None

    def require_user(user=Depends(current_user)):
        if user is None:
            raise HTTPException(status_code=303, headers={"Location": "/login"})
        return user

    def render(request: Request, name: str, status_code: int = 200, **ctx):
        return templates.TemplateResponse(request, name, {"mode": settings.mode, **ctx}, status_code=status_code)

    @app.get("/", include_in_schema=False)
    def index(user=Depends(current_user)):
        return RedirectResponse("/transfer" if user else "/login", status_code=303)

    @app.get("/login")
    def login_form(request: Request):
        return render(request, "login.html", error=None)

    @app.post("/login")
    def login(request: Request, username: str = Form(...), password: str = Form(...), conn=Depends(get_conn)):
        user = auth.authenticate(conn, username, password)
        if user is None:
            return render(request, "login.html", status_code=401, error="Invalid username or password")
        token = auth.create_session(conn, user["id"], clock(), settings.session_ttl)
        resp = RedirectResponse("/transfer", status_code=303)
        resp.set_cookie("session", token, httponly=True, secure=settings.cookie_secure,
                        samesite="lax", max_age=settings.session_ttl)
        return resp

    @app.post("/logout")
    def logout(request: Request, conn=Depends(get_conn)):
        auth.delete_session(conn, request.cookies.get("session"))
        resp = RedirectResponse("/login", status_code=303)
        resp.delete_cookie("session")
        return resp

    @app.get("/enroll")
    def enroll_page(request: Request, user=Depends(require_user), conn=Depends(get_conn)):
        payload = "tbaenroll1:" + auth.create_enroll_token(conn, user["id"], clock(), settings.enroll_ttl)
        return render(request, "enroll.html", user=user, payload=payload, qr_svg=_qr_svg(payload))

    @app.get("/transfer")
    def transfer_form(request: Request, user=Depends(require_user), conn=Depends(get_conn)):
        has_device = auth.device_for_user(conn, user["id"]) is not None
        return render(request, "transfer_form.html", user=user, has_device=has_device, error=None)

    @app.post("/transfer")
    def transfer_create(request: Request, to: str = Form(...), amount: str = Form(...),
                        user=Depends(require_user), conn=Depends(get_conn)):
        try:
            tx = transfers.create_transfer(conn, settings, user, to.strip(), amount.strip(), clock())
        except transfers.TransferError as exc:
            has_device = auth.device_for_user(conn, user["id"]) is not None
            return render(request, "transfer_form.html", status_code=400, user=user, has_device=has_device, error=str(exc))
        return RedirectResponse(f"/transfer/{tx['tx_id']}", status_code=303)

    @app.get("/transfer/{tx_id}")
    def transfer_confirm(request: Request, tx_id: str, user=Depends(require_user), conn=Depends(get_conn)):
        tx = transfers.get_tx_for_user(conn, tx_id, user["id"])
        if tx is None:
            raise HTTPException(status_code=404)
        qr_payload = None if settings.mode == "baseline" else encode_qr_payload(tx)
        return render(request, "confirm.html", user=user, tx=tx, qr_payload=qr_payload,
                      qr_svg=_qr_svg(qr_payload) if qr_payload else None,
                      otp_digits=settings.totp_digits if settings.mode == "baseline" else settings.otp_digits,
                      expires_in=max(0, tx["exp"] - clock()))

    def _result_page(request, tx_id, user, conn, ok_status=200):
        tx = transfers.get_tx_for_user(conn, tx_id, user["id"])
        if tx is None:
            raise HTTPException(status_code=404)
        state = transfers.current_state(conn, tx_id, user["id"], clock())
        return render(request, "result.html", status_code=ok_status if state == "executed" else 400,
                      user=user, tx=tx, state=state)

    @app.post("/transfer/{tx_id}/otp")
    def transfer_otp(request: Request, tx_id: str, otp: str = Form(...),
                     user=Depends(require_user), conn=Depends(get_conn)):
        if transfers.get_tx_for_user(conn, tx_id, user["id"]) is None:
            raise HTTPException(status_code=404)
        verify.confirm_otp(conn, settings, user["id"], tx_id, otp.replace(" ", "").strip(), clock())
        return _result_page(request, tx_id, user, conn)

    @app.get("/transfer/{tx_id}/result")
    def transfer_result(request: Request, tx_id: str, user=Depends(require_user), conn=Depends(get_conn)):
        return _result_page(request, tx_id, user, conn)

    @app.get("/transfer/{tx_id}/status")
    def transfer_status(tx_id: str, user=Depends(require_user), conn=Depends(get_conn)):
        state = transfers.current_state(conn, tx_id, user["id"], clock())
        if state is None:
            raise HTTPException(status_code=404)
        return {"state": state}

    @app.get("/api/config")
    def api_config():
        return {"mode": settings.mode, "otp_digits": settings.otp_digits, "totp_digits": settings.totp_digits}

    @app.get("/api/lookup")
    def api_lookup(account: str, user=Depends(require_user), conn=Depends(get_conn)):
        row = transfers.lookup_account(conn, account)
        if row is None:
            raise HTTPException(status_code=404)
        return {"account": row["account"], "name": row["display_name"]}

    @app.post("/api/device/enroll")
    def api_enroll(req: EnrollRequest, conn=Depends(get_conn)):
        try:
            raw = b64url_decode(req.public_key)
            public_key_from_raw(raw)
        except ValueError:
            return JSONResponse({"error": "invalid_public_key"}, status_code=400)
        result = auth.enroll_device(conn, req.token, raw, clock())
        if result is None:
            return JSONResponse({"error": "invalid_token"}, status_code=403)
        device_id, k_totp, k_hmac = result
        return {"device_id": device_id, "k_totp": b64url_encode(k_totp),
                "k_hmac": b64url_encode(k_hmac), "mode": settings.mode}

    @app.post("/api/device/confirm")
    def api_confirm(req: ConfirmRequest, conn=Depends(get_conn)):
        try:
            signature = b64url_decode(req.signature)
        except ValueError:
            return {"result": verify.Result.REJECTED.value}
        result = verify.confirm_signature(conn, settings, req.device_id, req.tx_id, signature, clock())
        return {"result": result.value}

    return app

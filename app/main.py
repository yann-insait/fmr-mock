"""Mock of the FMR APIs used by the Meitav Trade agent (password reset / username recovery).

Endpoints (FMR contract, as described in the Meitav Trade FMR spec):
    POST /ValidateExToken      ExSessionID + MToken            -> RequestID, RToken (+ RefreshToken)
    POST /AccountVerification  RequestID + RToken + Account    -> cards, Email Y/N, TIK Y/N, name
    POST /ResetPassword        RequestID + RToken + UserId     -> 210 (SMS sent) | 436 (card inactive)
    POST /RecoverUserID        RequestID + RToken + UserId     -> 209 (email sent) | 427 (no email)

Mock-only helpers live under /mock (accounts, outbox, reset). Field names and status codes
follow the spec; exact JSON shapes are our assumption until FMR shares their docs.
"""

from __future__ import annotations

import json
import os
import secrets
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

# --------------------------------------------------------------------------- config

def _env_bool(name: str, default: bool) -> bool:
    return os.getenv(name, str(default)).strip().lower() in {"1", "true", "yes", "on"}

RTOKEN_TTL_SECONDS = int(os.getenv("RTOKEN_TTL_SECONDS", "600"))
MAX_VERIFY_ATTEMPTS = int(os.getenv("MAX_VERIFY_ATTEMPTS", "3"))
# True: HTTP status == FMR status (210, 436, ...). False: always HTTP 200, status only in the body.
STATUS_IN_HTTP = _env_bool("FMR_STATUS_IN_HTTP", True)
API_KEY = os.getenv("MOCK_API_KEY", "")  # if set, every request needs header X-API-Key
DATA_FILE = Path(os.getenv("ACCOUNTS_FILE", Path(__file__).parent / "data" / "accounts.json"))

# MTokens that simulate a failed Meitav authentication.
FAILING_MTOKENS = {"invalid", "expired"}

# --------------------------------------------------------------------------- state

_lock = threading.Lock()
ACCOUNTS: dict[str, dict[str, Any]] = {}
SESSIONS: dict[str, dict[str, Any]] = {}   # RequestID -> session
REFRESH: dict[str, str] = {}               # RefreshToken -> RequestID
OUTBOX: list[dict[str, Any]] = []          # SMS / emails "sent"


def load_accounts() -> None:
    data = json.loads(DATA_FILE.read_text(encoding="utf-8"))
    ACCOUNTS.clear()
    for acc in data["accounts"]:
        ACCOUNTS[acc["account"]] = acc


def reset_state() -> None:
    with _lock:
        SESSIONS.clear()
        REFRESH.clear()
        OUTBOX.clear()
        load_accounts()


load_accounts()

# --------------------------------------------------------------------------- helpers

def fmr(status: int, **body: Any) -> JSONResponse:
    payload = {"Status": status, **body}
    return JSONResponse(payload, status_code=status if STATUS_IN_HTTP else 200)


def fmr_error(status: int, error: str, message: str, **extra: Any) -> JSONResponse:
    return fmr(status, Error=error, Message=message, **extra)


def require_api_key(request: Request, x_api_key: Optional[str] = Header(default=None)) -> None:
    if request.url.path == "/health":
        return
    if API_KEY and x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Missing or invalid X-API-Key")


def get_session(request_id: str, rtoken: str) -> tuple[Optional[dict], Optional[JSONResponse]]:
    s = SESSIONS.get(request_id)
    if not s or not secrets.compare_digest(s["rtoken"], rtoken):
        return None, fmr_error(401, "INVALID_TOKEN", "RequestID/RToken not recognised")
    if time.time() > s["rtoken_expires_at"]:
        return None, fmr_error(401, "TOKEN_EXPIRED", "RToken expired; refresh via ValidateExToken")
    return s, None


def issue_rtoken(s: dict) -> None:
    s["rtoken"] = secrets.token_urlsafe(24)
    s["rtoken_expires_at"] = time.time() + RTOKEN_TTL_SECONDS

# --------------------------------------------------------------------------- models

class ValidateExTokenIn(BaseModel):
    ExSessionID: Optional[str] = None
    MToken: Optional[str] = None
    RefreshToken: Optional[str] = Field(None, description="Pass instead of ExSessionID/MToken to refresh the RToken")


class AccountVerificationIn(BaseModel):
    RequestID: str
    RToken: str
    Account: str


class ActionIn(BaseModel):
    RequestID: str
    RToken: str
    UserId: str = Field(..., description="Last 3 digits of the selected card")

# --------------------------------------------------------------------------- app

app = FastAPI(title="FMR Mock", version="1.0.0", dependencies=[Depends(require_api_key)])


@app.exception_handler(RequestValidationError)
async def _bad_request(_: Request, exc: RequestValidationError) -> JSONResponse:
    missing = [".".join(str(p) for p in e["loc"][1:]) for e in exc.errors()]
    return fmr_error(400, "BAD_REQUEST", "Invalid or missing fields", Fields=missing)


@app.get("/health")
def health() -> dict:
    return {"ok": True}


@app.post("/ValidateExToken")
def validate_ex_token(body: ValidateExTokenIn) -> JSONResponse:
    with _lock:
        # Refresh path
        if body.RefreshToken:
            rid = REFRESH.get(body.RefreshToken)
            if not rid or rid not in SESSIONS:
                return fmr_error(401, "INVALID_REFRESH_TOKEN", "Refresh token not recognised")
            s = SESSIONS[rid]
            issue_rtoken(s)
            return fmr(200, RequestID=rid, RToken=s["rtoken"], RefreshToken=body.RefreshToken,
                       ExpiresIn=RTOKEN_TTL_SECONDS)

        # Initial validation
        if not body.ExSessionID or not body.MToken:
            return fmr_error(400, "BAD_REQUEST", "ExSessionID and MToken are required",
                             Fields=[f for f in ("ExSessionID", "MToken") if not getattr(body, f)])
        if body.MToken.lower() in FAILING_MTOKENS:
            return fmr_error(401, "INVALID_MTOKEN", f"MToken rejected ({body.MToken.lower()})")

        rid = str(uuid.uuid4())
        s = {"ex_session_id": body.ExSessionID, "attempts": 0, "verified_account": None}
        issue_rtoken(s)
        refresh = secrets.token_urlsafe(24)
        SESSIONS[rid] = s
        REFRESH[refresh] = rid
        return fmr(200, RequestID=rid, RToken=s["rtoken"], RefreshToken=refresh,
                   ExpiresIn=RTOKEN_TTL_SECONDS)


@app.post("/AccountVerification")
def account_verification(body: AccountVerificationIn) -> JSONResponse:
    with _lock:
        s, err = get_session(body.RequestID, body.RToken)
        if err:
            return err
        if s["attempts"] >= MAX_VERIFY_ATTEMPTS:
            return fmr_error(423, "TOO_MANY_ATTEMPTS", "Maximum verification attempts reached", AttemptsLeft=0)
        if not (body.Account.isdigit() and len(body.Account) == 6):
            # Format errors don't consume an attempt (Encore should catch these before calling).
            return fmr_error(400, "INVALID_ACCOUNT_FORMAT", "Account must be exactly 6 digits")

        acc = ACCOUNTS.get(body.Account)
        if not acc:
            s["attempts"] += 1
            return fmr_error(404, "ACCOUNT_NOT_FOUND", "Account does not match the authenticated customer",
                             AttemptsLeft=MAX_VERIFY_ATTEMPTS - s["attempts"])

        s["verified_account"] = acc["account"]
        return fmr(200,
                   Cards=[{"Last3": c["last3"], "PermissionCode": c["permission_code"]} for c in acc["cards"]],
                   Email=acc["email"], TIK=acc["tik"],
                   FirstName=acc["first_name"], LastName=acc["last_name"])


def _run_action(body: ActionIn, kind: str) -> JSONResponse:
    with _lock:
        s, err = get_session(body.RequestID, body.RToken)
        if err:
            return err
        if not s["verified_account"]:
            return fmr_error(409, "ACCOUNT_NOT_VERIFIED", "Call AccountVerification first")
        acc = ACCOUNTS[s["verified_account"]]
        card = next((c for c in acc["cards"] if c["last3"] == body.UserId), None)
        if not card:
            return fmr_error(404, "CARD_NOT_FOUND", "UserId does not match a card on this account")

        if kind == "email" and acc["email"] != "Y":
            return fmr_error(427, "NO_EMAIL", "No email on account; username cannot be sent")
        if not card["active"]:
            return fmr_error(436, "CARD_NOT_ACTIVE", "Selected card is not active")

        OUTBOX.append({"type": kind, "account": acc["account"], "card": body.UserId,
                       "request_id": body.RequestID, "at": time.strftime("%Y-%m-%dT%H:%M:%S")})
        if kind == "sms":
            return fmr(210, Message="Password reset SMS sent to the verified phone number")
        return fmr(209, Message="Username recovery email sent")


@app.post("/ResetPassword")
def reset_password(body: ActionIn) -> JSONResponse:
    return _run_action(body, "sms")


@app.post("/RecoverUserID")
def recover_user_id(body: ActionIn) -> JSONResponse:
    return _run_action(body, "email")

# --------------------------------------------------------------------------- mock-only helpers

@app.get("/mock/accounts")
def mock_accounts() -> dict:
    return {"accounts": list(ACCOUNTS.values())}


@app.get("/mock/outbox")
def mock_outbox() -> dict:
    return {"sent": OUTBOX}


@app.post("/mock/reset")
def mock_reset() -> dict:
    reset_state()
    return {"ok": True}


@app.post("/mock/expire/{request_id}")
def mock_expire(request_id: str) -> dict:
    """Force a session's RToken to expire, to test the refresh path."""
    with _lock:
        if request_id not in SESSIONS:
            raise HTTPException(404, "Unknown RequestID")
        SESSIONS[request_id]["rtoken_expires_at"] = 0
    return {"ok": True}

"""Mock of the FMR APIs used by the Meitav Trade agent (password reset / username recovery).

Endpoints (FMR contract, as described in the Meitav Trade FMR spec):
    POST /ValidateExToken      ExSessionID + MToken            -> RequestID, RToken
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
from typing import Any, Optional, Union

from fastapi import Body, Depends, FastAPI, HTTPException, Request, Security
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, Field

# --------------------------------------------------------------------------- config

def _env_bool(name: str, default: bool) -> bool:
    return os.getenv(name, str(default)).strip().lower() in {"1", "true", "yes", "on"}

MAX_VERIFY_ATTEMPTS = int(os.getenv("MAX_VERIFY_ATTEMPTS", "3"))
# Spec: BankAttempts = 2 failed bank-details identifications per RequestID (separate from the account counter).
MAX_BANK_ATTEMPTS = int(os.getenv("MAX_BANK_ATTEMPTS", "2"))
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
OUTBOX: list[dict[str, Any]] = []          # SMS / emails "sent"


def load_accounts() -> None:
    data = json.loads(DATA_FILE.read_text(encoding="utf-8"))
    ACCOUNTS.clear()
    for acc in data["accounts"]:
        ACCOUNTS[acc["account"]] = acc


def reset_state() -> None:
    with _lock:
        SESSIONS.clear()
        OUTBOX.clear()
        load_accounts()


load_accounts()

# --------------------------------------------------------------------------- helpers

def fmr(status: int, **body: Any) -> JSONResponse:
    payload = {"Status": status, **body}
    return JSONResponse(payload, status_code=status if STATUS_IN_HTTP else 200)


def fmr_error(status: int, error: str, message: str, **extra: Any) -> JSONResponse:
    return fmr(status, Error=error, Message=message, **extra)


api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False,
                              description="Value of `MOCK_API_KEY` (Render → Environment).")


def require_api_key(x_api_key: Optional[str] = Security(api_key_header)) -> None:
    if API_KEY and x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Missing or invalid X-API-Key")


def get_session(request_id: str, rtoken: str) -> tuple[Optional[dict], Optional[JSONResponse]]:
    s = SESSIONS.get(request_id)
    if not s or not secrets.compare_digest(s["rtoken"], rtoken):
        return None, fmr_error(401, "INVALID_TOKEN", "RequestID/RToken not recognised")
    return s, None


def issue_rtoken(s: dict) -> None:
    s["rtoken"] = secrets.token_urlsafe(24)

# --------------------------------------------------------------------------- models

class ValidateExTokenIn(BaseModel):
    ExSessionID: str = Field(..., description="GUID Meitav sends with the MToken")
    MToken: str = Field(..., description="JWT Meitav created after authenticating the customer. "
                                  "Any value works; `invalid` or `expired` simulate a failed login.")


class AccountVerificationIn(BaseModel):
    """Send EITHER the trade account number OR all three bank (עו"ש) fields, never both."""
    RequestID: str = Field(..., description="From ValidateExToken")
    RToken: str = Field(..., description="From ValidateExToken")
    Account: Optional[str] = Field(None, description="Trade account number, exactly 6 digits (pad with leading zeros)",
                                   examples=["012345"])
    Bank: Optional[Union[str, int]] = Field(None, description="Bank number, up to 3 digits", examples=["012"])
    BankBranch: Optional[Union[str, int]] = Field(None, description="Branch number, up to 3 digits", examples=["600"])
    BankAccount: Optional[Union[str, int]] = Field(None, description="Bank account number, up to 9 digits", examples=["123456"])


class ActionIn(BaseModel):
    RequestID: str = Field(..., description="From ValidateExToken")
    RToken: str = Field(..., description="From ValidateExToken")
    UserId: str = Field(..., description="Last 3 digits of the selected card", examples=["418"])


# Response schemas (documentation only; handlers return JSONResponse)
class TokenOut(BaseModel):
    Status: int = Field(200, examples=[200])
    RequestID: str
    RToken: str


class CardOut(BaseModel):
    Last3: str
    PermissionCode: str


class VerificationOut(BaseModel):
    Status: int = Field(200, examples=[200])
    Cards: list[CardOut]
    Email: str = Field(..., description="Y/N: account has an email address")
    TIK: str = Field(..., description="Y/N: IRA / managed account")
    FirstName: str
    LastName: str


class ActionOut(BaseModel):
    Status: int
    Message: str


class ErrorOut(BaseModel):
    Status: int
    Error: str
    Message: str
    AttemptsLeft: Optional[int] = None
    Fields: Optional[list[str]] = None


def err(status: int, code: str, msg: str, **extra: Any) -> dict:
    return {"model": ErrorOut, "description": code,
            "content": {"application/json": {"example": {"Status": status, "Error": code, "Message": msg, **extra}}}}


BAD_REQUEST = err(400, "BAD_REQUEST", "Invalid or missing fields", Fields=["RToken"])
BAD_TOKEN = err(401, "INVALID_TOKEN", "RequestID/RToken not recognised")
PROTECTED = {"dependencies": [Depends(require_api_key)]}

# --------------------------------------------------------------------------- app

DESCRIPTION = """
Mock of the **FMR** APIs used by the Meitav Trade agent for **password reset** and **username recovery**.

**Authorize first:** click **Authorize** and paste the API key (`MOCK_API_KEY`).

### Flow
1. `ValidateExToken`: get `RequestID` + `RToken`
2. `AccountVerification`: verify the 6-digit trade account, get the cards
3. `ResetPassword` (→ 210, SMS) or `RecoverUserID` (→ 209, email) with `UserId` = card's last 3 digits

### Test accounts
| Account | Cards | Result |
|---|---|---|
| `001234` | 771 | Happy path (one card) |
| `012345` | 025, 418 | Two cards: customer picks |
| `054321` | 309 | RecoverUserID → **427** (no email) |
| `067890` | 552 (inactive), 860 | 552 → **436** |
| `098765` | 144 | TIK = Y (managed account) |
| any other | – | **404**, 3 attempts then **423** |

### Bank details (instead of `Account`)
| Bank / Branch / Account | Trade account | Result |
|---|---|---|
| `012` / `600` / `123456` | 001234 | One card (771) |
| `010` / `800` / `554433` | 012345 | Two cards (025, 418) |
| `020` / `456` / `98765` | 054321 | No email (RecoverUserID → 427) |
| `011` / `042` / `777888` | 067890 | 552 inactive, 860 |
| `031` / `123` / `112233` | 054321 **and** 067890 | **418** (joint bank account) |
| any other full set | – | **404**, 2 attempts then **423** |
| only 1–2 bank fields | – | **434** |
| `Account` + bank fields | – | **435** |

### Status codes
By default the HTTP status equals the FMR `Status` (e.g. 210, 436). If the server runs with
`FMR_STATUS_IN_HTTP=false`, every response is HTTP 200 and the code is only in `Status`.

Only **209, 210, 427, 433, 436** come from the spec; other error codes are placeholders until FMR confirms them.
"""

app = FastAPI(
    title="FMR Mock API",
    version="1.0.0",
    description=DESCRIPTION,
    openapi_tags=[
        {"name": "FMR", "description": "Mocked FMR endpoints"},
        {"name": "Mock helpers", "description": "Test-only utilities (not part of FMR)"},
    ],
    swagger_ui_parameters={"persistAuthorization": True, "displayRequestDuration": True},
)


@app.exception_handler(RequestValidationError)
async def _bad_request(_: Request, exc: RequestValidationError) -> JSONResponse:
    missing = [".".join(str(p) for p in e["loc"][1:]) for e in exc.errors()]
    return fmr_error(400, "BAD_REQUEST", "Invalid or missing fields", Fields=missing)


@app.get("/health", tags=["Mock helpers"], summary="Health check (no API key)")
def health() -> dict:
    return {"ok": True}


@app.post("/ValidateExToken", tags=["FMR"], summary="Validate the MToken and open an FMR session",
          description="Returns the RequestID + RToken used on every later call. They don't expire.",
          responses={200: {"model": TokenOut, "description": "Session opened"},
                     400: BAD_REQUEST,
                     401: err(401, "INVALID_MTOKEN", "MToken rejected (invalid)")}, **PROTECTED)
def validate_ex_token(body: ValidateExTokenIn = Body(openapi_examples={
        "success": {"summary": "Successful validation", "value": {"ExSessionID": "test-1", "MToken": "eyJ.mock"}},
        "failed": {"summary": "Failed login (401)", "value": {"ExSessionID": "test-1", "MToken": "invalid"}},
    })) -> JSONResponse:
    with _lock:
        if body.MToken.lower() in FAILING_MTOKENS:
            return fmr_error(401, "INVALID_MTOKEN", f"MToken rejected ({body.MToken.lower()})")

        rid = str(uuid.uuid4())
        s = {"ex_session_id": body.ExSessionID, "attempts": 0, "bank_attempts": 0, "verified_account": None}
        issue_rtoken(s)
        SESSIONS[rid] = s
        return fmr(200, RequestID=rid, RToken=s["rtoken"])


def _bank_key(bank: Any, branch: Any, account: Any) -> Optional[tuple[int, int, int]]:
    """Normalise bank details to ints (so "012" == "12" == 12). None if the format is wrong."""
    parts = [str(x).strip() for x in (bank, branch, account)]
    limits = (3, 3, 9)
    if not all(p.isdigit() and 1 <= len(p) <= n for p, n in zip(parts, limits)):
        return None
    return tuple(int(p) for p in parts)


def _bank_index() -> dict[tuple[int, int, int], list[str]]:
    idx: dict[tuple[int, int, int], list[str]] = {}
    for acc in ACCOUNTS.values():
        for b in acc.get("banks", []):
            idx.setdefault(_bank_key(b["bank"], b["branch"], b["account"]), []).append(acc["account"])
    return idx


def _verified(s: dict, acc: dict) -> JSONResponse:
    s["verified_account"] = acc["account"]
    return fmr(200,
               Cards=[{"Last3": c["last3"], "PermissionCode": c["permission_code"]} for c in acc["cards"]],
               Email=acc["email"], TIK=acc["tik"],
               FirstName=acc["first_name"], LastName=acc["last_name"])


@app.post("/AccountVerification", tags=["FMR"], summary="Verify the customer by trade account OR bank details",
          description=(
              "Send **either** `Account` (6 digits) **or** all three bank fields `Bank` + `BankBranch` + `BankAccount`.\n\n"
              "Trade account and bank details have separate attempt counters per RequestID "
              f"(`MAX_VERIFY_ATTEMPTS`, `MAX_BANK_ATTEMPTS`)."),
          responses={200: {"model": VerificationOut, "description": "Customer identified"},
                     400: err(400, "INVALID_ACCOUNT_FORMAT", "Account must be exactly 6 digits"),
                     401: BAD_TOKEN,
                     404: err(404, "ACCOUNT_NOT_FOUND", "Account does not match the authenticated customer", AttemptsLeft=2),
                     418: err(418, "BANK_DETAILS_MULTIPLE_ACCOUNTS", "Bank details match more than one trade account"),
                     423: err(423, "TOO_MANY_ATTEMPTS", "Maximum verification attempts reached", AttemptsLeft=0),
                     434: err(434, "PARTIAL_BANK_DETAILS", "Bank, BankBranch and BankAccount are all required"),
                     435: err(435, "ACCOUNT_AND_BANK_DETAILS", "Send either the trade account or the bank details, not both")},
          **PROTECTED)
def account_verification(body: AccountVerificationIn = Body(openapi_examples={
        "account": {"summary": "By trade account", "value": {"RequestID": "<RequestID>", "RToken": "<RToken>", "Account": "012345"}},
        "bank": {"summary": "By bank details", "value": {"RequestID": "<RequestID>", "RToken": "<RToken>",
                                                          "Bank": "012", "BankBranch": "600", "BankAccount": "123456"}},
    })) -> JSONResponse:
    with _lock:
        s, err = get_session(body.RequestID, body.RToken)
        if err:
            return err

        bank_fields = (body.Bank, body.BankBranch, body.BankAccount)
        bank_given = sum(1 for f in bank_fields if f not in (None, ""))
        has_account = body.Account not in (None, "")

        # Spec: trade account + any bank field -> 435 (the spec text says 412, its error table says 435).
        if has_account and bank_given:
            return fmr_error(435, "ACCOUNT_AND_BANK_DETAILS", "Send either the trade account or the bank details, not both")
        if not has_account and not bank_given:
            return fmr_error(400, "BAD_REQUEST", "Invalid or missing fields", Fields=["Account | Bank+BankBranch+BankAccount"])

        if has_account:
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
            return _verified(s, acc)

        # ---- bank details (עו"ש)
        if bank_given < 3:
            return fmr_error(434, "PARTIAL_BANK_DETAILS", "Bank, BankBranch and BankAccount are all required")
        if s["bank_attempts"] >= MAX_BANK_ATTEMPTS:
            return fmr_error(423, "TOO_MANY_ATTEMPTS", "Maximum verification attempts reached", AttemptsLeft=0)
        key = _bank_key(*bank_fields)
        if key is None:
            return fmr_error(400, "INVALID_BANK_FORMAT",
                             "Bank and BankBranch: up to 3 digits; BankAccount: up to 9 digits")
        matches = _bank_index().get(key, [])
        if len(matches) > 1:
            return fmr_error(418, "BANK_DETAILS_MULTIPLE_ACCOUNTS", "Bank details match more than one trade account")
        if not matches:
            s["bank_attempts"] += 1
            return fmr_error(404, "BANK_DETAILS_NOT_FOUND", "Bank details do not match the authenticated customer",
                             AttemptsLeft=MAX_BANK_ATTEMPTS - s["bank_attempts"])
        return _verified(s, ACCOUNTS[matches[0]])


def _run_action(body: ActionIn, kind: str) -> JSONResponse:
    with _lock:
        s, err = get_session(body.RequestID, body.RToken)
        if err:
            return err
        if not s["verified_account"]:
            # Spec: 433 = customer not identified by trade account or bank details (AccOK/BankOK != Y).
            return fmr_error(433, "NOT_IDENTIFIED", "Customer not identified by trade account or bank details")
        acc = ACCOUNTS[s["verified_account"]]
        card = next((c for c in acc["cards"] if c["last3"] == body.UserId), None)
        if not card:
            # The spec has no dedicated code for this; 400 = invalid request.
            return fmr_error(400, "CARD_NOT_FOUND", "UserId does not match a card on this account")

        if kind == "email" and acc["email"] != "Y":
            return fmr_error(427, "NO_EMAIL", "No email on account; username cannot be sent")
        # Spec: the card-status check (436) applies to ResetPassword only.
        if kind == "sms" and not card["active"]:
            return fmr_error(436, "CARD_NOT_ACTIVE", "Selected card is not active")

        OUTBOX.append({"type": kind, "account": acc["account"], "card": body.UserId,
                       "request_id": body.RequestID, "at": time.strftime("%Y-%m-%dT%H:%M:%S")})
        if kind == "sms":
            return fmr(210, Message="Password reset SMS sent to the verified phone number")
        return fmr(209, Message="Username recovery email sent")


@app.post("/ResetPassword", tags=["FMR"], summary="Send the password-reset SMS",
          responses={210: {"model": ActionOut, "description": "SMS sent",
                          "content": {"application/json": {"example": {"Status": 210, "Message": "Password reset SMS sent to the verified phone number"}}}},
                     400: err(400, "CARD_NOT_FOUND", "UserId does not match a card on this account"), 401: BAD_TOKEN,
                     433: err(433, "NOT_IDENTIFIED", "Customer not identified by trade account or bank details"),
                     436: err(436, "CARD_NOT_ACTIVE", "Selected card is not active")}, **PROTECTED)
def reset_password(body: ActionIn) -> JSONResponse:
    return _run_action(body, "sms")


@app.post("/RecoverUserID", tags=["FMR"], summary="Send the username-recovery email",
          responses={209: {"model": ActionOut, "description": "Email sent",
                          "content": {"application/json": {"example": {"Status": 209, "Message": "Username recovery email sent"}}}},
                     400: err(400, "CARD_NOT_FOUND", "UserId does not match a card on this account"), 401: BAD_TOKEN,
                     433: err(433, "NOT_IDENTIFIED", "Customer not identified by trade account or bank details"),
                     427: err(427, "NO_EMAIL", "No email on account; username cannot be sent")}, **PROTECTED)
def recover_user_id(body: ActionIn) -> JSONResponse:
    return _run_action(body, "email")

# --------------------------------------------------------------------------- mock-only helpers

@app.get("/mock/accounts", tags=["Mock helpers"], summary="List test accounts", **PROTECTED)
def mock_accounts() -> dict:
    return {"accounts": list(ACCOUNTS.values())}


@app.get("/mock/outbox", tags=["Mock helpers"], summary="SMS / emails sent so far", **PROTECTED)
def mock_outbox() -> dict:
    return {"sent": OUTBOX}


@app.post("/mock/reset", tags=["Mock helpers"], summary="Clear sessions and outbox", **PROTECTED)
def mock_reset() -> dict:
    reset_state()
    return {"ok": True}


# --------------------------------------------------------------------------- test-only: session callback
# Simulates FMR Milestone 2: the agent asks for authentication; the mock plays Commbox + Meitav.
# The agent calls POST /test/push-session; we answer 200 at once (so the agent's turn is not blocked),
# create an MToken + ExSessionID ourselves, then, in the background, call Encore's /conversation on the
# same conversation_id with them in session_data.

import urllib.error
import urllib.request

INSAIT_BASE = os.getenv("INSAIT_BASE", "https://api-platform.insait.io").rstrip("/")
INSAIT_API_TOKEN = os.getenv("INSAIT_API_TOKEN", "")      # the test agent's API token (eat_...), set in Render
CALLBACK_DELAY_SECONDS = float(os.getenv("CALLBACK_DELAY_SECONDS", "2"))
CALLBACK_MESSAGE = os.getenv("CALLBACK_MESSAGE", "[session update]")
PUSH_LOG: list[dict[str, Any]] = []


class PushSessionIn(BaseModel):
    """The agent asks "authenticate this customer". The mock plays Commbox + Meitav: it creates the MToken itself."""
    conversation_id: str = Field(..., description="Encore conversation UUID ({{system__conversation_id}} in the flow)")
    intent: Optional[str] = Field(None, description="reset_password / recover_username / both (logged only)")
    mtoken: Optional[str] = Field(None, description="Optional override; by default the mock generates one")
    ex_session_id: Optional[str] = Field(None, description="Optional override; by default the mock generates one")


def _push_to_encore(entry: dict[str, Any]) -> None:
    time.sleep(CALLBACK_DELAY_SECONDS)
    payload = {
        "conversation_id": entry["conversation_id"],
        "message": CALLBACK_MESSAGE,
        "session_data": {"MToken": entry["mtoken"], "ExSessionID": entry["ex_session_id"]},
    }
    req = urllib.request.Request(
        f"{INSAIT_BASE}/api/v1/external/conversation",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "X-API-Token": INSAIT_API_TOKEN},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            entry["callback_status"] = resp.status
            entry["callback_response"] = resp.read().decode("utf-8", "replace")[:2000]
    except urllib.error.HTTPError as e:
        entry["callback_status"] = e.code
        entry["callback_response"] = e.read().decode("utf-8", "replace")[:2000]
    except Exception as e:  # network error, timeout
        entry["callback_status"] = None
        entry["callback_response"] = f"{type(e).__name__}: {e}"
    entry["finished_at"] = time.time()


# No X-API-Key on purpose: the test agent calls it without a key. It can only push a fixed test message
# into conversations of the agent whose token is set in INSAIT_API_TOKEN.
@app.post("/test/push-session", tags=["Mock helpers"],
          summary="TEST: authenticate the customer (mock Commbox/Meitav creates the MToken and pushes it back)")
def push_session(body: PushSessionIn) -> dict:
    if not INSAIT_API_TOKEN:
        raise HTTPException(status_code=503, detail="INSAIT_API_TOKEN is not set on the server")
    entry = {"id": uuid.uuid4().hex[:8], "conversation_id": body.conversation_id, "intent": body.intent,
             "mtoken": body.mtoken or f"eyJ.mock-{secrets.token_urlsafe(24)}",
             "ex_session_id": body.ex_session_id or str(uuid.uuid4()),
             "queued_at": time.time(), "callback_status": "pending"}
    with _lock:
        PUSH_LOG.append(entry)
    threading.Thread(target=_push_to_encore, args=(entry,), daemon=True).start()
    return {"ok": True, "push_id": entry["id"], "callback_in_seconds": CALLBACK_DELAY_SECONDS}


@app.get("/test/push-log", tags=["Mock helpers"], summary="TEST: results of the session callbacks", **PROTECTED)
def push_log() -> dict:
    return {"pushes": PUSH_LOG}

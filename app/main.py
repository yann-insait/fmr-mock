"""Mock of the FMR APIs used by the Meitav Trade agent (password reset / username recovery).

FMR endpoints follow FMR's Swagger v1 (/api/ExternalProvider/*, see app/fmr_v1.py):
    POST ValidateExToken      ExSessionID + mjwtToken                -> RequestID, rjwtToken
    POST AccountVerification  RequestID + rjwtToken + Account | bank -> array with cards, Email, Tik, name
    POST ResetPassword        RequestID + rjwtToken + SubCard        -> 210 (deep link) | 436 (card inactive)
    POST ForgotUsername       RequestID + rjwtToken + SubCard        -> 209 (secure message) | 427 (no email)
"""

from __future__ import annotations

import json
import os
import secrets
import threading
from pathlib import Path
from typing import Any, Optional

from fastapi import FastAPI, HTTPException, Request, Security
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.security import APIKeyHeader

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


def issue_rtoken(s: dict) -> None:
    s["rtoken"] = secrets.token_urlsafe(24)

# --------------------------------------------------------------------------- app

DESCRIPTION = """
Mock of the **FMR** APIs used by the Meitav Trade agent for **password reset** and **username recovery**,
shaped like FMR's Swagger v1 (`/api/ExternalProvider/*`).

**Authorize first:** click **Authorize** and paste the API key (`MOCK_API_KEY`).

### Flow
1. `ValidateExToken`: get `RequestID` + `rjwtToken`
2. `AccountVerification`: verify the 6-digit trade account (or bank details), get the cards
3. `ResetPassword` (→ 210, deep link) or `ForgotUsername` (→ 209, secure message) with `SubCard` = card's last 3 digits

### Test accounts
| Account | Cards | Result |
|---|---|---|
| `001234` | 771 | Happy path (one card) |
| `012345` | 025, 418 | Two cards: customer picks |
| `054321` | 309 | ForgotUsername → **427** (no email) |
| `067890` | 552 (inactive), 860 | 552 → **436** |
| `098765` | 144 | Tik = Y (managed account) |
| any other | – | **404** (HTTP 401), 3 attempts then **423** |

### Bank details (instead of `Account`)
| Bank / Branch / BankAccount | Trade account | Result |
|---|---|---|
| `012` / `600` / `123456` | 001234 | One card (771) |
| `010` / `800` / `554433` | 012345 | Two cards (025, 418) |
| `020` / `456` / `98765` | 054321 | No email (ForgotUsername → 427) |
| `011` / `042` / `777888` | 067890 | 552 inactive, 860 |
| `031` / `123` / `112233` | 054321 **and** 067890 | **418** (joint bank account) |
| any other full set | – | **404**, 2 attempts then **423** |
| only 1–2 bank fields | – | **434** |
| `Account` + bank fields | – | **435** |
"""

app = FastAPI(
    title="FMR Mock API",
    version="1.0.0",
    description=DESCRIPTION,
    swagger_ui_parameters={"persistAuthorization": True, "displayRequestDuration": True},
)


@app.exception_handler(RequestValidationError)
async def _bad_request(_: Request, exc: RequestValidationError) -> JSONResponse:
    missing = [".".join(str(p) for p in e["loc"][1:]) for e in exc.errors()]
    return fmr_error(400, "BAD_REQUEST", "Invalid or missing fields", Fields=missing)


@app.get("/health", include_in_schema=False)  # Render health check (render.yaml)
def health() -> dict:
    return {"ok": True}


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


# --------------------------------------------------------------------------- FMR Swagger v1 (/api/ExternalProvider/*)
# FMR's own contract (Swagger prototype, 20.10).
from app.fmr_v1 import router as fmr_v1_router  # noqa: E402

app.include_router(fmr_v1_router)

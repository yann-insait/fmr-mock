"""FMR ExternalProvider API, shaped like FMR's Swagger prototype (20.10).

Routes live under /api/ExternalProvider/* and use the accounts, sessions and outbox kept in main.py.

Contract details, all taken from the Swagger:
    - field names: mjwtToken / rjwtToken (were MToken / RToken), Branch (was BankBranch), SubCard (was UserId)
    - AccountVerification returns an ARRAY of results; cards are CardPermission[{SubCard, Permission}]; Tik (was TIK)
    - ResetPassword returns a DeepLink; ForgotUsername sends a secure message
    - HTTP status: ValidateExToken = Status; the other endpoints = 200, except 401 for Status 404/408
      Invalid request = empty HTTP 400.
    - no Error / Message / AttemptsLeft fields (not in the Swagger)

FMR has not listed the business Status values for these endpoints. The ones used here are the
older mock's (spec V10.1) codes: 404 not found, 408 session expired, 418, 423, 433, 434, 435, 436, 209, 210, 427.
"""

from __future__ import annotations

import secrets
import time
import uuid
from typing import Any, Optional, Union

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, Field, ValidationError

from app import main as core

router = APIRouter(prefix="/api/ExternalProvider", tags=["FMR (Swagger v1)"])
PROTECTED = [Depends(core.require_api_key)]

# Swagger Permission enum. The older mock keeps FMR's PermissionCode ("01"...); this mapping is our guess.
PERMISSIONS = {"00": "None", "01": "FullExecution", "02": "InformationOnly", "03": "ExecuteTransactionsNoWithdrawal"}

# mjwtToken values that simulate ValidateExToken outcomes.
TOKEN_STATUS = {"invalid": 400, "expired": 400, "active-request": 430, "duplicate": 432, "no-card": 436,
                "session-expired": 408}



# --------------------------------------------------------------------------- models (Swagger definitions)

class ValidateExRequest(BaseModel):
    ExSessionID: str = Field(..., min_length=1, max_length=50)
    mjwtToken: str = Field(..., min_length=1, max_length=16384,
                           description="Any value works. `invalid`/`expired` → 400, `active-request` → 430, "
                                       "`duplicate` → 432, `no-card` → 436.")


class AccountVerificationRequest(BaseModel):
    RequestID: str
    rjwtToken: str = Field(..., min_length=1, max_length=16384)
    Account: Optional[str] = Field(None, max_length=10, examples=["012345"])
    Bank: Optional[Union[str, int]] = Field(None, examples=["012"])
    Branch: Optional[Union[str, int]] = Field(None, examples=["600"])
    BankAccount: Optional[Union[str, int]] = Field(None, examples=["123456"])


class SubCardRequest(BaseModel):
    RequestID: str
    rjwtToken: str = Field(..., min_length=1, max_length=16384)
    SubCard: str = Field(..., min_length=3, max_length=3, examples=["418"])


# --------------------------------------------------------------------------- helpers

def _doc_body(model: type[BaseModel]) -> dict:
    """Request body for /docs only: the handlers parse the body themselves (Swagger: invalid request = empty 400)."""
    return {"requestBody": {"required": True, "content": {"application/json": {"schema": model.model_json_schema()}}}}


def _empty_400() -> Response:
    return Response(status_code=400)


async def _parse(request: Request, model: type[BaseModel]) -> Optional[BaseModel]:
    """Swagger: an invalid request is an empty HTTP 400 (not the older mock's JSON error)."""
    try:
        return model.model_validate(await request.json())
    except (ValueError, ValidationError):
        return None


def _valid_guid(value: str) -> bool:
    try:
        return uuid.UUID(value) != uuid.UUID(int=0)
    except ValueError:
        return False


def _http(status: int, extra: dict[int, int] | None = None) -> int:
    """Business Status -> HTTP status for the endpoints that answer 200 (Swagger)."""
    if status in (404, 408):
        return 401
    return (extra or {}).get(status, 200)


def _session(req: BaseModel) -> tuple[Optional[dict], Optional[int]]:
    s = core.SESSIONS.get(req.RequestID)
    if not s or not secrets.compare_digest(s["rtoken"], req.rjwtToken):
        return None, 404           # unknown RequestID / token → treated as "not found" (HTTP 401)
    if s.get("expired"):
        return None, 408
    return s, None


# --------------------------------------------------------------------------- endpoints

@router.post("/ValidateExToken", summary="Validate the external session token (HTTP status = Status)",
             dependencies=PROTECTED, openapi_extra=_doc_body(ValidateExRequest))
async def validate_ex_token(request: Request) -> Response:
    body = await _parse(request, ValidateExRequest)
    if body is None or not body.ExSessionID.strip() or not body.mjwtToken.strip():
        return _empty_400()
    with core._lock:
        status = TOKEN_STATUS.get(body.mjwtToken.lower(), 200)
        if status not in (200, 408):
            return JSONResponse({"ExSessionID": body.ExSessionID, "RequestID": None, "rjwtToken": None,
                                 "Status": status}, status_code=status)
        rid = str(uuid.uuid4())
        s = {"ex_session_id": body.ExSessionID, "attempts": 0, "bank_attempts": 0, "verified_account": None,
             "expired": status == 408}   # session-expired: the session opens, later calls get 408
        core.issue_rtoken(s)
        core.SESSIONS[rid] = s
        return JSONResponse({"ExSessionID": body.ExSessionID, "RequestID": rid, "rjwtToken": s["rtoken"],
                             "Status": 200}, status_code=200)


def _verification(rid: str, s: Optional[dict], status: int, acc: Optional[dict] = None) -> JSONResponse:
    item: dict[str, Any] = {"RequestID": rid, "rjwtToken": s["rtoken"] if s else None, "Status": status,
                            "Email": None, "Tik": None, "FirstName": None, "LastName": None, "CardPermission": []}
    if acc:
        s["verified_account"] = acc["account"]
        item.update(Email=acc["email"], Tik=acc["tik"], FirstName=acc["first_name"], LastName=acc["last_name"],
                    CardPermission=[{"SubCard": c["last3"],
                                     "Permission": PERMISSIONS.get(c["permission_code"], "None")}
                                    for c in acc["cards"]])
    return JSONResponse([item], status_code=_http(status))


@router.post("/AccountVerification", summary="Verify by trade account OR bank details (returns an array)",
             dependencies=PROTECTED, openapi_extra=_doc_body(AccountVerificationRequest))
async def account_verification(request: Request) -> Response:
    body = await _parse(request, AccountVerificationRequest)
    if body is None or not _valid_guid(body.RequestID) or not body.rjwtToken.strip():
        return _empty_400()
    with core._lock:
        s, bad = _session(body)
        if bad:
            return _verification(body.RequestID, None, bad)

        bank_fields = (body.Bank, body.Branch, body.BankAccount)
        bank_given = sum(1 for f in bank_fields if f not in (None, ""))
        has_account = body.Account not in (None, "")
        if has_account and bank_given:
            return _verification(body.RequestID, s, 435)
        if not has_account and not bank_given:
            return _empty_400()

        if has_account:
            if s["attempts"] >= core.MAX_VERIFY_ATTEMPTS:
                return _verification(body.RequestID, s, 423)
            if not (body.Account.isdigit() and len(body.Account) == 6):
                return _empty_400()   # format errors don't use an attempt
            acc = core.ACCOUNTS.get(body.Account)
            if not acc:
                s["attempts"] += 1
                return _verification(body.RequestID, s, 404)
            return _verification(body.RequestID, s, 200, acc)

        if bank_given < 3:
            return _verification(body.RequestID, s, 434)
        if s["bank_attempts"] >= core.MAX_BANK_ATTEMPTS:
            return _verification(body.RequestID, s, 423)
        key = core._bank_key(*bank_fields)
        if key is None:
            return _empty_400()
        matches = core._bank_index().get(key, [])
        if len(matches) > 1:
            return _verification(body.RequestID, s, 418)
        if not matches:
            s["bank_attempts"] += 1
            return _verification(body.RequestID, s, 404)
        return _verification(body.RequestID, s, 200, core.ACCOUNTS[matches[0]])


def _card_check(body: SubCardRequest) -> tuple[Optional[dict], Optional[dict], Optional[dict], int]:
    """Returns (session, account, card, status) for ResetPassword / ForgotUsername."""
    s, bad = _session(body)
    if bad:
        return None, None, None, bad
    if not s["verified_account"]:
        return s, None, None, 433
    acc = core.ACCOUNTS[s["verified_account"]]
    card = next((c for c in acc["cards"] if c["last3"] == body.SubCard), None)
    if not card:
        return s, acc, None, 404   # no dedicated code known; "not found"
    return s, acc, card, 0


@router.post("/ResetPassword", summary="Request a password-reset deep link",
             dependencies=PROTECTED, openapi_extra=_doc_body(SubCardRequest))
async def reset_password(request: Request) -> Response:
    body = await _parse(request, SubCardRequest)
    if body is None or not _valid_guid(body.RequestID):
        return _empty_400()
    with core._lock:
        s, acc, card, status = _card_check(body)
        out: dict[str, Any] = {"RequestID": body.RequestID, "rjwtToken": s["rtoken"] if s else None,
                               "Status": status, "DeepLink": None}
        if status == 0 and not card["active"]:
            out["Status"] = 436
        elif status == 0:
            link_id = str(uuid.uuid4())
            out.update(Status=210, DeepLink=f"{request.base_url}reset?DeeplinkID={link_id}")
            core.OUTBOX.append({"type": "deeplink", "account": acc["account"], "card": card["last3"],
                                "request_id": body.RequestID, "deeplink_id": link_id,
                                "at": time.strftime("%Y-%m-%dT%H:%M:%S")})
        return JSONResponse(out, status_code=_http(out["Status"]))


@router.post("/ForgotUsername", summary="Request username recovery through a secure message",
             dependencies=PROTECTED, openapi_extra=_doc_body(SubCardRequest))
async def forgot_username(request: Request) -> Response:
    body = await _parse(request, SubCardRequest)
    if body is None or not _valid_guid(body.RequestID):
        return _empty_400()
    with core._lock:
        s, acc, card, status = _card_check(body)
        if status == 0 and acc["email"] != "Y":
            status = 427
        elif status == 0:
            status = 209
            core.OUTBOX.append({"type": "secure_message", "account": acc["account"], "card": card["last3"],
                                "request_id": body.RequestID,
                                "at": time.strftime("%Y-%m-%dT%H:%M:%S")})
        return JSONResponse({"RequestID": body.RequestID, "rjwtToken": s["rtoken"] if s else None,
                             "Status": status}, status_code=_http(status))



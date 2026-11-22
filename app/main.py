"""Mock of the FMR APIs used by the Meitav Trade agent (password reset / username recovery).

FMR endpoints follow FMR's Swagger v1 (/api/ExternalProvider/*, see app/fmr_v1.py):
    POST ValidateExToken      ExSessionID + mjwtToken                -> RequestID, rjwtToken
    POST AccountVerification  RequestID + rjwtToken + Account | bank -> array with cards, Email, Tik, name
    POST ResetPassword        RequestID + rjwtToken + SubCard        -> 210 (deep link) | 436 (card inactive)
    POST ForgotUsername       RequestID + rjwtToken + SubCard        -> 209 (secure message) | 427 (no email)
Also: POST /api/formemail/send-form-by-email   email + formName + data  -> 200 (form emailed) | 500 (send failed)
    formName: "kubiot" (pension enrolment) | "nispah5" (נספח ה', end of employment)
"""

from __future__ import annotations

import json
import os
import secrets
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Literal, Optional

from fastapi import Body, Depends, FastAPI, HTTPException, Request, Security
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, Field, ValidationError

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

# send-form-by-email: an email whose domain is one of these simulates a failed send (500).
FAILING_FORM_DOMAINS = {"fail.com", "error.com"}

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

# --------------------------------------------------------------------------- models

class KubiotData(BaseModel):
    """`data` for formName = kubiot (pension / study-fund enrolment). Field names follow the real API, typos included."""
    new_filldate: str = Field(..., description="Fill date, DD/MM/YYYY", examples=["20/11/2025"])
    fullName: str = Field(..., description="Employee full name", examples=["ישראל ישראלי"])
    idNumber: str = Field(..., description="Employee ID number (ת.ז.)", examples=["012345678"])
    employeName: str = Field(..., description="Employer name (sic: real API field name)", examples=["מיטב"])
    HP: str = Field(..., description="Employer company number (ח.פ.)", examples=["516583036"])
    monthlyIncome: str = Field(..., description="Monthly salary, formatted", examples=["3,000"])
    product: str = Field(..., description="Product 1", examples=["פנסיה מקיפה"])
    salaryCategory: str = Field(..., description="Salary category for product 1", examples=["משכורת בסיסית"])
    ma: str = Field(..., description="Fund tax-approval number (מ.ה.) for product 1", examples=["163"])
    ddovedPayment: str = Field(..., description="Employee contribution, product 1", examples=["6%"])
    ddcompensation: str = Field(..., description="Severance contribution, product 1", examples=["6%"])
    ddmaasikPayment: str = Field(..., description="Employer contribution, product 1", examples=["6.5%"])
    insureIncome: str = Field(..., description="Insured salary, product 1", examples=["2,000"])
    # Optional second product
    product2: Optional[str] = Field(None, description="Product 2", examples=["השתלמות"])
    salaryCategory2: Optional[str] = Field(None, examples=["משכורת בסיסית"])
    ma2: Optional[str] = Field(None, examples=["880"])
    ddovedPayment2: Optional[str] = Field(None, examples=["2.5%"])
    ddmaasikPayment2: Optional[str] = Field(None, examples=["7.5%"])
    insureIncome2: Optional[str] = Field(None, examples=["3,000"])


class Nispah5Data(BaseModel):
    """`data` for formName = nispah5 (נספח ה': end-of-employment notice)."""
    emploeeName: str = Field(..., description="Employee full name (sic: real API field name)", examples=["ישראל ישראלי"])
    idNumber: str = Field(..., description="Employee ID number (ת.ז.)", examples=["012345678"])
    maasikName: str = Field(..., description="Employer name", examples=["מיטב"])
    HP: str = Field(..., description="Employer company number (ח.פ.)", examples=["516583036"])
    product: str = Field(..., description="Product", examples=["מיטב פנסיה מקיפה"])
    accountNum: str = Field(..., description="Account number", examples=["18-012345678"])


FORM_DATA_MODELS: dict[str, type[BaseModel]] = {"kubiot": KubiotData, "nispah5": Nispah5Data}


class SendFormIn(BaseModel):
    email: str = Field(..., description="Recipient. A `@fail.com` / `@error.com` address simulates a failed send (500).",
                       examples=["customer@example.com"])
    formName: Literal["kubiot", "nispah5"] = Field(..., description="Selects the `data` shape")
    # Validated in the handler against FORM_DATA_MODELS[formName]; the OpenAPI schema is patched to a oneOf below.
    data: dict[str, Any] = Field(..., description="Form fields. `kubiot` → KubiotData, `nispah5` → Nispah5Data")


# Response schemas (documentation only; handlers return JSONResponse) (documentation only; handlers return JSONResponse)
class SendFormOut(BaseModel):
    Status: int = Field(200, examples=[200])
    Message: str
    FormName: str
    ReferenceID: str


class ErrorOut(BaseModel):
    Status: int
    Error: str
    Message: str
    AttemptsLeft: Optional[int] = None
    Fields: Optional[list[str]] = None


def err(status: int, code: str, msg: str, **extra: Any) -> dict:
    return {"model": ErrorOut, "description": code,
            "content": {"application/json": {"example": {"Status": status, "Error": code, "Message": msg, **extra}}}}


PROTECTED = {"dependencies": [Depends(require_api_key)]}

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

### Forms
`POST /api/formemail/send-form-by-email` emails a filled form (`formName`: `kubiot` or `nispah5`).
Any recipient works; `@fail.com` / `@error.com` → **500**.
"""

app = FastAPI(
    title="FMR Mock API",
    version="1.0.0",
    description=DESCRIPTION,
    openapi_tags=[
        {"name": "Forms", "description": "Mocked Meitav chat-integration-api (send-form-by-email)"},
    ],
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


KUBIOT_EXAMPLE = {
    "email": "customer@example.com", "formName": "kubiot",
    "data": {"new_filldate": "20/11/2025", "fullName": "ישראל ישראלי", "idNumber": "012345678",
             "employeName": "מיטב", "HP": "516583036", "monthlyIncome": "3,000",
             "product": "פנסיה מקיפה", "salaryCategory": "משכורת בסיסית", "ma": "163",
             "ddovedPayment": "6%", "ddcompensation": "6%", "ddmaasikPayment": "6.5%", "insureIncome": "2,000",
             "product2": "השתלמות", "salaryCategory2": "משכורת בסיסית", "ma2": "880",
             "ddovedPayment2": "2.5%", "ddmaasikPayment2": "7.5%", "insureIncome2": "3,000"}}
NISPAH5_EXAMPLE = {
    "email": "customer@example.com", "formName": "nispah5",
    "data": {"emploeeName": "ישראל ישראלי", "idNumber": "012345678", "maasikName": "מיטב",
             "HP": "516583036", "product": "מיטב פנסיה מקיפה", "accountNum": "18-012345678"}}


@app.post("/api/formemail/send-form-by-email", tags=["Forms"], summary="Email a filled form to the customer",
          description="Mock of Meitav's `chat-integration-api` `send-form-by-email`. Pick the `data` shape with "
                      "`formName`: **kubiot** (pension enrolment) or **nispah5** (נספח ה'). No RequestID/RToken "
                      "needed. The real API also wants the customer's bearer token and the IBM gateway headers "
                      "`x-ibm-client-id` / `x-ibm-client-secret`; the mock ignores all three.\n\n"
                      "Any email works, except one at `@fail.com` or `@error.com`, which returns 500 "
                      "`FORM_SEND_FAILED`. Unknown `formName` or missing `data` fields return 400.",
          responses={200: {"model": SendFormOut, "description": "Form emailed",
                          "content": {"application/json": {"example": {"Status": 200, "Message": "Form sent by email",
                                                                       "FormName": "kubiot", "ReferenceID": "6f1c…"}}}},
                     400: err(400, "BAD_REQUEST", "Invalid or missing fields", Fields=["data.HP"]),
                     500: err(500, "FORM_SEND_FAILED", "Form could not be sent")}, **PROTECTED)
def send_form_by_email(body: SendFormIn = Body(openapi_examples={
        "kubiot": {"summary": "kubiot: two products (200)", "value": KUBIOT_EXAMPLE},
        "nispah5": {"summary": "nispah5 (200)", "value": NISPAH5_EXAMPLE},
        "failed": {"summary": "Send failed (500)", "value": {**NISPAH5_EXAMPLE, "email": "customer@fail.com"}},
    })) -> JSONResponse:
    try:
        data = FORM_DATA_MODELS[body.formName].model_validate(body.data)
    except ValidationError as exc:
        fields = ["data." + ".".join(str(p) for p in e["loc"]) for e in exc.errors()]
        return fmr_error(400, "BAD_REQUEST", "Invalid or missing fields", Fields=fields)

    with _lock:
        domain = body.email.rsplit("@", 1)[-1].lower()
        if domain in FAILING_FORM_DOMAINS:
            return fmr_error(500, "FORM_SEND_FAILED", "Form could not be sent")

        ref = str(uuid.uuid4())
        OUTBOX.append({"type": "form_email", "form_name": body.formName, "reference_id": ref, "email": body.email,
                       "data": data.model_dump(exclude_none=True), "at": time.strftime("%Y-%m-%dT%H:%M:%S")})
        return fmr(200, Message="Form sent by email", FormName=body.formName, ReferenceID=ref)


def _openapi_with_form_schemas() -> dict:
    """Document `SendFormIn.data` as oneOf(KubiotData, Nispah5Data) instead of a bare object."""
    if app.openapi_schema:
        return app.openapi_schema
    spec = _default_openapi()
    schemas = spec["components"]["schemas"]
    for model in FORM_DATA_MODELS.values():
        schemas[model.__name__] = model.model_json_schema(ref_template="#/components/schemas/{model}")
    data = schemas["SendFormIn"]["properties"]["data"]
    data.pop("additionalProperties", None)
    data.pop("type", None)
    data["oneOf"] = [{"$ref": f"#/components/schemas/{m.__name__}"} for m in FORM_DATA_MODELS.values()]
    return spec


_default_openapi = app.openapi
app.openapi = _openapi_with_form_schemas  # type: ignore[method-assign]

# --------------------------------------------------------------------------- FMR Swagger v1 (/api/ExternalProvider/*)
# FMR's own contract (Swagger prototype, 20.10). Kept next to the routes above, which the Encore staging tools still call.
from app.fmr_v1 import router as fmr_v1_router  # noqa: E402

app.include_router(fmr_v1_router)

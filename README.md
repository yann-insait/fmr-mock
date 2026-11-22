# FMR Mock API

Mock of the four FMR APIs the Meitav Trade agent uses for password reset and username recovery, shaped like FMR's Swagger v1 (`/api/ExternalProvider/*`). Lets us build and test the Encore flow before FMR's real endpoints are available. Also mocks Meitav's `send-form-by-email`.

Field names and HTTP behaviour follow FMR's Swagger prototype (20.10). Business Status values are not in the Swagger; the mock keeps the spec V10.1 ones.

## Run

```bash
# Local
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8080

# Docker
docker build -t fmr-mock .
docker run -p 8080:8080 -e MOCK_API_KEY=changeme fmr-mock
```

Interactive docs: `http://localhost:8080/docs`

Tests: `pip install -r requirements-dev.txt && pytest -q`

## Deploy to Render

The repo includes `render.yaml`, so Render sets everything up from it.

1. Push this folder to a GitHub repo (private is fine).
2. In Render: **New → Blueprint**, pick the repo, click **Apply**.
3. When the build finishes, the service URL is shown at the top (e.g. `https://fmr-mock-xxxx.onrender.com`).
4. Get the API key: service → **Environment** → `MOCK_API_KEY` (generated automatically).
5. Check: `curl https://<url>/health` → `{"ok": true}`

**Free plan:** the service sleeps after 15 minutes without traffic. The first call after that takes ~1 minute to wake it, and sleeping clears all sessions. Call `/health` before a test session. Upgrade to a paid instance if the agent's tool calls time out.

## Configuration

| Env var | Default | Purpose |
|---|---|---|
| `MOCK_API_KEY` | *(empty)* | If set, every request (except `/health`) needs header `X-API-Key`. Set it when deployed publicly. |
| `MAX_VERIFY_ATTEMPTS` | `3` | Wrong account numbers allowed per RequestID before `423`. |
| `MAX_BANK_ATTEMPTS` | `2` | Wrong bank details allowed per RequestID before `423` (spec `BankAttempts`). |
| `FMR_STATUS_IN_HTTP` | `true` | `send-form-by-email` only: `true` = HTTP status equals `Status`; `false` = always HTTP 200. |
| `ACCOUNTS_FILE` | `app/data/accounts.json` | Mock accounts. |
| `PORT` | `8080` | Docker only. |


## FMR endpoints (`/api/ExternalProvider/*`)

FMR's own contract (Swagger prototype, 20.10, untested on their side). These are the four endpoints the Encore FMR agent calls.

| Endpoint | Request | Response |
|---|---|---|
| `POST /api/ExternalProvider/ValidateExToken` | `ExSessionID`, `mjwtToken` | `ExSessionID`, `RequestID`, `rjwtToken`, `Status`. **HTTP status = Status.** |
| `POST /api/ExternalProvider/AccountVerification` | `RequestID`, `rjwtToken` + `Account` **or** `Bank` + `Branch` + `BankAccount` | **Array** of `{RequestID, rjwtToken, Status, Email, Tik, FirstName, LastName, CardPermission: [{SubCard, Permission}]}` |
| `POST /api/ExternalProvider/ResetPassword` | `RequestID`, `rjwtToken`, `SubCard` | `RequestID`, `rjwtToken`, `Status`, `DeepLink` |
| `POST /api/ExternalProvider/ForgotUsername` | `RequestID`, `rjwtToken`, `SubCard` | `RequestID`, `rjwtToken`, `Status` |

`SubCard` = last 3 digits of the selected card.

HTTP status (from the Swagger): `ValidateExToken` returns the Status as the HTTP code. The other endpoints return **200**, or **401** when Status is 404 or 408. An invalid request is an **empty 400**. No `Error` / `Message` / `AttemptsLeft` fields.

| Status | When |
|---|---|
| 200 | ValidateExToken / AccountVerification success |
| 209 | ForgotUsername: secure message sent |
| 210 | ResetPassword: deep link created |
| 404 | Unknown account, bank details or card, or bad RequestID / rjwtToken (HTTP 401) |
| 408 | Session expired (HTTP 401) |
| 418 | Bank details belong to more than one trade account |
| 423 | Too many wrong attempts (`MAX_VERIFY_ATTEMPTS` / `MAX_BANK_ATTEMPTS`) |
| 427 | ForgotUsername on an account with no email |
| 433 | ResetPassword / ForgotUsername before a successful AccountVerification |
| 434 | Only 1–2 of the 3 bank fields sent |
| 435 | `Account` and bank fields sent together |
| 436 | ResetPassword with an inactive card |

`mjwtToken` values that simulate outcomes: `invalid` / `expired` → 400, `active-request` → 430, `duplicate` → 432, `no-card` → 436, `session-expired` → the session opens, later calls get 408.

`Permission` comes from the account's `permission_code`: 00 None, 01 FullExecution, 02 InformationOnly, 03 ExecuteTransactionsNoWithdrawal (our guess).

### `POST /api/formemail/send-form-by-email`

Mock of Meitav's `chat-integration-api` form-email endpoint (from the "PROJECT INSAIT - forms" Postman collection). Stand-alone: no `RequestID`/`rjwtToken`. The real API also needs the customer's bearer token plus the `x-ibm-client-id` / `x-ibm-client-secret` gateway headers; the mock ignores them.

Envelope: `{ "email", "formName", "data" }`. `formName` selects the `data` shape:

**`kubiot`** (pension / study-fund enrolment) — the `*2` fields are an optional second product:

```json
{
  "email": "customer@example.com",
  "formName": "kubiot",
  "data": {
    "new_filldate": "20/11/2025", "fullName": "ישראל ישראלי", "idNumber": "012345678",
    "employeName": "מיטב", "HP": "516583036", "monthlyIncome": "3,000",
    "product": "פנסיה מקיפה", "salaryCategory": "משכורת בסיסית", "ma": "163",
    "ddovedPayment": "6%", "ddcompensation": "6%", "ddmaasikPayment": "6.5%", "insureIncome": "2,000",
    "product2": "השתלמות", "salaryCategory2": "משכורת בסיסית", "ma2": "880",
    "ddovedPayment2": "2.5%", "ddmaasikPayment2": "7.5%", "insureIncome2": "3,000"
  }
}
```

**`nispah5`** (נספח ה׳, end of employment):

```json
{
  "email": "customer@example.com",
  "formName": "nispah5",
  "data": {
    "emploeeName": "ישראל ישראלי", "idNumber": "012345678", "maasikName": "מיטב",
    "HP": "516583036", "product": "מיטב פנסיה מקיפה", "accountNum": "18-012345678"
  }
}
```

Field names (including the typos `employeName` / `emploeeName`) are exactly as in the real API. All values are strings.

→ `200` `{ "Status": 200, "Message": "Form sent by email", "FormName": "kubiot", "ReferenceID": "<uuid>" }`.

- Any email works, except one at `@fail.com` or `@error.com` → `500 FORM_SEND_FAILED`
- Unknown `formName`, or `data` missing a required field → `400 BAD_REQUEST`


## Identification by bank details (עו"ש)

`AccountVerification` accepts **either** `Account` **or** all three of `Bank` (≤3 digits), `Branch` (≤3 digits) and `BankAccount` (≤9 digits). Numbers are compared as integers, so `"012"`, `"12"` and `12` match. Bank attempts and trade-account attempts are counted separately per RequestID.

| Bank / Branch / BankAccount | Trade account | Result |
|---|---|---|
| `012` / `600` / `123456` | 001234 | One card (771) |
| `010` / `800` / `554433` | 012345 | Two cards (025, 418) |
| `020` / `456` / `98765` | 054321 | No email (ForgotUsername → 427) |
| `011` / `042` / `777888` | 067890 | 552 inactive, 860 |
| `012` / `600` / `999000` | 098765 | Tik = Y |
| `031` / `123` / `112233` | 054321 **and** 067890 | **418** (joint account) |

## Test accounts

| Account | Cards (last 3) | Email | Tik | Scenario |
|---|---|---|---|---|
| `001234` | 771 | Y | N | One card — happy path for both actions |
| `012345` | 025, 418 | Y | N | Two cards — customer picks |
| `054321` | 309 | **N** | N | ForgotUsername → 427 |
| `067890` | 552 (**inactive**), 860 | Y | N | Pick 552 → 436 |
| `098765` | 144 | Y | **Y** | IRA / managed account |
| any other 6 digits | — | — | — | 404, uses an attempt |

Edit `app/data/accounts.json` to add more. State is in memory: restarting the service clears all sessions.

## Full flow with curl

```bash
B=http://localhost:8080/api/ExternalProvider
T=$(curl -s $B/ValidateExToken -H 'Content-Type: application/json' \
  -d '{"ExSessionID":"g-1","mjwtToken":"eyJ.mock"}')
RID=$(echo $T | jq -r .RequestID); RT=$(echo $T | jq -r .rjwtToken)

curl -s $B/AccountVerification -H 'Content-Type: application/json' \
  -d "{\"RequestID\":\"$RID\",\"rjwtToken\":\"$RT\",\"Account\":\"012345\"}"

curl -s $B/ResetPassword -H 'Content-Type: application/json' \
  -d "{\"RequestID\":\"$RID\",\"rjwtToken\":\"$RT\",\"SubCard\":\"418\"}"
```

Form email:

```bash
curl -s http://localhost:8080/api/formemail/send-form-by-email -H 'Content-Type: application/json' \
  -d '{"email":"customer@example.com","formName":"nispah5","data":{"emploeeName":"ישראל ישראלי","idNumber":"012345678","maasikName":"מיטב","HP":"516583036","product":"מיטב פנסיה מקיפה","accountNum":"18-012345678"}}'
# → 200. Use "email":"customer@fail.com" to get 500.
```

Add `-H 'X-API-Key: <key>'` if `MOCK_API_KEY` is set.

# FMR Mock API

Mock of the four FMR APIs the Meitav Trade agent uses for password reset and username recovery. Lets us build and test the Encore flow before FMR's real endpoints are available.

Field names and status codes follow the Meitav Trade FMR spec. **Exact JSON shapes are assumptions** — update `app/main.py` once FMR shares their docs.

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
| `FMR_STATUS_IN_HTTP` | `true` | `true`: HTTP status = FMR status (210, 436…). `false`: always HTTP 200, status only in body `Status`. Use `false` if the agent's tool treats non-2xx as a failure. |
| `ACCOUNTS_FILE` | `app/data/accounts.json` | Mock accounts. |
| `PORT` | `8080` | Docker only. |

## Endpoints

All `POST`, JSON body. Every response includes `Status`.

### `POST /ValidateExToken`

```json
{ "ExSessionID": "<GUID>", "MToken": "eyJ..." }
```

→ `200` `{ "RequestID", "RToken" }`. Tokens don't expire; they last until the service restarts.

Any MToken works, except `invalid` or `expired` → `401 INVALID_MTOKEN`.

### `POST /AccountVerification`

```json
{ "RequestID": "...", "RToken": "...", "Account": "001234" }
```

→ `200` `{ "Cards": [{ "Last3": "771", "PermissionCode": "01" }], "Email": "Y", "TIK": "N", "FirstName", "LastName" }`

### `POST /ResetPassword` and `POST /RecoverUserID`

```json
{ "RequestID": "...", "RToken": "...", "UserId": "771" }
```

`UserId` = last 3 digits of the selected card.

- ResetPassword → `210` (SMS sent)
- RecoverUserID → `209` (email sent)

### Status codes

| Code | Error | When |
|---|---|---|
| 200 | — | ValidateExToken / AccountVerification success |
| 209 | — | RecoverUserID success |
| 210 | — | ResetPassword success |
| 400 | `BAD_REQUEST` / `INVALID_ACCOUNT_FORMAT` | Missing fields; account not exactly 6 digits (doesn't use an attempt) |
| 401 | `INVALID_MTOKEN` / `INVALID_TOKEN` | Auth problems |
| 404 | `ACCOUNT_NOT_FOUND` | Unknown account (uses an attempt; `AttemptsLeft` returned) |
| 400 | `CARD_NOT_FOUND` | `UserId` isn't a card on the verified account (no dedicated code in the spec) |
| 433 | `NOT_IDENTIFIED` | ResetPassword / RecoverUserID before a successful AccountVerification (spec 433) |
| 423 | `TOO_MANY_ATTEMPTS` | Max wrong account numbers reached |
| 427 | `NO_EMAIL` | RecoverUserID on account with Email = N |
| 436 | `CARD_NOT_ACTIVE` | ResetPassword with an inactive card (RecoverUserID doesn't check card status, per spec) |

**Real FMR codes:** 209, 210, 427, 433 and 436 come from the spec. 400 (`CARD_NOT_FOUND`), 401, 404 and 423 are placeholders until FMR confirms their error codes.

## Identification by bank details (עו"ש)

Per the spec, `AccountVerification` accepts **either** `Account` **or** all three of `Bank` (≤3 digits), `BankBranch` (≤3 digits) and `BankAccount` (≤9 digits). Numbers are compared as integers, so `"012"`, `"12"` and `12` match.

| Code | Error | When |
|---|---|---|
| 400 | `BAD_REQUEST` | Neither `Account` nor bank details sent |
| 400 | `INVALID_BANK_FORMAT` | Too many digits / not digits (doesn't use an attempt) |
| 404 | `BANK_DETAILS_NOT_FOUND` | No trade account with these bank details (uses a bank attempt; `AttemptsLeft` returned) |
| 418 | `BANK_DETAILS_MULTIPLE_ACCOUNTS` | Bank details belong to more than one trade account |
| 423 | `TOO_MANY_ATTEMPTS` | `MAX_BANK_ATTEMPTS` (default 2) wrong bank details |
| 434 | `PARTIAL_BANK_DETAILS` | Only 1–2 of the 3 bank fields sent |
| 435 | `ACCOUNT_AND_BANK_DETAILS` | `Account` and bank fields sent together (spec text says 412, its error table says 435) |

Bank attempts and trade-account attempts are counted separately per RequestID (spec: `BankAttempts`, `ACCAttempts`).

| Bank / Branch / Account | Trade account | Result |
|---|---|---|
| `012` / `600` / `123456` | 001234 | One card (771) |
| `010` / `800` / `554433` | 012345 | Two cards (025, 418) |
| `020` / `456` / `98765` | 054321 | No email (RecoverUserID → 427) |
| `011` / `042` / `777888` | 067890 | 552 inactive, 860 |
| `012` / `600` / `999000` | 098765 | TIK = Y |
| `031` / `123` / `112233` | 054321 **and** 067890 | **418** (joint account) |

## Test accounts

| Account | Cards (last 3) | Email | TIK | Scenario |
|---|---|---|---|---|
| `001234` | 771 | Y | N | One card — happy path for both actions |
| `012345` | 025, 418 | Y | N | Two cards — customer picks |
| `054321` | 309 | **N** | N | RecoverUserID → 427 |
| `067890` | 552 (**inactive**), 860 | Y | N | Pick 552 → 436 |
| `098765` | 144 | Y | **Y** | IRA / managed account |
| any other 6 digits | — | — | — | 404, uses an attempt |

Edit `app/data/accounts.json` to add more.

## FMR Swagger v1 (`/api/ExternalProvider/*`)

FMR's own contract (Swagger prototype, 20.10, untested on their side). Same accounts, attempts and outbox as the routes above; those older routes stay, because the Encore staging tools still call them.

| Endpoint | Request | Response |
|---|---|---|
| `POST /api/ExternalProvider/ValidateExToken` | `ExSessionID`, `mjwtToken` | `ExSessionID`, `RequestID`, `rjwtToken`, `Status`. **HTTP status = Status.** |
| `POST /api/ExternalProvider/AccountVerification` | `RequestID`, `rjwtToken` + `Account` **or** `Bank` + `Branch` + `BankAccount` | **Array** of `{RequestID, rjwtToken, Status, Email, Tik, FirstName, LastName, CardPermission: [{SubCard, Permission}]}` |
| `POST /api/ExternalProvider/ResetPassword` | `RequestID`, `rjwtToken`, `SubCard` | `RequestID`, `rjwtToken`, `Status`, `DeepLink` |
| `POST /api/ExternalProvider/ResetPasswordCard` | `RequestID`, `rjwtToken`, `DeeplinkID` | `RequestID`, `Status`, `CardID` |
| `POST /api/ExternalProvider/ForgotUsername` | `RequestID`, `rjwtToken`, `SubCard` | `RequestID`, `rjwtToken`, `Status` (the secure-message link goes to `/mock/outbox`) |
| `GET /api/ExternalProvider/SecureMessage/{token}` | – | HTML form (public, no API key) |
| `POST /api/ExternalProvider/SecureMessage/{token}/Unlock` | form `clientID` | HTML page with the username; 403 if the ID number is wrong |

HTTP status (from the Swagger): `ValidateExToken` returns the Status as the HTTP code. The other endpoints return **200**, or **401** when Status is 404 or 408 (`ResetPasswordCard`: **403** for 433). An invalid request is an **empty 400**. No `Error` / `Message` / `AttemptsLeft` fields.

Business Status values are not in the Swagger; the mock keeps the spec V10.1 ones: 200, 209 (secure message sent), 210 (deep link created), 404 not found, 408 session expired, 418, 423, 427, 433, 434, 435, 436.

`mjwtToken` values that simulate outcomes: `invalid` / `expired` → 400, `active-request` → 430, `duplicate` → 432, `no-card` → 436, `session-expired` → the session opens, later calls get 408.

`Permission` comes from the account's `permission_code`: 00 None, 01 FullExecution, 02 InformationOnly, 03 ExecuteTransactionsNoWithdrawal (our guess). Test ID numbers for the secure message: `id_number` in `app/data/accounts.json` (e.g. 001234 → `000000018`, username `dana.levi`).

## Mock-only helpers

| Endpoint | Purpose |
|---|---|
| `GET /health` | Health check (no API key needed) |
| `GET /mock/accounts` | List test accounts |
| `GET /mock/outbox` | SMS/emails "sent" so far |
| `POST /mock/reset` | Clear sessions, outbox and reload accounts |

State is in memory: restarting the service clears all sessions.

## Full flow with curl

```bash
B=http://localhost:8080
T=$(curl -s $B/ValidateExToken -H 'Content-Type: application/json' \
  -d '{"ExSessionID":"g-1","MToken":"eyJ.mock"}')
RID=$(echo $T | jq -r .RequestID); RT=$(echo $T | jq -r .RToken)

curl -s $B/AccountVerification -H 'Content-Type: application/json' \
  -d "{\"RequestID\":\"$RID\",\"RToken\":\"$RT\",\"Account\":\"012345\"}"

curl -s $B/ResetPassword -H 'Content-Type: application/json' \
  -d "{\"RequestID\":\"$RID\",\"RToken\":\"$RT\",\"UserId\":\"418\"}"
```

Add `-H 'X-API-Key: <key>'` if `MOCK_API_KEY` is set.

## Test only: session callback (`test/session-callback` branch)

Research endpoint for FMR Milestone 2 (customer authenticates in the middle of a chat). Not part of FMR.

- `POST /test/push-session` `{ "conversation_id": "<Encore conversation UUID>", "intent": "reset_password" }` (the mock plays Commbox + Meitav: it creates the MToken and ExSessionID itself; `mtoken` / `ex_session_id` are optional overrides)
  → returns `200` at once, then after `CALLBACK_DELAY_SECONDS` calls Encore `POST /api/v1/external/conversation`
  on that `conversation_id` with message `CALLBACK_MESSAGE` and `session_data: {MToken, ExSessionID}`.
- `GET /test/push-log` → status and response of each callback (needs `X-API-Key`; `/test/push-session` does not).

| Env var | Default | Purpose |
|---|---|---|
| `INSAIT_API_TOKEN` | *(empty)* | API token (`eat_...`) of the Encore test agent. Required; without it the endpoint returns `503`. |
| `INSAIT_BASE` | `https://api-platform.insait.io` | Encore API host. |
| `CALLBACK_DELAY_SECONDS` | `2` | Wait before the callback, so the agent's own turn has finished. |
| `CALLBACK_MESSAGE` | `[session update]` | Message text sent with the callback. |

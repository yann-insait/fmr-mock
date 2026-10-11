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
| 404 | `CARD_NOT_FOUND` | `UserId` isn't a card on the verified account |
| 409 | `ACCOUNT_NOT_VERIFIED` | Action called before AccountVerification |
| 423 | `TOO_MANY_ATTEMPTS` | Max wrong account numbers reached |
| 427 | `NO_EMAIL` | RecoverUserID on account with Email = N |
| 436 | `CARD_NOT_ACTIVE` | Selected card inactive |

**Real FMR codes:** only 209, 210, 427 and 436 come from the spec. 400/401/404/409/423 are placeholders until FMR confirms their error codes.

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

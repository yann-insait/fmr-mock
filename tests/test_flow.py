import pytest
from fastapi.testclient import TestClient

from app import main
from app.main import app

c = TestClient(app)


@pytest.fixture(autouse=True)
def clean():
    main.reset_state()


def login():
    r = c.post("/ValidateExToken", json={"ExSessionID": "g-1", "MToken": "eyJ.mock"})
    assert r.status_code == 200
    return r.json()


def auth(t, **kw):
    return {"RequestID": t["RequestID"], "RToken": t["RToken"], **kw}


def test_password_reset_one_card():
    t = login()
    r = c.post("/AccountVerification", json=auth(t, Account="001234"))
    assert r.status_code == 200 and len(r.json()["Cards"]) == 1
    r = c.post("/ResetPassword", json=auth(t, UserId="771"))
    assert r.status_code == 210 and r.json()["Status"] == 210
    assert c.get("/mock/outbox").json()["sent"][0]["type"] == "sms"


def test_username_two_cards():
    t = login()
    r = c.post("/AccountVerification", json=auth(t, Account="012345"))
    assert [x["Last3"] for x in r.json()["Cards"]] == ["025", "418"]
    assert c.post("/RecoverUserID", json=auth(t, UserId="418")).status_code == 209


def test_both_actions_same_token():
    t = login()
    c.post("/AccountVerification", json=auth(t, Account="001234"))
    assert c.post("/RecoverUserID", json=auth(t, UserId="771")).status_code == 209
    assert c.post("/ResetPassword", json=auth(t, UserId="771")).status_code == 210


def test_no_email_427():
    t = login()
    c.post("/AccountVerification", json=auth(t, Account="054321"))
    assert c.post("/RecoverUserID", json=auth(t, UserId="309")).status_code == 427


def test_inactive_card_436():
    t = login()
    c.post("/AccountVerification", json=auth(t, Account="067890"))
    assert c.post("/ResetPassword", json=auth(t, UserId="552")).status_code == 436
    assert c.post("/ResetPassword", json=auth(t, UserId="860")).status_code == 210


def test_invalid_mtoken():
    r = c.post("/ValidateExToken", json={"ExSessionID": "g", "MToken": "expired"})
    assert r.status_code == 401


def test_bad_rtoken():
    t = login()
    r = c.post("/AccountVerification", json={"RequestID": t["RequestID"], "RToken": "nope", "Account": "001234"})
    assert r.status_code == 401


def test_attempts_and_format():
    t = login()
    assert c.post("/AccountVerification", json=auth(t, Account="1234")).status_code == 400  # no attempt used
    for left in (2, 1, 0):
        r = c.post("/AccountVerification", json=auth(t, Account="999999"))
        assert r.status_code == 404 and r.json()["AttemptsLeft"] == left
    assert c.post("/AccountVerification", json=auth(t, Account="001234")).status_code == 423


def test_action_requires_verification():
    t = login()
    r = c.post("/ResetPassword", json=auth(t, UserId="771"))
    assert r.status_code == 433 and r.json()["Error"] == "NOT_IDENTIFIED"


def test_unknown_card_400():
    t = login()
    c.post("/AccountVerification", json=auth(t, Account="012345"))
    r = c.post("/ResetPassword", json=auth(t, UserId="999"))
    assert r.status_code == 400 and r.json()["Error"] == "CARD_NOT_FOUND"


def test_recover_ignores_card_status():
    # Spec: 436 is a ResetPassword check only; RecoverUserID on the inactive card still sends the email.
    t = login()
    c.post("/AccountVerification", json=auth(t, Account="067890"))
    assert c.post("/RecoverUserID", json=auth(t, UserId="552")).status_code == 209
    assert c.post("/ResetPassword", json=auth(t, UserId="552")).status_code == 436


def test_tokens_do_not_expire():
    t = login()
    assert "ExpiresIn" not in t and "RefreshToken" not in t


def test_validate_requires_both_fields():
    r = c.post("/ValidateExToken", json={"ExSessionID": "g"})
    assert r.status_code == 400 and "MToken" in r.json()["Fields"]


def test_missing_fields_400():
    r = c.post("/ResetPassword", json={"RequestID": "x"})
    assert r.status_code == 400 and "RToken" in r.json()["Fields"]


def test_status_in_body_mode(monkeypatch):
    monkeypatch.setattr(main, "STATUS_IN_HTTP", False)
    t = login()
    c.post("/AccountVerification", json=auth(t, Account="067890"))
    r = c.post("/ResetPassword", json=auth(t, UserId="552"))
    assert r.status_code == 200 and r.json()["Status"] == 436


def test_api_key(monkeypatch):
    monkeypatch.setattr(main, "API_KEY", "secret")
    assert c.get("/health").status_code == 200
    assert c.post("/ValidateExToken", json={"ExSessionID": "g", "MToken": "x"}).status_code == 401
    r = c.post("/ValidateExToken", json={"ExSessionID": "g", "MToken": "x"}, headers={"X-API-Key": "secret"})
    assert r.status_code == 200


def test_openapi_has_security_and_examples():
    spec = c.get("/openapi.json").json()
    assert "APIKeyHeader" in spec["components"]["securitySchemes"]
    assert "436" in spec["paths"]["/ResetPassword"]["post"]["responses"]

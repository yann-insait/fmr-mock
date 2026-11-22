"""FMR Swagger v1 routes (/api/ExternalProvider/*)."""
import pytest
from fastapi.testclient import TestClient

from app import main
from app.main import app

c = TestClient(app)
V1 = "/api/ExternalProvider"


@pytest.fixture(autouse=True)
def clean():
    main.reset_state()


def login(token="eyJ.mock"):
    r = c.post(f"{V1}/ValidateExToken", json={"ExSessionID": "g-1", "mjwtToken": token})
    assert r.status_code == 200 and r.json()["Status"] == 200
    return r.json()


def auth(t, **kw):
    return {"RequestID": t["RequestID"], "rjwtToken": t["rjwtToken"], **kw}


def verify(t, **kw):
    return c.post(f"{V1}/AccountVerification", json=auth(t, **kw))


def test_validate_ex_token_fields():
    t = login()
    assert set(t) == {"ExSessionID", "RequestID", "rjwtToken", "Status"} and t["ExSessionID"] == "g-1"


@pytest.mark.parametrize("token,status", [("invalid", 400), ("active-request", 430), ("duplicate", 432), ("no-card", 436)])
def test_validate_ex_token_http_equals_status(token, status):
    r = c.post(f"{V1}/ValidateExToken", json={"ExSessionID": "g", "mjwtToken": token})
    assert r.status_code == status and r.json()["Status"] == status


def test_invalid_request_is_empty_400():
    r = c.post(f"{V1}/ValidateExToken", json={"ExSessionID": "g"})
    assert r.status_code == 400 and r.content == b""


def test_account_verification_returns_array():
    t = login()
    r = verify(t, Account="012345")
    assert r.status_code == 200 and isinstance(r.json(), list) and len(r.json()) == 1
    item = r.json()[0]
    assert item["Status"] == 200 and item["Email"] == "Y" and item["Tik"] == "N"
    assert [x["SubCard"] for x in item["CardPermission"]] == ["025", "418"]
    assert item["CardPermission"][1]["Permission"] == "InformationOnly"


def test_not_found_is_http_401_status_404_then_423():
    t = login()
    for _ in range(main.MAX_VERIFY_ATTEMPTS):
        r = verify(t, Account="999999")
        assert r.status_code == 401 and r.json()[0]["Status"] == 404
    r = verify(t, Account="001234")
    assert r.status_code == 200 and r.json()[0]["Status"] == 423


def test_bank_details_use_branch_field():
    t = login()
    r = verify(t, Bank="010", Branch="800", BankAccount="554433")
    assert r.json()[0]["Status"] == 200
    assert verify(login(), Bank="031", Branch="123", BankAccount="112233").json()[0]["Status"] == 418
    assert verify(login(), Bank="012", Branch="600").json()[0]["Status"] == 434
    assert verify(login(), Account="001234", Bank="012", Branch="600", BankAccount="123456").json()[0]["Status"] == 435


def test_reset_password_deeplink():
    t = login()
    verify(t, Account="012345")
    r = c.post(f"{V1}/ResetPassword", json=auth(t, SubCard="418"))
    assert r.status_code == 200 and r.json()["Status"] == 210
    assert "DeeplinkID=" in r.json()["DeepLink"]


def test_reset_password_inactive_card_436():
    t = login()
    verify(t, Account="067890")
    r = c.post(f"{V1}/ResetPassword", json=auth(t, SubCard="552"))
    assert r.status_code == 200 and r.json()["Status"] == 436 and r.json()["DeepLink"] is None


def test_reset_password_before_verification_433():
    t = login()
    r = c.post(f"{V1}/ResetPassword", json=auth(t, SubCard="771"))
    assert r.status_code == 200 and r.json()["Status"] == 433


def test_forgot_username_secure_message():
    t = login()
    verify(t, Account="001234")
    r = c.post(f"{V1}/ForgotUsername", json=auth(t, SubCard="771"))
    assert r.status_code == 200 and r.json()["Status"] == 209
    assert main.OUTBOX[-1]["type"] == "secure_message"


def test_forgot_username_no_email_427():
    t = login()
    verify(t, Account="054321")
    r = c.post(f"{V1}/ForgotUsername", json=auth(t, SubCard="309"))
    assert r.status_code == 200 and r.json()["Status"] == 427


def test_session_expired_408():
    t = login("session-expired")
    r = verify(t, Account="001234")
    assert r.status_code == 401 and r.json()[0]["Status"] == 408


def test_bad_token_is_404():
    t = login()
    r = c.post(f"{V1}/AccountVerification", json={"RequestID": t["RequestID"], "rjwtToken": "nope", "Account": "001234"})
    assert r.status_code == 401 and r.json()[0]["Status"] == 404


def test_only_used_routes_remain():
    paths = set(c.get("/openapi.json").json()["paths"])
    assert paths == {f"{V1}/ValidateExToken", f"{V1}/AccountVerification", f"{V1}/ResetPassword",
                     f"{V1}/ForgotUsername", "/api/formemail/send-form-by-email"}


def test_v1_needs_api_key(monkeypatch):
    monkeypatch.setattr(main, "API_KEY", "secret")
    assert c.get("/health").status_code == 200
    assert c.post(f"{V1}/ValidateExToken", json={"ExSessionID": "g", "mjwtToken": "x"}).status_code == 401


def test_openapi_lists_v1_bodies():
    spec = c.get("/openapi.json").json()
    body = spec["paths"][f"{V1}/AccountVerification"]["post"]["requestBody"]["content"]["application/json"]["schema"]
    assert "Branch" in body["properties"] and "rjwtToken" in body["properties"]

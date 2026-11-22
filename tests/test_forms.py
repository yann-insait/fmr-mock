"""send-form-by-email mock (kubiot / nispah5)."""
import pytest
from fastapi.testclient import TestClient

from app import main
from app.main import app

c = TestClient(app)


@pytest.fixture(autouse=True)
def clean():
    main.reset_state()


KUBIOT = {"email": "customer@example.com", "formName": "kubiot",
          "data": {"new_filldate": "20/11/2025", "fullName": "ישראל ישראלי", "idNumber": "012345678",
                   "employeName": "מיטב", "HP": "516583036", "monthlyIncome": "3,000",
                   "product": "פנסיה מקיפה", "salaryCategory": "משכורת בסיסית", "ma": "163",
                   "ddovedPayment": "6%", "ddcompensation": "6%", "ddmaasikPayment": "6.5%", "insureIncome": "2,000"}}
NISPAH5 = {"email": "customer@example.com", "formName": "nispah5",
           "data": {"emploeeName": "ישראל ישראלי", "idNumber": "012345678", "maasikName": "מיטב",
                    "HP": "516583036", "product": "מיטב פנסיה מקיפה", "accountNum": "18-012345678"}}
FORM_URL = "/api/formemail/send-form-by-email"


def test_send_form_kubiot():
    r = c.post(FORM_URL, json=KUBIOT)
    assert r.status_code == 200 and r.json()["FormName"] == "kubiot" and r.json()["ReferenceID"]
    sent = main.OUTBOX
    assert sent[0]["type"] == "form_email" and sent[0]["form_name"] == "kubiot"
    assert sent[0]["data"]["HP"] == "516583036" and "product2" not in sent[0]["data"]


def test_send_form_kubiot_second_product():
    data = {**KUBIOT["data"], "product2": "השתלמות", "salaryCategory2": "משכורת בסיסית", "ma2": "880",
            "ddovedPayment2": "2.5%", "ddmaasikPayment2": "7.5%", "insureIncome2": "3,000"}
    assert c.post(FORM_URL, json={**KUBIOT, "data": data}).status_code == 200
    assert main.OUTBOX[0]["data"]["product2"] == "השתלמות"


def test_send_form_nispah5():
    r = c.post(FORM_URL, json=NISPAH5)
    assert r.status_code == 200 and r.json()["FormName"] == "nispah5"


def test_send_form_failed():
    r = c.post(FORM_URL, json={**NISPAH5, "email": "customer@fail.com"})
    assert r.status_code == 500 and r.json()["Error"] == "FORM_SEND_FAILED"
    assert main.OUTBOX == []


def test_send_form_missing_data_field():
    data = {k: v for k, v in NISPAH5["data"].items() if k != "HP"}
    r = c.post(FORM_URL, json={**NISPAH5, "data": data})
    assert r.status_code == 400 and any(f.endswith("HP") for f in r.json()["Fields"])


def test_send_form_wrong_shape_for_form_name():
    # nispah5 data under the kubiot formName must be rejected
    r = c.post(FORM_URL, json={**NISPAH5, "formName": "kubiot"})
    assert r.status_code == 400


def test_send_form_unknown_form_name():
    r = c.post(FORM_URL, json={**NISPAH5, "formName": "other"})
    assert r.status_code == 400

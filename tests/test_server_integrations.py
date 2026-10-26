"""Server-wide MISP / VirusTotal defaults (Administration -> MISP & VirusTotal) and how cases override them."""
import json

import pytest
from fastapi.testclient import TestClient

from tests.test_app import FIXTURE, login  # sets the test environment first
from tests.test_integrations import calls, configure, url  # noqa: F401  (fixture)
from app import integrations as I
from app.db import db
from app.main import app

SRV_URL = "https://misp.corp.example"
SRV_MISP_KEY = "srv-MISP-SECRET-0123456789"
SRV_VT_KEY = "srv-VT-SECRET-0123456789"
CASE_URL = "https://other-misp.example"
CASE_MISP_KEY = "case-MISP-SECRET-abcdef"
CASE_VT_KEY = "case-VT-SECRET-abcdef"


@pytest.fixture(scope="module")
def admin():
    with TestClient(app) as c:
        yield login(c)


@pytest.fixture(autouse=True)
def clean_settings():
    with db() as conn:
        conn.execute("DELETE FROM settings")
    yield
    with db() as conn:
        conn.execute("DELETE FROM settings")


@pytest.fixture()
def case(admin):
    fx = json.loads(json.dumps(FIXTURE))
    fx["case_id"] = "SRV-1"
    fx["malware"][0]["md5"] = "a" * 64
    r = admin.post("/api/cases/import", content=json.dumps(fx))
    assert r.status_code == 200, r.text
    return r.json()["id"]


def server(admin, **vals):
    r = admin.patch("/api/settings/integrations", json=vals)
    assert r.status_code == 200, r.text
    return r.json()


def integ(admin, case):
    return admin.get(f"/api/cases/{case}/integrations").json()


def test_admin_only_and_keys_write_only(admin):
    out = server(admin, misp_url=SRV_URL + "/", misp_apikey=SRV_MISP_KEY, vt_apikey=SRV_VT_KEY)
    assert out["misp_url"] == SRV_URL and out["secrets_set"] == {"misp_apikey": True, "vt_apikey": True}
    raw = json.dumps(admin.get("/api/settings/integrations").json())
    assert SRV_MISP_KEY not in raw and SRV_VT_KEY not in raw
    with db() as conn:                                            # encrypted at rest
        stored = {r["k"]: r["v"] for r in conn.execute("SELECT k, v FROM settings")}
    assert stored["misp_apikey"].startswith("v1:") and SRV_MISP_KEY not in json.dumps(stored)
    # editors, viewers and API keys cannot see or change them
    admin.post("/api/users", json={"username": "srv-ed", "password": "a-long-password-123", "role": "user",
                                   "must_change_password": False})
    with TestClient(app) as c:
        r = c.post("/api/login", json={"username": "srv-ed", "password": "a-long-password-123"})
        c.headers["X-CSRF-Token"] = r.json()["csrf"]
        assert c.get("/api/settings/integrations").status_code == 403
        assert c.patch("/api/settings/integrations", json={"misp_url": "https://x.example"}).status_code == 403
    key = admin.post("/api/keys", json={"name": "srv-rw", "profile": "readwrite"}).json()["secret"]
    assert TestClient(app).get("/api/settings/integrations",
                               headers={"Authorization": f"Bearer {key}"}).status_code in (401, 403)


def test_url_rules_and_removal(admin):
    r = admin.patch("/api/settings/integrations", json={"misp_url": "http://misp.example"})
    assert r.status_code == 422 and "https" in r.text
    assert admin.patch("/api/settings/integrations", json={"misp_url": "https://u:p@misp.example"}).status_code == 422
    assert admin.patch("/api/settings/integrations", json={"bogus": 1}).status_code == 422
    server(admin, misp_url=SRV_URL, misp_apikey=SRV_MISP_KEY)
    out = server(admin, misp_apikey="", misp_url="")
    assert out["misp_url"] == "" and out["secrets_set"]["misp_apikey"] is False


def test_case_uses_server_misp_with_its_own_event(admin, case, calls):
    server(admin, misp_url=SRV_URL, misp_apikey=SRV_MISP_KEY)
    st = integ(admin, case)["misp"]
    assert st["configured"] is False and st["missing"] == ["MISP event ID"] and st["source"] == "server"
    assert admin.get(f"/api/cases/{case}").json()["meta"]["use_server_misp"] is True
    configure(admin, case, mispeventid="42")
    st = integ(admin, case)["misp"]
    assert st["configured"] and st["source"] == "server" and st["server"] == SRV_URL and st["event_id"] == "42"
    calls.answers[SRV_URL] = (200, {"Attribute": [{"id": "1"}]})
    r = admin.post(url(case, "network_indicators", 1, "send-to-misp"), json={})
    assert r.status_code == 200, r.text
    assert calls[-1]["url"] == f"{SRV_URL}/attributes/add/42" and calls[-1]["headers"]["Authorization"] == SRV_MISP_KEY


def test_switch_on_ignores_the_case_values(admin, case, calls):
    """While 'Use the server-wide MISP' is on, the case's own URL/key are kept but not used."""
    server(admin, misp_url=SRV_URL, misp_apikey=SRV_MISP_KEY)
    configure(admin, case, mispserver=CASE_URL, mispapikey=CASE_MISP_KEY, mispeventid="7", use_server_misp=True)
    st = integ(admin, case)["misp"]
    assert st["configured"] and st["source"] == "server" and st["server"] == SRV_URL
    meta = admin.get(f"/api/cases/{case}").json()["meta"]
    assert meta["mispserver"] == CASE_URL and meta["secrets_set"]["mispapikey"] is True        # kept
    configure(admin, case, use_server_misp=False)                                              # used again
    st = integ(admin, case)["misp"]
    assert st["configured"] and st["source"] == "case" and st["server"] == CASE_URL


def test_server_key_never_sent_to_a_case_url(admin, case, calls):
    """A case with its own URL but no key of its own must not borrow the server-wide key (it would leak)."""
    server(admin, misp_url=SRV_URL, misp_apikey=SRV_MISP_KEY)
    configure(admin, case, mispserver=CASE_URL, mispeventid="7")
    st = integ(admin, case)["misp"]
    assert st["configured"] is False and st["source"] == "case" and st["missing"] == ["MISP API key"]
    assert admin.post(url(case, "network_indicators", 1, "send-to-misp"), json={}).status_code == 400
    assert admin.post(f"/api/cases/{case}/integrations/misp/test").status_code == 400
    assert not calls                                                  # nothing left the server
    configure(admin, case, mispapikey=CASE_MISP_KEY)
    calls.answers[CASE_URL] = (200, {"Attribute": [{"id": "1"}]})
    assert admin.post(url(case, "network_indicators", 1, "send-to-misp"), json={}).status_code == 200
    assert calls[-1]["url"].startswith(CASE_URL) and calls[-1]["headers"]["Authorization"] == CASE_MISP_KEY
    assert all(SRV_MISP_KEY not in json.dumps(c["headers"]) for c in calls)


def test_server_wide_misp_may_use_private_range(admin, case, calls, monkeypatch):
    """SSRF boundary (CWE-918): MISP_ALLOW_PRIVATE is the admin's trust in the server-wide MISP, so the
    server-wide path carries allow_private through; an editor-supplied case URL does not (see
    test_integrations.test_send_to_misp and test_private_case_misp_refused_even_when_private_allowed)."""
    from app.config import settings
    monkeypatch.setattr(settings, "misp_allow_private", True)
    server(admin, misp_url=SRV_URL, misp_apikey=SRV_MISP_KEY)
    configure(admin, case, mispeventid="7", use_server_misp=True)
    calls.answers[SRV_URL] = (200, {"Attribute": [{"id": "1"}]})
    assert admin.post(url(case, "network_indicators", 1, "send-to-misp"), json={}).status_code == 200
    assert calls[-1]["url"].startswith(SRV_URL) and calls[-1]["allow_private"] is True


def test_case_key_without_url_is_an_incomplete_override(admin, case, calls):
    server(admin, misp_url=SRV_URL, misp_apikey=SRV_MISP_KEY)
    configure(admin, case, mispapikey=CASE_MISP_KEY, mispeventid="7")
    st = integ(admin, case)["misp"]
    assert st["configured"] is False and st["missing"] == ["MISP server URL"]


def test_opt_out_switches(admin, case, calls):
    server(admin, misp_url=SRV_URL, misp_apikey=SRV_MISP_KEY, vt_apikey=SRV_VT_KEY)
    info = admin.get(f"/api/cases/{case}").json()["meta"]
    assert info["use_server_misp"] is True and info["use_server_vt"] is True      # default on
    configure(admin, case, mispeventid="42", use_server_misp=False, use_server_vt=False)
    st = integ(admin, case)
    assert st["misp"]["configured"] is False and st["misp"]["source"] == "case"
    assert st["misp"]["missing"] == ["MISP server URL", "MISP API key"]
    assert st["virustotal"]["configured"] is False
    r = admin.post(url(case, "malware", 1, "check-virustotal"))
    assert r.status_code == 400 and not calls
    configure(admin, case, use_server_misp=True, use_server_vt=True)
    assert integ(admin, case)["misp"]["configured"] and integ(admin, case)["virustotal"]["source"] == "server"


def test_virustotal_case_key_wins_then_server(admin, case, calls):
    server(admin, vt_apikey=SRV_VT_KEY)
    calls.answers["https://www.virustotal.com/"] = (200, {"data": {"attributes": {"last_analysis_stats": {
        "malicious": 0, "suspicious": 0, "harmless": 1, "undetected": 60}}}})
    assert admin.post(url(case, "malware", 1, "check-virustotal")).status_code == 200
    assert calls[-1]["headers"]["x-apikey"] == SRV_VT_KEY
    configure(admin, case, vtapikey=CASE_VT_KEY, use_server_vt=True)                     # stored, not used
    assert admin.post(url(case, "malware", 1, "check-virustotal")).status_code == 200
    assert calls[-1]["headers"]["x-apikey"] == SRV_VT_KEY
    configure(admin, case, use_server_vt=False)
    assert admin.post(url(case, "malware", 1, "check-virustotal")).status_code == 200
    assert calls[-1]["headers"]["x-apikey"] == CASE_VT_KEY
    assert admin.post(f"/api/cases/{case}/integrations/virustotal/test").status_code == 200
    assert calls[-1]["headers"]["x-apikey"] == CASE_VT_KEY


def test_fox_never_carries_server_settings_or_switches(admin, case):
    server(admin, misp_url=SRV_URL, misp_apikey=SRV_MISP_KEY, vt_apikey=SRV_VT_KEY)
    configure(admin, case, mispeventid="42", use_server_vt=False)
    raw = admin.get(f"/api/cases/{case}/export").content.decode()
    doc = json.loads(raw)
    assert doc["mispserver"] == "" and doc["mispeventid"] == "42" and doc["mispapikey"] == doc["vtapikey"] == ""
    assert SRV_URL not in raw and "use_server" not in raw
    for ext in ("export.xlsx", "export.pdf", "export.tex"):
        body = admin.get(f"/api/cases/{case}/{ext}").content
        assert SRV_MISP_KEY.encode() not in body and SRV_VT_KEY.encode() not in body


def test_import_adopts_server_url_and_ignores_switches_in_file(admin):
    server(admin, misp_url=SRV_URL, misp_apikey=SRV_MISP_KEY)
    fx = json.loads(json.dumps(FIXTURE))
    fx.update(case_id="SRV-2", mispserver=SRV_URL + "/", mispeventid="9", use_server_misp=False)
    r = admin.post("/api/cases/import", content=json.dumps(fx))
    assert r.status_code == 200 and any("server-wide MISP" in w for w in r.json()["warnings"])
    cid = r.json()["id"]
    meta = admin.get(f"/api/cases/{cid}").json()["meta"]
    assert meta["mispserver"] == "" and meta["mispeventid"] == "9" and meta["use_server_misp"] is True
    assert integ(admin, cid)["misp"]["configured"] and integ(admin, cid)["misp"]["source"] == "server"
    # another MISP in the file: the case uses its own MISP (switch off; it then needs the case's own key)
    fx.update(case_id="SRV-3", mispserver=CASE_URL)
    r = admin.post("/api/cases/import", content=json.dumps(fx))
    assert any("own MISP server" in w for w in r.json()["warnings"])
    meta = admin.get(f"/api/cases/{r.json()['id']}").json()["meta"]
    assert meta["mispserver"] == CASE_URL and meta["use_server_misp"] is False and meta["use_server_vt"] is True
    assert integ(admin, r.json()["id"])["misp"]["missing"] == ["MISP API key"]


def test_replace_keeps_switches(admin, case):
    configure(admin, case, use_server_misp=False)
    fox = admin.get(f"/api/cases/{case}/export").content
    assert admin.post(f"/api/cases/{case}/replace", content=fox).status_code == 200
    assert admin.get(f"/api/cases/{case}").json()["meta"]["use_server_misp"] is False


def test_cases_stored_before_the_switches(admin, case):
    """No switch stored: on, unless the case already has its own MISP / VirusTotal values (kept in use)."""
    def strip(**extra):
        with db() as conn:
            meta = json.loads(conn.execute("SELECT meta FROM cases WHERE id=?", (case,)).fetchone()[0])
            for k in ("use_server_misp", "use_server_vt"):
                meta.pop(k, None)
            meta.update(extra)
            conn.execute("UPDATE cases SET meta=? WHERE id=?", (json.dumps(meta), case))
        return admin.get(f"/api/cases/{case}").json()["meta"]
    out = strip()
    assert out["use_server_misp"] is True and out["use_server_vt"] is True
    out = strip(mispserver=CASE_URL)
    assert out["use_server_misp"] is False and out["use_server_vt"] is True


def test_server_connection_tests(admin, calls):
    assert admin.post("/api/settings/integrations/misp/test").status_code == 400          # nothing configured
    server(admin, misp_url=SRV_URL, misp_apikey=SRV_MISP_KEY, vt_apikey=SRV_VT_KEY)
    calls.answers[SRV_URL] = (200, {"version": "2.4.200"})
    r = admin.post("/api/settings/integrations/misp/test")
    assert r.status_code == 200 and "2.4.200" in r.json()["message"]
    assert calls[-1]["url"] == f"{SRV_URL}/servers/getVersion" and calls[-1]["headers"]["Authorization"] == SRV_MISP_KEY
    calls.answers["https://www.virustotal.com/"] = (404, None)
    assert admin.post("/api/settings/integrations/virustotal/test").status_code == 200
    assert calls[-1]["headers"]["x-apikey"] == SRV_VT_KEY

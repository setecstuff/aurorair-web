"""Row actions (to timeline / to hosts), MISP and VirusTotal integrations, and API-key privacy."""
import io
import json
import zipfile

import pytest
from fastapi.testclient import TestClient

from tests.test_app import FIXTURE, login  # sets the test environment first
from app import integrations as I
from app.config import settings
from app.main import app

VT_KEY = "vt-SECRET-0123456789abcdef"
MISP_KEY = "misp-SECRET-abcdefghijklmnop"
SHA256 = "a" * 64


@pytest.fixture(scope="module")
def admin():
    with TestClient(app) as c:
        yield login(c)


@pytest.fixture()
def case(admin):
    fx = json.loads(json.dumps(FIXTURE))
    fx["case_id"] = "INT-1"
    fx["malware"][0].update(path_on_disk="C:\\Windows\\Temp", creation_date="2026-01-01 09:00:00", notes="dropper")
    fx["exfiltration"] = [{"recid": 1, "w2ui": {}, "exfiltime": "2026-01-02 03:04:05", "stagingsystem": "host-a",
                           "exfil_to": "evil.example", "filename": "loot.7z", "notes": "via https"}]
    r = admin.post("/api/cases/import", content=json.dumps(fx))
    assert r.status_code == 200, r.text
    return r.json()["id"]


@pytest.fixture()
def calls(monkeypatch):
    """Fake upstream: records every outbound request instead of touching the network."""
    class Log(list):
        answers: dict
    log = Log()
    answers = {}

    def fake(method, url, headers, body=None, guard=True, verify=True, allow_private=None):
        log.append({"method": method, "url": url, "headers": headers, "body": body, "guard": guard,
                    "allow_private": allow_private})
        for prefix, ans in answers.items():
            if url.startswith(prefix):
                return ans(url, body) if callable(ans) else ans
        return 500, None
    monkeypatch.setattr(I, "_request", fake)
    log.answers = answers
    return log


def configure(admin, case, **vals):
    """Case Details. Setting the case's own MISP / VirusTotal values also switches the server-wide ones off (as a
    user does in the UI, where those fields are locked while the switch is on), unless the test says otherwise."""
    if {"mispserver", "mispapikey"} & set(vals):
        vals.setdefault("use_server_misp", False)
    if "vtapikey" in vals:
        vals.setdefault("use_server_vt", False)
    r = admin.patch(f"/api/cases/{case}", json={"changes": vals})
    assert r.status_code == 200, r.text


def url(case, section, recid, action):
    return f"/api/cases/{case}/sections/{section}/{recid}/{action}"


# ------------------------------------------------------------------ to timeline / to hosts

def test_investigated_system_to_timeline(admin, case):
    admin.patch(f"/api/cases/{case}/sections/investigated_systems/1",
                json={"changes": {"first_compromise": "2026-01-01 08:00:00"}, "version": 1})
    r = admin.post(url(case, "investigated_systems", 1, "to-timeline"))
    assert r.status_code == 200, r.text
    d = r.json()["data"]
    assert (d["event_host"], d["event_data"], d["date_time"], d["followup"]) == \
        ("host-a", "x", "2026-01-01 08:00:00", True)
    assert admin.get(f"/api/cases/{case}/audit?limit=2").json()[0]["action"] == "to_timeline"


def test_malware_to_timeline_and_hosts(admin, case):
    d = admin.post(url(case, "malware", 1, "to-timeline")).json()["data"]
    assert d["event_type"] == "Malware" and d["date_time"] == "2026-01-01 09:00:00"
    assert d["event_data"] == "Malware created (C:\\Windows\\Temp\\bad.exe). dropper"
    # host-a is already an investigated system in the fixture -> refused like Aurora does
    r = admin.post(url(case, "malware", 1, "to-investigated-systems"))
    assert r.status_code == 409 and "already" in r.json()["detail"]
    # new malware on another host -> added with verdict from the case lookup ("Infected")
    admin.post(f"/api/cases/{case}/sections/systems", json={"data": {"text": "host-b"}})
    m = admin.post(f"/api/cases/{case}/sections/malware",
                   json={"data": {"text": "x.dll", "hostname": "host-b", "creation_date": "2026-01-03 00:00:00"}})
    r = admin.post(url(case, "malware", m.json()["recid"], "to-investigated-systems"))
    assert r.status_code == 200, r.text
    d = r.json()["data"]
    assert (d["hostname"], d["verdict"], d["first_compromise"]) == ("host-b", "Infected", "2026-01-03 00:00:00")


def test_exfiltration_to_timeline(admin, case):
    d = admin.post(url(case, "exfiltration", 1, "to-timeline")).json()["data"]
    assert (d["event_host"], d["event_source_host"], d["direction"], d["event_type"]) == \
        ("host-a", "evil.example", "->", "Exfil")
    assert d["event_data"] == "loot.7z exfiltrated." and d["notes"] == "via https"
    assert d["date_time"] == "2026-01-02 03:04:05"


def test_actions_only_where_aurora_has_them(admin, case):
    assert admin.post(url(case, "timeline", 1, "to-timeline")).status_code == 400
    assert admin.post(url(case, "network_indicators", 1, "check-virustotal")).status_code == 400
    assert admin.post(url(case, "exfiltration", 1, "send-to-misp"), json={}).status_code == 400


def test_viewer_cannot_run_actions(admin, case):
    uid = admin.post("/api/users", json={"username": "watcher", "password": "watcher-password-1", "role": "user",
                                         "must_change_password": False}).json()["id"]
    assert admin.post(f"/api/cases/{case}/members", json={"user_id": uid, "permission": "viewer"}).status_code == 200
    with TestClient(app) as v:
        login(v, "watcher", "watcher-password-1")
        assert v.post(url(case, "malware", 1, "to-timeline")).status_code == 403
        assert v.post(url(case, "malware", 1, "check-virustotal")).status_code == 403
        assert v.get(url(case, "malware", 1, "actions")).status_code == 200


# ------------------------------------------------------------------ VirusTotal

def test_vt_requires_key_and_hash(admin, case, calls):
    acts = {a["action"]: a for a in admin.get(url(case, "malware", 1, "actions")).json()["actions"]}
    assert not acts["check_virustotal"]["available"] and "VirusTotal key" in acts["check_virustotal"]["reason"]
    assert admin.post(url(case, "malware", 1, "check-virustotal")).status_code == 400
    configure(admin, case, vtapikey=VT_KEY)
    m = admin.post(f"/api/cases/{case}/sections/malware", json={"data": {"text": "nohash.exe"}}).json()
    acts = {a["action"]: a for a in admin.get(url(case, "malware", m["recid"], "actions")).json()["actions"]}
    assert not acts["check_virustotal"]["available"] and "hash" in acts["check_virustotal"]["reason"]
    assert admin.post(url(case, "malware", m["recid"], "check-virustotal")).status_code == 400
    assert calls == []                                    # nothing left the server


@pytest.mark.parametrize("upstream,verdict", [
    ((200, {"data": {"attributes": {"sha256": SHA256, "last_analysis_stats": {"malicious": 3, "undetected": 60}}}}),
     "infected"),
    ((200, {"data": {"attributes": {"last_analysis_stats": {"malicious": 0, "harmless": 5, "undetected": 60}}}}),
     "clean"),
    ((404, {"error": {"code": "NotFoundError"}}), "noresult"),
])
def test_vt_verdict_stored(admin, case, calls, upstream, verdict):
    configure(admin, case, vtapikey=VT_KEY)
    calls.answers["https://www.virustotal.com/api/v3/files/"] = upstream
    r = admin.post(url(case, "malware", 1, "check-virustotal"))
    assert r.status_code == 200, r.text
    assert r.json()["verdict"] == verdict and r.json()["record"]["data"]["vt"] == verdict
    assert admin.get(f"/api/cases/{case}/sections/malware/1").json()["data"]["vt"] == verdict
    c = calls[-1]
    assert c["url"] == "https://www.virustotal.com/api/v3/files/d41d8cd98f00b204e9800998ecf8427e"
    assert c["headers"] == {"x-apikey": VT_KEY}
    log = admin.get(f"/api/cases/{case}/audit?limit=1").json()[0]
    assert log["action"] == "check_virustotal" and VT_KEY not in json.dumps(log)


def test_vt_errors(admin, case, calls):
    configure(admin, case, vtapikey=VT_KEY)
    calls.answers["https://www.virustotal.com/"] = (429, {})
    assert admin.post(url(case, "malware", 1, "check-virustotal")).status_code == 429
    calls.answers["https://www.virustotal.com/"] = (401, {})
    r = admin.post(url(case, "malware", 1, "check-virustotal"))
    assert r.status_code == 400 and VT_KEY not in r.text


def test_vt_field_still_read_only_for_clients(admin, case):
    r = admin.patch(f"/api/cases/{case}/sections/malware/1", json={"changes": {"vt": "clean"}, "version": 1})
    assert r.status_code == 422


# ------------------------------------------------------------------ MISP

def test_misp_requires_configuration(admin, case, calls):
    acts = {a["action"]: a for a in admin.get(url(case, "network_indicators", 1, "actions")).json()["actions"]}
    assert not acts["send_to_misp"]["available"] and "MISP" in acts["send_to_misp"]["reason"]
    assert admin.post(url(case, "network_indicators", 1, "send-to-misp"), json={}).status_code == 400
    configure(admin, case, mispserver="https://misp.example.org", mispeventid="42")   # key still missing
    r = admin.post(url(case, "network_indicators", 1, "send-to-misp"), json={})
    assert r.status_code == 400 and "MISP API key" in r.json()["detail"]
    assert calls == []


def test_misp_proposals_like_aurora(admin, case):
    net = admin.get(url(case, "network_indicators", 1, "misp-attributes")).json()["attributes"]
    assert [(a["aurora_field"], a["type"], a["value"]) for a in net] == [
        ("Domain Name", "domain", "evil.example"), ("IP", "ip-dst", "10.0.0.1"),
        ("Domain IP", "domain|ip", "evil.example|10.0.0.1"), ("IP Port", "ip-dst|port", "10.0.0.1|443")]
    mal = admin.get(url(case, "malware", 1, "misp-attributes")).json()["attributes"]
    assert [(a["type"], a["value"]) for a in mal] == [
        ("filename", "bad.exe"), ("filename", "C:\\Windows\\Temp\\bad.exe"),
        ("md5", "d41d8cd98f00b204e9800998ecf8427e")]


def test_send_to_misp(admin, case, calls):
    configure(admin, case, mispserver="https://misp.example.org/", mispeventid="42", mispapikey=MISP_KEY)
    calls.answers["https://misp.example.org/attributes/add/42"] = lambda u, body: (
        200, {"Attribute": [{"id": str(i)} for i, _ in enumerate(body)]})
    r = admin.post(url(case, "network_indicators", 1, "send-to-misp"), json={"attributes": [
        {"type": "ip-src", "value": "10.0.0.1", "comment": "C2"},
        {"type": "domain", "value": "evil.example"}]})
    assert r.status_code == 200, r.text
    assert r.json()["added"] == 2
    c = calls[-1]
    assert c["method"] == "POST" and c["headers"] == {"Authorization": MISP_KEY} and c["guard"] is True
    assert c["allow_private"] is False          # editor-supplied case URL: private ranges not allowed (CWE-918)
    assert c["body"] == [{"type": "ip-src", "value": "10.0.0.1", "comment": "C2"},
                         {"type": "domain", "value": "evil.example", "comment": ""}]
    log = admin.get(f"/api/cases/{case}/audit?limit=1").json()[0]
    assert log["action"] == "send_to_misp" and MISP_KEY not in json.dumps(log)


def test_send_to_misp_only_record_values(admin, case, calls):
    configure(admin, case, mispserver="https://misp.example.org", mispeventid="42", mispapikey=MISP_KEY)
    for bad in ([{"type": "domain", "value": "something-else.example"}],
                [{"type": "not-a-type", "value": "evil.example"}],
                [{"type": "domain", "value": "evil.example", "comment": "a\x00b"}],
                [{"type": "domain", "value": "evil.example", "to_ids": True}]):
        r = admin.post(url(case, "network_indicators", 1, "send-to-misp"), json={"attributes": bad})
        assert r.status_code in (400, 422), (bad, r.text)
    assert calls == []


def test_misp_url_rules(admin, case, calls):
    configure(admin, case, mispserver="http://misp.example.org", mispeventid="42", mispapikey=MISP_KEY)
    r = admin.post(f"/api/cases/{case}/integrations/misp/test")
    assert r.status_code == 400 and "https" in r.json()["detail"]
    configure(admin, case, mispserver="https://misp.example.org", mispeventid="42; DROP")
    assert admin.post(f"/api/cases/{case}/integrations/misp/test").status_code == 400
    assert calls == []


@pytest.mark.parametrize("ip", ["127.0.0.1", "169.254.169.254", "::1", "0.0.0.0", "224.0.0.1"])
def test_ssrf_guard(monkeypatch, ip):
    """Loopback / link-local (incl. cloud metadata) / multicast / unspecified are always refused, even with
    MISP_ALLOW_PRIVATE on. _resolve is a pre-connection check (returns None); the connection re-resolves."""
    monkeypatch.setattr(I.socket, "getaddrinfo", lambda *a, **k: [(None, None, None, "", (ip, 443))])
    monkeypatch.setattr(settings, "misp_allow_private", True)
    with pytest.raises(I.IntegrationError):
        I._resolve("misp.example.org", 443, guard=True, allow_private=True)
    assert I._resolve("misp.example.org", 443, guard=False, allow_private=True) is None   # allowlisted host: no check


def test_private_misp_allowed_by_default(monkeypatch):
    monkeypatch.setattr(I.socket, "getaddrinfo", lambda *a, **k: [(None, None, None, "", ("10.1.2.3", 443))])
    monkeypatch.setattr(settings, "misp_allow_private", True)
    assert I._resolve("misp.corp.lan", 443, guard=True, allow_private=True) is None       # internal MISP allowed


@pytest.mark.parametrize("ip", ["10.1.2.3", "192.168.1.9", "172.16.0.1", "fd00::1"])
def test_private_misp_refused_when_disabled(monkeypatch, ip):
    monkeypatch.setattr(I.socket, "getaddrinfo", lambda *a, **k: [(None, None, None, "", (ip, 443))])
    monkeypatch.setattr(settings, "misp_allow_private", False)
    with pytest.raises(I.IntegrationError) as e:
        I._resolve("misp.corp.lan", 443, guard=True, allow_private=False)
    assert "private" in str(e.value) and "MISP_ALLOW_PRIVATE" in str(e.value)


@pytest.mark.parametrize("ip", ["10.1.2.3", "192.168.1.9", "172.16.0.1", "fd00::1"])
def test_private_case_misp_refused_even_when_private_allowed(monkeypatch, ip):
    """SSRF (CWE-918): MISP_ALLOW_PRIVATE is the admin's trust in the server-wide MISP; an editor-supplied case
    URL (allow_private=False) may not reach a private range even while MISP_ALLOW_PRIVATE is on. The remediation
    points at the allowlist, not at turning the global flag on."""
    monkeypatch.setattr(I.socket, "getaddrinfo", lambda *a, **k: [(None, None, None, "", (ip, 443))])
    monkeypatch.setattr(settings, "misp_allow_private", True)
    with pytest.raises(I.IntegrationError) as e:
        I._resolve("misp.corp.lan", 443, guard=True, allow_private=False)
    msg = str(e.value)
    assert "private" in msg and "MISP_ALLOWED_HOSTS" in msg and "MISP_ALLOW_PRIVATE=true" not in msg


def test_metadata_refused_even_when_private_allowed(monkeypatch):
    monkeypatch.setattr(I.socket, "getaddrinfo", lambda *a, **k: [(None, None, None, "", ("169.254.169.254", 443))])
    monkeypatch.setattr(settings, "misp_allow_private", True)              # still blocked: link-local
    with pytest.raises(I.IntegrationError) as e:
        I._resolve("metadata.example", 443, guard=True, allow_private=True)
    assert "metadata" in str(e.value)


def test_misp_test_connection(admin, case, calls):
    configure(admin, case, mispserver="https://misp.example.org", mispeventid="42", mispapikey=MISP_KEY)
    calls.answers["https://misp.example.org/events/view/42"] = (200, {"Event": {"info": "IR-608 C2"}})
    r = admin.post(f"/api/cases/{case}/integrations/misp/test")
    assert r.status_code == 200 and r.json()["event_info"] == "IR-608 C2"
    calls.answers["https://misp.example.org/events/view/42"] = (403, {"message": "Authentication failed."})
    r = admin.post(f"/api/cases/{case}/integrations/misp/test")
    assert r.status_code == 400 and MISP_KEY not in r.text


# ------------------------------------------------------------------ API keys never leave the server

def test_api_keys_never_returned_or_exported(admin, case):
    configure(admin, case, mispserver="https://misp.example.org", mispeventid="42", mispapikey=MISP_KEY,
              vtapikey=VT_KEY)
    info = admin.get(f"/api/cases/{case}").json()
    assert info["meta"]["mispapikey"] == "" and info["meta"]["vtapikey"] == ""
    assert info["meta"]["secrets_set"] == {"mispapikey": True, "vtapikey": True}
    assert info["integrations"]["misp"]["configured"] and info["integrations"]["virustotal"]["configured"]
    for path in ("", "/integrations", "/report-data", "/summary", "/audit?limit=50"):
        assert MISP_KEY not in admin.get(f"/api/cases/{case}{path}").text
        assert VT_KEY not in admin.get(f"/api/cases/{case}{path}").text
    fox = json.loads(admin.get(f"/api/cases/{case}/export").content)
    assert fox["mispapikey"] == "" and fox["vtapikey"] == ""                 # exported as blanks
    assert fox["mispserver"] == "https://misp.example.org" and fox["mispeventid"] == "42"
    with zipfile.ZipFile(io.BytesIO(admin.get(f"/api/cases/{case}/export.xlsx").content)) as z:
        blob = b"".join(z.read(n) for n in z.namelist())
    assert MISP_KEY.encode() not in blob and VT_KEY.encode() not in blob


def test_keys_survive_replace_from_exported_fox(admin, case, calls):
    configure(admin, case, vtapikey=VT_KEY)
    exported = admin.get(f"/api/cases/{case}/export").content
    assert VT_KEY.encode() not in exported
    assert admin.post(f"/api/cases/{case}/replace", content=exported).status_code == 200
    assert admin.get(f"/api/cases/{case}").json()["meta"]["secrets_set"]["vtapikey"] is True


def test_keys_can_be_replaced_and_removed(admin, case):
    configure(admin, case, vtapikey=VT_KEY)
    # write-only: no `expected` needed (nobody can know the current value)
    r = admin.patch(f"/api/cases/{case}", json={"changes": {"vtapikey": ""}, "expected": {}})
    assert r.status_code == 200
    assert admin.get(f"/api/cases/{case}").json()["meta"]["secrets_set"]["vtapikey"] is False


# ------------------------------------------------------------------ the same actions through an API key

def test_actions_with_readwrite_api_key(admin, case, calls):
    secret = admin.post("/api/keys", json={"name": "actions-bot", "profile": "readwrite"}).json()["secret"]
    c = TestClient(app)
    c.headers["Authorization"] = f"Bearer {secret}"
    r = c.post(f"/api/cases/{case}/sections/exfiltration/1/to-timeline")
    assert r.status_code == 200 and r.json()["data"]["event_type"] == "Exfil" and r.json()["updated_by"] == "api:actions-bot"
    configure(admin, case, mispserver="https://misp.example.org", mispeventid="42", mispapikey=MISP_KEY)
    calls.answers["https://misp.example.org/"] = (200, {"Attribute": [{"id": "1"}]})
    r = c.post(f"/api/cases/{case}/sections/network_indicators/1/send-to-misp",
               json={"attributes": [{"type": "domain", "value": "evil.example"}]})
    assert r.status_code == 200 and len(calls) == 1 and calls[0]["headers"]["Authorization"] == MISP_KEY
    r = c.post(f"/api/cases/{case}/sections/malware/1/check-virustotal")
    assert r.status_code == 400 and "VirusTotal" in r.text
    ro = admin.post("/api/keys", json={"name": "actions-ro", "profile": "read"}).json()["secret"]
    c.headers["Authorization"] = f"Bearer {ro}"
    assert c.post(f"/api/cases/{case}/sections/exfiltration/1/to-timeline").status_code == 403
    assert c.get(f"/api/cases/{case}/sections/malware/1/actions").status_code == 200


def test_api_keys_encrypted_at_rest(admin, case):
    """The MISP / VirusTotal keys are stored AES-GCM encrypted (SECRET_KEY), never in clear in the database."""
    from app.db import db
    configure(admin, case, mispserver="https://misp.example.org", mispeventid="42", mispapikey=MISP_KEY,
              vtapikey=VT_KEY)
    with db() as conn:
        raw = conn.execute("SELECT meta FROM cases WHERE id=?", (case,)).fetchone()["meta"]
    assert MISP_KEY not in raw and VT_KEY not in raw and '"vtapikey":"v1:' in raw

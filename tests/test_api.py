"""Application API keys (admin-managed, read / readwrite, expiry, enable, IP allowlist, rotation) and the REST API."""
import json
import time

import pytest
from fastapi.testclient import TestClient

from tests.test_app import FIXTURE, login
from app.main import app


@pytest.fixture(scope="module")
def admin():
    with TestClient(app) as c:
        yield login(c)


@pytest.fixture(scope="module")
def case(admin):
    fx = json.loads(json.dumps(FIXTURE))
    fx["case_id"] = "API-1"
    r = admin.post("/api/cases/import", content=json.dumps(fx))
    assert r.status_code == 200, r.text
    return r.json()["id"]


def make_key(admin, name, profile="readwrite", **extra):
    r = admin.post("/api/keys", json={"name": name, "profile": profile, **extra})
    assert r.status_code == 200, r.text
    return r.json()["secret"], r.json()["key"]


def bearer(secret, ip=None):
    c = TestClient(app, client=(ip, 50000)) if ip else TestClient(app)
    c.headers["Authorization"] = f"Bearer {secret}"
    return c


@pytest.fixture(scope="module")
def api(admin):
    return bearer(make_key(admin, "writer")[0])


# ------------------------------------------------------------------ keys: identity, profiles, admin-only

def test_key_identity_and_no_csrf(api, case):
    me = api.get("/api/me").json()
    assert me["api_key"]["name"] == "writer" and me["api_key"]["profile"] == "readwrite" and me["role"] == "editor"
    r = api.post(f"/api/cases/{case}/sections/casenotes", json={"data": {"note": "via key"}})
    assert r.status_code == 200, r.text
    assert r.json()["updated_by"] == "api:writer"
    assert api.get(f"/api/cases/{case}/audit?limit=1").json()[0]["username"] == "api:writer"


def test_secret_shown_once_and_hashed(admin):
    secret, info = make_key(admin, "listed", "read")
    listed = admin.get("/api/keys").json()
    assert all(secret not in json.dumps(k) for k in listed)
    assert any(k["name"] == "listed" and k["prefix"] == secret[:12] for k in listed)
    assert admin.post("/api/keys", json={"name": "listed", "profile": "read"}).status_code == 409   # names unique


def test_read_profile(admin, case):
    ro = bearer(make_key(admin, "reader", "read")[0])
    assert ro.get(f"/api/cases/{case}/sections/timeline").status_code == 200
    assert ro.get(f"/api/cases/{case}/export.xlsx").status_code == 200
    assert ro.post(f"/api/cases/{case}/sections/casenotes", json={"data": {"note": "x"}}).status_code == 403
    assert ro.post("/api/cases", json={"case_id": "RO-1"}).status_code == 403
    assert ro.patch(f"/api/cases/{case}/report", json={"changes": {"conclusions": "x"}}).status_code == 403


def test_readwrite_creates_cases_but_no_admin_operations(api, case):
    r = api.post("/api/cases", json={"case_id": "API-NEW", "client": "c"})
    assert r.status_code == 200, r.text
    pk = r.json()["id"]
    assert api.post(f"/api/cases/{pk}/sections/systems", json={"data": {"text": "host-1"}}).status_code == 200
    for method, path, body in (
            ("post", "/api/cases/import", None), ("post", f"/api/cases/{case}/replace", None),
            ("post", f"/api/cases/{pk}/delete", {"confirm": "API-NEW"}), ("get", "/api/backups", None),
            ("post", "/api/backups", None), ("post", "/api/backups/restore?confirm=RESTORE", None),
            ("get", "/api/users", None), ("get", "/api/keys", None),
            ("post", "/api/keys", {"name": "x", "profile": "read"}),
            ("post", "/api/me/password", {"current": "a", "new": "b"})):
        kw = {"json": body} if body is not None else ({} if method == "get" else {"content": b"{}"})
        assert getattr(api, method)(path, **kw).status_code == 403, path


def test_who_can_create_and_delete_cases(admin):
    for name in ("creator1", "creator2"):
        assert admin.post("/api/users", json={"username": name, "password": "a-long-password-123",
                                              "role": "user", "must_change_password": False}).status_code == 200
    u1 = login(TestClient(app), "creator1", "a-long-password-123")
    u2 = login(TestClient(app), "creator2", "a-long-password-123")
    # any signed-in user may create a case and becomes its owner
    r = u1.post("/api/cases", json={"case_id": "BY-U1", "client": "x"})
    assert r.status_code == 200, r.text
    pk = r.json()["id"]
    # a read key cannot create; a readwrite (all-scope) key can
    assert bearer(make_key(admin, "creator-ro", "read")[0]).post("/api/cases", json={"case_id": "RO"}).status_code == 403
    rw = bearer(make_key(admin, "creator-rw", "readwrite")[0])
    assert rw.post("/api/cases", json={"case_id": "BY-KEY"}).status_code == 200
    # another user cannot even see the case (404, never 403) and cannot delete it
    assert u2.get(f"/api/cases/{pk}").status_code == 404
    assert u2.post(f"/api/cases/{pk}/delete", json={"confirm": "BY-U1"}).status_code == 404
    # a case key is never an owner/admin, so it cannot delete
    assert rw.post(f"/api/cases/{pk}/delete", json={"confirm": "BY-U1"}).status_code == 403
    # the owner can delete their own case
    assert u1.post(f"/api/cases/{pk}/delete", json={"confirm": "BY-U1"}).status_code == 200


def test_non_admins_cannot_manage_keys(admin):
    assert admin.post("/api/users", json={"username": "kuser", "password": "a-long-password-123",
                                          "role": "user", "must_change_password": False}).status_code == 200
    c = login(TestClient(app), "kuser", "a-long-password-123")
    assert c.get("/api/keys").status_code == 403
    assert c.post("/api/keys", json={"name": "by-user", "profile": "read"}).status_code == 403


def test_disable_expire_rotate_delete(admin, case):
    secret, info = make_key(admin, "lifecycle", "read")
    c = bearer(secret)
    assert c.get("/api/cases").status_code == 200
    assert admin.patch(f"/api/keys/{info['id']}", json={"enabled": False}).status_code == 200
    assert c.get("/api/cases").status_code == 401
    admin.patch(f"/api/keys/{info['id']}", json={"enabled": True})
    assert c.get("/api/cases").status_code == 200
    yesterday = time.strftime("%Y-%m-%d", time.gmtime(time.time() - 2 * 86400))
    assert admin.patch(f"/api/keys/{info['id']}", json={"expires": yesterday}).json()["expired"] is True
    assert c.get("/api/cases").status_code == 401
    admin.patch(f"/api/keys/{info['id']}", json={"expires": ""})
    assert c.get("/api/cases").status_code == 200
    r = admin.patch(f"/api/keys/{info['id']}", json={"profile": "readwrite"})
    assert r.json()["profile"] == "readwrite" and c.get("/api/me").json()["role"] == "editor"
    rot = admin.post(f"/api/keys/{info['id']}/rotate").json()
    assert c.get("/api/cases").status_code == 401                       # old secret dead
    assert bearer(rot["secret"]).get("/api/cases").status_code == 200
    assert rot["key"]["name"] == "lifecycle"                            # identity unchanged
    assert admin.delete(f"/api/keys/{info['id']}").status_code == 200
    assert bearer(rot["secret"]).get("/api/cases").status_code == 401
    assert admin.patch(f"/api/keys/{info['id']}", json={"enabled": True}).status_code == 404
    assert admin.patch(f"/api/keys/{info['id']}", json={"expires": "not-a-date"}).status_code in (400, 404)


def test_key_ip_allowlist(admin):
    secret, info = make_key(admin, "allowlisted", "read", ip_allowlist=["10.1.0.0/16", "2001:db8::/48", "192.0.2.7"])
    assert info["ip_allowlist"] == ["10.1.0.0/16", "2001:db8::/48", "192.0.2.7"]
    assert bearer(secret, "10.1.2.3").get("/api/cases").status_code == 200
    assert bearer(secret, "192.0.2.7").get("/api/cases").status_code == 200
    assert bearer(secret, "2001:db8::42").get("/api/cases").status_code == 200
    assert bearer(secret, "::ffff:10.1.9.9").get("/api/cases").status_code == 200     # IPv4-mapped
    assert bearer(secret, "10.2.0.1").get("/api/cases").status_code == 403
    assert bearer(secret, "2001:db9::1").get("/api/cases").status_code == 403
    admin.patch(f"/api/keys/{info['id']}", json={"ip_allowlist": []})                 # empty = any address
    assert bearer(secret, "10.2.0.1").get("/api/cases").status_code == 200
    assert admin.patch(f"/api/keys/{info['id']}", json={"ip_allowlist": ["10.0.0.0/33"]}).status_code == 400
    assert admin.post("/api/keys", json={"name": "bad", "profile": "read", "ip_allowlist": ["nope"]}).status_code == 400


def test_bad_keys(case):
    for s in ("aurora_nope", "garbage", "aurora_" + "x" * 200):
        assert bearer(s).get("/api/cases").status_code == 401


# ------------------------------------------------------------------ records API

def test_version_update_and_delete_verb(api, case):
    rec = api.post(f"/api/cases/{case}/sections/osint", json={"data": {"url": "https://a.example", "desc": "x"}}).json()
    url = f"/api/cases/{case}/sections/osint/{rec['recid']}"
    assert api.get(url).json()["data"]["url"] == "https://a.example"
    assert api.patch(url, json={"changes": {"desc": "y"}}).status_code == 422          # needs version or expected
    r = api.patch(url, json={"changes": {"desc": "y"}, "version": rec["version"]})
    assert r.status_code == 200 and r.json()["version"] == rec["version"] + 1
    assert api.patch(url, json={"changes": {"desc": "z"}, "version": rec["version"]}).status_code == 409
    assert api.delete(f"{url}?version={rec['version']}").status_code == 409
    assert api.delete(f"{url}?version={r.json()['version']}").status_code == 200
    assert api.get(url).status_code == 404


def test_query_filter_sort_page(api, case):
    base = f"/api/cases/{case}/sections/systems"
    full = api.get(base).json()
    assert full["total"] == len(full["records"])
    r = api.get(base, params={"filter": "system_type:Attacker Infra"}).json()
    assert r["total"] >= 1 and all(x["data"]["system_type"] == "Attacker Infra" for x in r["records"])
    r = api.get(base, params={"sort": "text", "order": "desc", "limit": 1}).json()
    names = sorted((x["data"]["text"].lower() for x in full["records"]), reverse=True)
    assert r["records"][0]["data"]["text"].lower() == names[0] and r["total"] == full["total"]
    assert api.get(base, params={"q": "evil"}).json()["total"] >= 1
    assert api.get(base, params={"filter": "nope:1"}).status_code == 422


def test_search(api, case):
    r = api.get(f"/api/cases/{case}/search", params={"q": "evil.example"}).json()
    sections = {h["section"] for h in r["results"]}
    assert {"systems", "timeline", "network_indicators"} <= sections


def test_bulk_atomic_and_declare_missing(api, case):
    url = f"/api/cases/{case}/sections/timeline/bulk"
    before = api.get(f"/api/cases/{case}").json()["counts"]["timeline"]
    bad = [{"date_time": "2026-01-03 00:00:00", "event_data": "ok"}, {"date_time": "not a date"}]
    r = api.post(url, json={"records": bad})
    assert r.status_code == 422 and r.json()["errors"][0]["index"] == 1
    assert api.get(f"/api/cases/{case}").json()["counts"]["timeline"] == before      # nothing written
    new = [{"date_time": "2026-01-03 00:00:00", "event_host": "new-box", "event_data": "a", "visual": True},
           {"date_time": "2026-01-03 00:05:00", "event_host": "new-box", "event_source_host": "evil.example",
            "direction": "->", "event_data": "b"}]
    assert api.post(url, json={"records": new}).status_code == 422                     # new-box undeclared
    r = api.post(url + "?declare_missing=true", json={"records": new})
    assert r.status_code == 200 and r.json()["created"] == 2


def test_summary_and_openapi(api, case):
    s = api.get(f"/api/cases/{case}/summary").json()
    assert s["timezone"] == "UTC" and len(s["activity_by_hour_utc"]) == 24
    spec = api.get("/api/openapi.json").json()
    assert "/api/cases/{case_pk}/sections/{section}/bulk" in spec["paths"] and "/mcp" not in spec["paths"]
    assert "/api/cases/{case_pk}/report" in spec["paths"]
    assert not any(path.startswith("/api/keys") for path in spec["paths"])          # keys: GUI only
    assert spec["info"]["license"]["identifier"] == "Apache-2.0"
    assert api.get("/api/version").json()["storage_format_version"] == 7
    assert TestClient(app).post("/mcp", json={}).status_code in (401, 404, 405)          # MCP is gone


# ------------------------------------------------------------------ documentation

def test_generated_docs_are_up_to_date():
    """docs/data-model.md, docs/schema.sql and docs/openapi.json must match the code (run tools/gen_docs.py)."""
    import importlib.util
    from pathlib import Path
    root = Path(__file__).resolve().parent.parent
    spec = importlib.util.spec_from_file_location("gen_docs", root / "tools" / "gen_docs.py")
    gen = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gen)
    assert (root / "docs" / "data-model.md").read_text(encoding="utf-8") == gen.data_model()
    assert (root / "docs" / "schema.sql").read_text(encoding="utf-8") == gen.schema_sql()
    assert json.loads((root / "docs" / "openapi.json").read_text(encoding="utf-8")) == app.openapi()


def test_doc_cross_links_resolve():
    """Every relative link in docs/*.md must resolve to another bundled docs file (no dangling refs, no ../ escape)."""
    import posixpath, re
    from pathlib import Path
    docs = Path(__file__).resolve().parent.parent / "docs"
    available = {p.relative_to(docs).as_posix()
                 for p in list(docs.glob("*")) + list(docs.glob("examples/*")) if p.is_file()}
    for md in docs.glob("*.md"):
        for href in re.findall(r"\]\(([^)\s#]+)(?:#[^)]*)?\)", md.read_text(encoding="utf-8")):
            if href.startswith(("http://", "https://")):
                continue
            target = posixpath.normpath(href).lstrip("./")
            assert not href.startswith("../") and target in available, f"{md.name}: {href} is not a bundled docs file"


def test_doc_link_labels_are_not_relative_paths():
    import re
    from pathlib import Path
    for md in (Path(__file__).resolve().parent.parent / "docs").glob("*.md"):
        for label in re.findall(r"\[([^\]]+)\]\([^)]+\)", md.read_text(encoding="utf-8")):
            assert ".." not in label, f"{md.name}: link text {label!r}"


# ------------------------------------------------------------------ authorization sweep over every route

SESSION_STAGE_ROUTES = {"/api/login", "/api/login/mfa", "/api/login/password", "/api/mfa/setup", "/api/session",
                        "/api/logout"}
ADMIN_ONLY = ("/api/users", "/api/keys", "/api/settings", "/api/backups", "/api/cases/import", "/replace", "/delete")


def _routes(case):
    spec = app.openapi()
    for path, ops in spec["paths"].items():
        url = (path.replace("{case_pk}", str(case)).replace("{section}", "timeline").replace("{recid}", "1")
               .replace("{key_id}", "999").replace("{user_id}", "999").replace("{name}", "x.sql.gz"))
        for method in ops:
            yield method.upper(), path, url


def test_every_route_requires_authentication(case):
    anon = TestClient(app)
    for method, path, url in _routes(case):
        if path in ("/api/login",):
            continue
        r = anon.request(method, url, json={})
        assert r.status_code == 401, (method, path, r.status_code)


def test_partial_sign_in_reaches_nothing_else(admin, case):
    """A session waiting for its MFA code may only call the sign-in endpoints."""
    import app.security as SEC
    admin.post("/api/users", json={"username": "halfway", "password": "a-long-password-123", "role": "admin",
                                   "must_change_password": False})
    c = TestClient(app)
    c.post("/api/login", json={"username": "halfway", "password": "a-long-password-123"})
    c.headers["X-CSRF-Token"] = c.get("/api/session").json()["csrf"]
    secret = c.get("/api/mfa/setup").json()["secret"]
    c.post("/api/mfa/setup", json={"code": SEC.totp_now(secret)})
    half = TestClient(app)
    r = half.post("/api/login", json={"username": "halfway", "password": "a-long-password-123"})
    assert r.json()["stage"] == "mfa"
    half.headers["X-CSRF-Token"] = r.json()["csrf"]
    for method, path, url in _routes(case):
        if path in SESSION_STAGE_ROUTES:
            continue
        assert half.request(method, url, json={}).status_code in (401, 403), (method, path)


def test_key_profiles_on_every_route(admin, case):
    ro = bearer(make_key(admin, "sweep-read", "read")[0])
    rw = bearer(make_key(admin, "sweep-rw", "readwrite")[0])
    for method, path, url in _routes(case):
        if path in SESSION_STAGE_ROUTES or path.startswith("/api/me/"):
            continue
        admin_only = any(x in path for x in ADMIN_ONLY) and not path.endswith("/{recid}/delete")
        if method != "GET" or admin_only:
            r = ro.request(method, url, json={})
            assert r.status_code == 403, ("read", method, path, r.status_code)
        if admin_only:
            r = rw.request(method, url, json={})
            assert r.status_code == 403, ("readwrite", method, path, r.status_code)

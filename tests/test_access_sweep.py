"""
Adversarial authorization sweep. Builds one case C (owner + an editor member + a viewer member), a second
case D owned by the admin, and the four API-key shapes, then drives EVERY case route from the live OpenAPI
with every actor and asserts no one can do or see what they must not:

  * an outsider (signed-in, not a member) gets 404 on every route of a case - never 2xx, never 403 (so a
    case id cannot even be confirmed to exist);
  * a viewer can read but every write and every management action is refused;
  * an editor can write but every management action (members / invites / ownership / delete / replace) is
    refused - no self-escalation;
  * a single-case API key cannot touch any other case; no case key can manage membership;
  * no user and no case key can reach any admin surface or enumerate other users.
"""
import re

import pytest
from fastapi.testclient import TestClient

from tests.test_app import FIXTURE, login
from app.main import app

PW = "a-long-password-123"
ADMIN_SURFACES = ("/api/users", "/api/keys", "/api/settings/integrations", "/api/backups")


@pytest.fixture(scope="module")
def admin():
    with TestClient(app) as c:
        yield login(c)


def mkuser(admin, name):
    r = admin.post("/api/users", json={"username": name, "password": PW, "role": "user", "must_change_password": False})
    assert r.status_code == 200, r.text
    return r.json()["id"]


def sess(name):
    return login(TestClient(app), name, PW)


def bearer(secret):
    c = TestClient(app)
    c.headers["Authorization"] = f"Bearer {secret}"
    return c


def mkkey(admin, name, **body):
    r = admin.post("/api/keys", json={"name": name, **body})
    assert r.status_code == 200, r.text
    return r.json()["secret"]


@pytest.fixture(scope="module")
def world(admin):
    oid = mkuser(admin, "swowner"); eid = mkuser(admin, "sweditor")
    vid = mkuser(admin, "swviewer"); _out = mkuser(admin, "swoutsider")
    owner = sess("swowner")
    # case C owned by swowner, populated so record routes have a row 1; editor+viewer added by admin
    import json as _json
    fx = _json.loads(_json.dumps(FIXTURE)); fx["case_id"] = "SWEEP-C"
    C = owner.post("/api/cases/import", content=_json.dumps(fx)).json()["id"]
    assert admin.post(f"/api/cases/{C}/members", json={"user_id": eid, "permission": "editor"}).status_code == 200
    assert admin.post(f"/api/cases/{C}/members", json={"user_id": vid, "permission": "viewer"}).status_code == 200
    fx2 = _json.loads(_json.dumps(FIXTURE)); fx2["case_id"] = "SWEEP-D"
    D = admin.post("/api/cases/import", content=_json.dumps(fx2)).json()["id"]
    return {
        "C": C, "D": D, "eid": eid, "vid": vid, "oid": oid,
        "owner": owner, "editor": sess("sweditor"), "viewer": sess("swviewer"), "outsider": sess("swoutsider"),
        "ksingle": bearer(mkkey(admin, "sw-single", profile="readwrite", kind="case", scope="single", case_pk=C)),
        "kall_ro": bearer(mkkey(admin, "sw-all-ro", profile="read", kind="case", scope="all")),
        "kall_rw": bearer(mkkey(admin, "sw-all-rw", profile="readwrite", kind="case", scope="all")),
        "kadmin": bearer(mkkey(admin, "sw-admin", profile="readwrite", kind="admin")),
    }


# Case-level management is the segment *immediately* after {case_pk} - NOT the record /delete deep in /sections.
MANAGE_RE = re.compile(r"/cases/\{case_pk\}/(members|invites|owner|replace|delete)(/|\{|$)")
# Leaving a case is a legitimate self-service action for any member, not a privileged write.
SELF_RE = re.compile(r"/cases/\{case_pk\}/leave$")


def case_routes(case_pk, world):
    """(method, kind, url) for every route under /api/cases/{case_pk}. kind in view|write|manage|self."""
    spec = app.openapi()
    for path, ops in spec["paths"].items():
        if "{case_pk}" not in path:
            continue
        url = (path.replace("{case_pk}", str(case_pk)).replace("{section}", "timeline")
               .replace("{recid}", "1").replace("{user_id}", str(world["vid"])).replace("{invite_id}", "1"))
        for method in ops:
            m = method.upper()
            if SELF_RE.search(path):
                kind = "self"
            elif MANAGE_RE.search(path):       # members/invites/owner/replace/delete - incl. their GET reads
                kind = "manage"
            elif m == "GET":
                kind = "view"
            else:
                kind = "write"
            yield m, kind, url


def hit(client, method, url, body=None):
    return client.request(method, url, json=(body if body is not None else {}))


# --------------------------------------------------------------------------- #

def test_outsider_sees_and_reaches_nothing(world):
    out = world["outsider"]
    assert out.get("/api/cases").json() == []                       # no case visible at all
    for method, kind, url in case_routes(world["C"], world):
        r = hit(out, method, url)
        assert r.status_code not in (200, 201), ("outsider mutated/read", method, url, r.status_code)
        if method == "GET":
            assert r.status_code == 404, ("outsider existence leak", method, url, r.status_code)


def test_viewer_cannot_write_or_manage(world):
    vw = world["viewer"]
    for method, kind, url in case_routes(world["C"], world):
        if kind == "self":
            continue                       # /leave is a legitimate member action (tested separately)
        r = hit(vw, method, url)
        if kind in ("write", "manage"):
            assert r.status_code not in (200, 201), ("viewer performed a mutation", method, url, r.status_code)
        if kind == "view":
            assert r.status_code != 403, ("viewer wrongly blocked from reading", method, url)


def test_editor_cannot_manage(world):
    ed = world["editor"]
    for method, kind, url in case_routes(world["C"], world):
        if kind == "manage":
            r = hit(ed, method, url)
            assert r.status_code not in (200, 201), ("editor performed a management action", method, url, r.status_code)


def test_single_case_key_cannot_touch_other_cases(world):
    k = world["ksingle"]
    for method, kind, url in case_routes(world["D"], world):          # D is NOT this key's case
        r = hit(k, method, url)
        assert r.status_code not in (200, 201), ("single key reached another case", method, url, r.status_code)
        if method == "GET":
            assert r.status_code == 404, ("single key existence leak on other case", method, url, r.status_code)
    # on its own case it may read/write, but never manage membership
    for method, kind, url in case_routes(world["C"], world):
        if kind == "manage":
            r = hit(k, method, url)
            assert r.status_code not in (200, 201), ("case key managed membership", method, url, r.status_code)


def test_readonly_key_cannot_write_or_manage(world):
    k = world["kall_ro"]
    for method, kind, url in case_routes(world["C"], world):
        if kind in ("write", "manage"):
            r = hit(k, method, url)
            assert r.status_code not in (200, 201), ("read key wrote/managed", method, url, r.status_code)


def test_readwrite_all_key_cannot_manage(world):
    k = world["kall_rw"]
    for method, kind, url in case_routes(world["C"], world):
        if kind == "manage":
            r = hit(k, method, url)
            assert r.status_code not in (200, 201), ("all-rw key managed membership", method, url, r.status_code)


def test_no_user_or_case_key_reaches_admin_surfaces(world):
    for who in ("owner", "editor", "viewer", "outsider", "ksingle", "kall_ro", "kall_rw"):
        c = world[who]
        for s in ADMIN_SURFACES:
            assert c.get(s).status_code == 403, (who, "GET", s)
        assert c.post("/api/keys", json={"name": "x", "profile": "read"}).status_code == 403, (who, "create key")
        assert c.post("/api/users", json={"username": "x", "password": PW}).status_code == 403, (who, "create user")
    # the admin key, by contrast, is a full administrator
    assert world["kadmin"].get("/api/users").status_code == 200


# -------- explicit escalation attempts (valid bodies, exact codes) -------- #

def test_members_cannot_escalate_themselves(world):
    C, eid, vid = world["C"], world["eid"], world["vid"]
    ed, vw = world["editor"], world["viewer"]
    # change own / each other's permission
    assert ed.patch(f"/api/cases/{C}/members/{eid}", json={"permission": "editor"}).status_code == 403
    assert vw.patch(f"/api/cases/{C}/members/{vid}", json={"permission": "editor"}).status_code == 403
    assert vw.patch(f"/api/cases/{C}/members/{eid}", json={"permission": "viewer"}).status_code == 403
    # add a member / invite / transfer ownership / remove the owner
    assert ed.post(f"/api/cases/{C}/members", json={"user_id": vid, "permission": "editor"}).status_code == 403
    assert ed.post(f"/api/cases/{C}/invites", json={"permission": "editor", "max_redeems": 1}).status_code == 403
    assert ed.patch(f"/api/cases/{C}/owner", json={"user_id": eid}).status_code == 403
    assert vw.delete(f"/api/cases/{C}/members/{world['oid']}").status_code == 403
    # a viewer cannot escalate by writing records either
    assert vw.post(f"/api/cases/{C}/sections/casenotes", json={"data": {"note": "x"}}).status_code == 403


def test_users_cannot_touch_other_accounts(world, admin):
    vw, eid = world["viewer"], world["eid"]
    assert vw.get("/api/users").status_code == 403
    assert vw.patch(f"/api/users/{eid}", json={"role": "admin"}).status_code == 403   # no self/other promotion
    assert vw.patch(f"/api/users/{eid}", json={"active": False}).status_code == 403
    assert vw.delete(f"/api/users/{eid}").status_code == 403
    assert vw.post(f"/api/users/{eid}/reset-mfa").status_code == 403


def test_no_member_enumeration_for_non_managers(world):
    """Information disclosure: editors and viewers must not be able to list the other users on the case, and a
    case's details must not carry a member roster."""
    C = world["C"]
    assert world["editor"].get(f"/api/cases/{C}/members").status_code == 403
    assert world["viewer"].get(f"/api/cases/{C}/members").status_code == 403
    assert world["kall_rw"].get(f"/api/cases/{C}/members").status_code == 403
    detail = world["viewer"].get(f"/api/cases/{C}").json()
    assert "members" not in detail and "member_list" not in detail
    # the only person named is the owner (a case participant); no roster of co-members leaks
    assert set(detail) >= {"owner", "access"} and isinstance(detail.get("owner"), str)


def test_join_cannot_be_guessed(world):
    out = world["outsider"]
    # no code, wrong code, and a real case uuid with a bogus code all fail the same vague way
    real_uuid = world["owner"].get(f"/api/cases/{world['C']}").json()["uuid"]
    assert out.post("/api/cases/join", json={"uuid": real_uuid, "code": "aurora-invite_bogus"}).status_code == 400
    assert out.post("/api/cases/join", json={"uuid": "x", "code": "y"}).status_code == 400
    assert out.get("/api/cases").json() == []                        # still in nothing

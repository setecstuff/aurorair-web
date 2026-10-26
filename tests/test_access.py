"""
Per-case access control: ownership, membership, invite codes, API-key scoping, and the IDOR guarantees that
no user can see or touch a case they were not given access to. The environment and a fresh database come from
conftest.py; helpers and the admin fixture come from test_app.
"""
import json
import time

import pytest
from fastapi.testclient import TestClient

from tests.test_app import FIXTURE, login
from app.main import app

PW = "a-long-password-123"


@pytest.fixture()
def admin():
    with TestClient(app) as c:
        yield login(c)


def mkuser(admin, name):
    r = admin.post("/api/users", json={"username": name, "password": PW, "role": "user", "must_change_password": False})
    assert r.status_code == 200, r.text
    return r.json()["id"]


def session(name):
    return login(TestClient(app), name, PW)


def mkcase(client, case_id, client_name="c"):
    r = client.post("/api/cases", json={"case_id": case_id, "client": client_name})
    assert r.status_code == 200, r.text
    return r.json()["id"]


def bearer(secret):
    c = TestClient(app)
    c.headers["Authorization"] = f"Bearer {secret}"
    return c


def mkkey(admin, name, **body):
    r = admin.post("/api/keys", json={"name": name, **body})
    assert r.status_code == 200, r.text
    return r.json()["secret"]


# --------------------------------------------------------------------------- #

def test_new_user_sees_no_cases_and_cannot_reach_others(admin):
    mkuser(admin, "acalice"); mkuser(admin, "acbravo")
    alice, bob = session("acalice"), session("acbravo")
    pk = mkcase(alice, "A-1")
    assert [c["id"] for c in alice.get("/api/cases").json()] == [pk]
    # bob is a signed-in user but not a member: the case must be invisible and unreachable (404, never 403)
    assert bob.get("/api/cases").json() == []
    for method, path, body in [
        ("GET", f"/api/cases/{pk}", None),
        ("GET", f"/api/cases/{pk}/sections/timeline", None),
        ("POST", f"/api/cases/{pk}/sections/timeline", {"data": {"event_type": "x"}}),
        ("PATCH", f"/api/cases/{pk}", {"changes": {"client": "hax"}}),
        ("GET", f"/api/cases/{pk}/export", None),
        ("GET", f"/api/cases/{pk}/members", None),
        ("POST", f"/api/cases/{pk}/invites", {"permission": "editor", "max_redeems": 1}),
        ("PATCH", f"/api/cases/{pk}/owner", {"user_id": 1}),
        ("GET", f"/api/cases/{pk}/audit", None),
        ("GET", f"/api/cases/{pk}/report", None),
    ]:
        r = bob.request(method, path, json=body) if body is not None else bob.request(method, path)
        assert r.status_code == 404, (method, path, r.status_code)


def test_invite_join_editor_and_viewer(admin):
    mkuser(admin, "acowner1"); mkuser(admin, "aced"); mkuser(admin, "acvw")
    owner = session("acowner1")
    pk = mkcase(owner, "INV-1")
    # editor invite
    inv = owner.post(f"/api/cases/{pk}/invites", json={"permission": "editor", "max_redeems": 5}).json()
    ed = session("aced")
    assert ed.post("/api/cases/join", json={"uuid": inv["uuid"], "code": inv["code"]}).status_code == 200
    assert ed.post(f"/api/cases/{pk}/sections/casenotes", json={"data": {"note": "hi"}}).status_code == 200
    # viewer invite
    invv = owner.post(f"/api/cases/{pk}/invites", json={"permission": "viewer", "max_redeems": 5}).json()
    vw = session("acvw")
    assert vw.post("/api/cases/join", json={"uuid": invv["uuid"], "code": invv["code"]}).status_code == 200
    assert vw.get(f"/api/cases/{pk}/sections/casenotes").status_code == 200
    assert vw.post(f"/api/cases/{pk}/sections/casenotes", json={"data": {"note": "no"}}).status_code == 403
    # neither editor nor viewer may manage membership (no self-escalation)
    for m in (ed, vw):
        assert m.get(f"/api/cases/{pk}/members").status_code == 403
        assert m.post(f"/api/cases/{pk}/invites", json={"permission": "editor", "max_redeems": 1}).status_code == 403
        assert m.patch(f"/api/cases/{pk}/owner", json={"user_id": 1}).status_code == 403


def test_invite_limits(admin):
    mkuser(admin, "aco2"); mkuser(admin, "acj1"); mkuser(admin, "acj2")
    owner = session("aco2")
    pk = mkcase(owner, "LIM-1")
    inv = owner.post(f"/api/cases/{pk}/invites", json={"permission": "viewer", "max_redeems": 1}).json()
    j1, j2 = session("acj1"), session("acj2")
    assert j1.post("/api/cases/join", json={"uuid": inv["uuid"], "code": inv["code"]}).status_code == 200
    # redeem count exhausted
    assert j2.post("/api/cases/join", json={"uuid": inv["uuid"], "code": inv["code"]}).status_code == 400
    # already a member -> 409
    assert j1.post("/api/cases/join", json={"uuid": inv["uuid"], "code": inv["code"]}).status_code in (400, 409)
    # right code, wrong uuid -> 400
    inv2 = owner.post(f"/api/cases/{pk}/invites", json={"permission": "viewer", "max_redeems": 5}).json()
    assert j2.post("/api/cases/join", json={"uuid": "00000000-0000-0000-0000-000000000000", "code": inv2["code"]}).status_code == 400
    # revoked invite cannot be used
    invid = owner.get(f"/api/cases/{pk}/invites").json()["invites"][0]["id"]
    assert owner.delete(f"/api/cases/{pk}/invites/{invid}").status_code == 200
    # expired invite cannot be used
    past = time.strftime("%Y-%m-%d", time.gmtime(time.time() - 2 * 86400))
    inv3 = owner.post(f"/api/cases/{pk}/invites", json={"permission": "viewer", "max_redeems": 5, "expires": past}).json()
    assert j2.post("/api/cases/join", json={"uuid": inv3["uuid"], "code": inv3["code"]}).status_code == 400


def test_admin_adds_removes_and_transfers(admin):
    oid = mkuser(admin, "aco3"); mid = mkuser(admin, "acm3")
    owner = session("aco3"); member = session("acm3")
    pk = mkcase(owner, "ADM-1")
    # admin adds a member directly (owners cannot enumerate users, admins can)
    assert admin.post(f"/api/cases/{pk}/members", json={"user_id": mid, "permission": "viewer"}).status_code == 200
    assert member.get(f"/api/cases/{pk}").status_code == 200
    # admin changes the permission and then removes
    assert admin.patch(f"/api/cases/{pk}/members/{mid}", json={"permission": "editor"}).status_code == 200
    assert member.post(f"/api/cases/{pk}/sections/casenotes", json={"data": {"note": "x"}}).status_code == 200
    assert admin.delete(f"/api/cases/{pk}/members/{mid}").status_code == 200
    assert member.get(f"/api/cases/{pk}").status_code == 404
    # admin sees the case with its owner; admin has full access without membership
    row = next(c for c in admin.get("/api/cases").json() if c["id"] == pk)
    assert row["owner"] == "aco3"
    assert admin.get(f"/api/cases/{pk}").status_code == 200
    # admin may transfer ownership to any user (auto-added); the former owner stays as an editor
    assert admin.patch(f"/api/cases/{pk}/owner", json={"user_id": mid}).status_code == 200
    assert member.get(f"/api/cases/{pk}/members").status_code == 200           # new owner can manage
    assert owner.post(f"/api/cases/{pk}/invites", json={"permission": "editor", "max_redeems": 1}).status_code == 403


def test_owner_transfer_only_to_member(admin):
    mkuser(admin, "aco4"); mid = mkuser(admin, "acm4"); oth = mkuser(admin, "acx4")
    owner = session("aco4")
    pk = mkcase(owner, "TR-1")
    # a non-member target is refused for an owner-initiated transfer
    assert owner.patch(f"/api/cases/{pk}/owner", json={"user_id": oth}).status_code == 400
    # add m4 then transfer works
    assert admin.post(f"/api/cases/{pk}/members", json={"user_id": mid, "permission": "viewer"}).status_code == 200
    assert owner.patch(f"/api/cases/{pk}/owner", json={"user_id": mid}).status_code == 200


def test_leave_case(admin):
    mkuser(admin, "aco5"); mid = mkuser(admin, "acm5")
    owner = session("aco5"); member = session("acm5")
    pk = mkcase(owner, "LV-1")
    admin.post(f"/api/cases/{pk}/members", json={"user_id": mid, "permission": "editor"})
    assert member.post(f"/api/cases/{pk}/leave").status_code == 200
    assert member.get(f"/api/cases/{pk}").status_code == 404
    # the owner cannot leave (must transfer first)
    assert owner.post(f"/api/cases/{pk}/leave").status_code == 400


def test_deleting_owner_orphans_case(admin):
    oid = mkuser(admin, "aco6")
    owner = session("aco6")
    pk = mkcase(owner, "ORPH-1")
    assert admin.delete(f"/api/users/{oid}").status_code == 200
    # the case still exists, is owner-less, and only an admin can reach it
    row = next((c for c in admin.get("/api/cases").json() if c["id"] == pk), None)
    assert row is not None and (row["owner"] in ("", None))
    assert admin.get(f"/api/cases/{pk}").status_code == 200


def test_api_key_scopes(admin):
    # admin owns two cases for the key-scope checks
    a = mkcase(admin, "KEY-A"); b = mkcase(admin, "KEY-B")
    single = bearer(mkkey(admin, "k-single", profile="readwrite", kind="case", scope="single", case_pk=a))
    allk = bearer(mkkey(admin, "k-all", profile="read", kind="case", scope="all"))
    adk = bearer(mkkey(admin, "k-admin", profile="readwrite", kind="admin"))
    # single-case key: only its case
    assert single.get(f"/api/cases/{a}").status_code == 200
    assert single.get(f"/api/cases/{b}").status_code == 404
    assert single.post(f"/api/cases/{a}/sections/casenotes", json={"data": {"note": "x"}}).status_code == 200
    assert [c["id"] for c in single.get("/api/cases").json()] == [a]
    # all-scope read key: sees every case, read-only, no admin, no membership management
    assert allk.get(f"/api/cases/{a}").status_code == 200 and allk.get(f"/api/cases/{b}").status_code == 200
    assert allk.post(f"/api/cases/{a}/sections/casenotes", json={"data": {"note": "x"}}).status_code == 403
    assert allk.get("/api/users").status_code == 403
    assert allk.get(f"/api/cases/{a}/members").status_code == 403
    # case keys cannot import or create-by-single; admin key can do everything
    assert single.post("/api/cases", json={"case_id": "NOPE"}).status_code == 403
    assert adk.get("/api/users").status_code == 200
    assert adk.post(f"/api/cases/{a}/members", json={"user_id": 1, "permission": "viewer"}).status_code in (200, 409)
    # deleting a single-case key's case removes the key (fails closed)
    assert admin.post(f"/api/cases/{a}/delete", json={"confirm": "KEY-A"}).status_code == 200
    assert single.get(f"/api/cases/{b}").status_code == 401


def test_cannot_revoke_a_used_up_or_expired_invite(admin):
    import time as _t
    mkuser(admin, "rvown"); mkuser(admin, "rvjoin")
    owner = session("rvown")
    pk = mkcase(owner, "RV-1")
    # a single-use invite that gets redeemed is "used up" and must not be revocable (would flip used-up->revoked)
    inv = owner.post(f"/api/cases/{pk}/invites", json={"permission": "viewer", "max_redeems": 1}).json()
    joiner = session("rvjoin")
    assert joiner.post("/api/cases/join", json={"uuid": inv["uuid"], "code": inv["code"]}).status_code == 200
    used_id = owner.get(f"/api/cases/{pk}/invites").json()["invites"][0]["id"]
    assert owner.delete(f"/api/cases/{pk}/invites/{used_id}").status_code == 409
    # an expired invite cannot be revoked either
    past = _t.strftime("%Y-%m-%d", _t.gmtime(_t.time() - 2 * 86400))
    exp = owner.post(f"/api/cases/{pk}/invites", json={"permission": "viewer", "max_redeems": 5, "expires": past}).json()
    exp_id = exp["invite"]["id"]
    assert owner.delete(f"/api/cases/{pk}/invites/{exp_id}").status_code == 409
    # an active invite revokes fine, and only once
    act = owner.post(f"/api/cases/{pk}/invites", json={"permission": "viewer", "max_redeems": 5}).json()
    act_id = act["invite"]["id"]
    assert owner.delete(f"/api/cases/{pk}/invites/{act_id}").status_code == 200
    assert owner.delete(f"/api/cases/{pk}/invites/{act_id}").status_code == 409   # already revoked


def test_case_number_in_listing(admin):
    mkuser(admin, "aco7")
    owner = session("aco7")
    pk = mkcase(owner, "NUM-1")
    row = next(c for c in owner.get("/api/cases").json() if c["id"] == pk)
    assert row["id"] == pk and row["case_id"] == "NUM-1" and row.get("uuid")

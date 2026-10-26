"""
Per-case access control: ownership, membership, invite codes, and the FastAPI dependencies that gate every
case route. This is the security boundary between cases; `auth.py` establishes *who* the caller is, this
module decides *what case* they may touch.

Model (see docs/user-guide.md):
  * A case has one owner (a user) and any number of members, each a user with an 'editor' or 'viewer'
    permission. The owner always has editor rights plus management (invite / add / remove / change permission
    / transfer ownership). Only the owner or an administrator may manage membership - never an editor, a
    viewer, or a case API key (that is how escalation is prevented).
  * An administrator - a browser session admin or an admin API key - has full access to every case without
    being a member.
  * A case API key reaches case *data* only: profile read -> viewer, readwrite -> editor; scope 'all' -> every
    case, 'single' -> exactly one case.
  * A user who is neither owner, member nor admin must not even learn a case exists: those routes answer 404,
    never 403, so case ids cannot be probed.
"""
from __future__ import annotations

import hashlib
import secrets
import time
import uuid as _uuid

from fastapi import HTTPException, Request

from . import auth
from .db import db

PERMISSIONS = ("editor", "viewer")
INVITE_PREFIX = "aurora-invite_"
MAX_REDEEMS = 10_000


def new_case_uuid() -> str:
    return str(_uuid.uuid4())


def _th(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


# --------------------------------------------------------------------------- #
# Resolving a principal's level on a case
# --------------------------------------------------------------------------- #

def level(conn, p: auth.Principal, case_pk: int) -> tuple[str | None, int | None]:
    """(level, owner_id) for this principal on this case. level is one of 'admin', 'owner', 'editor',
    'viewer', or None when the case is missing or the principal has no access at all (the caller turns both
    into 404 so existence never leaks)."""
    row = conn.execute("SELECT owner_id FROM cases WHERE id = ?", (case_pk,)).fetchone()
    if not row:
        return None, None
    owner_id = row["owner_id"]
    if p.is_admin:                                   # session admin or admin API key
        return "admin", owner_id
    if p.via_key:                                    # case API key: data only, never management
        if p.key_scope == "single" and p.key_case_pk != case_pk:
            return None, owner_id
        return ("editor" if p.key_can_write else "viewer"), owner_id
    if owner_id is not None and owner_id == p.id:
        return "owner", owner_id
    m = conn.execute("SELECT permission FROM case_members WHERE case_pk = ? AND user_id = ?",
                     (case_pk, p.id)).fetchone()
    if m:
        return m["permission"], owner_id
    return None, owner_id


def _resolve(request: Request, case_pk: int) -> tuple[auth.Principal, str | None, int | None]:
    p = auth.current_principal(request)
    with db() as conn:
        lvl, owner_id = level(conn, p, case_pk)
    return p, lvl, owner_id


# FastAPI dependencies. FastAPI injects `case_pk` from the path and `request` from the connection.

def case_viewer(case_pk: int, request: Request) -> auth.Principal:
    """Any access to the case (admin, owner, editor or viewer)."""
    p, lvl, _ = _resolve(request, case_pk)
    if lvl is None:
        raise HTTPException(404, "Case not found")
    return p


def case_editor(case_pk: int, request: Request) -> auth.Principal:
    """Write access to case data (admin, owner or editor)."""
    p, lvl, _ = _resolve(request, case_pk)
    if lvl is None:
        raise HTTPException(404, "Case not found")
    if lvl == "viewer":
        raise HTTPException(403, "Read-only access to this case")
    return p


def case_manager(case_pk: int, request: Request) -> auth.Principal:
    """Manage the case itself - membership, invites, ownership, delete/replace (owner or administrator only)."""
    p, lvl, _ = _resolve(request, case_pk)
    if lvl is None:
        raise HTTPException(404, "Case not found")
    if lvl not in ("admin", "owner"):
        raise HTTPException(403, "Only the case owner or an administrator can do this")
    return p


def visible_case_ids(conn, p: auth.Principal) -> set[int] | None:
    """The case ids a principal may list, or None meaning 'every case' (admin / all-scope key)."""
    if p.is_admin:
        return None
    if p.via_key:
        if p.key_scope == "single":
            return {p.key_case_pk} if p.key_case_pk else set()
        return None
    ids = {r[0] for r in conn.execute("SELECT id FROM cases WHERE owner_id = ?", (p.id,))}
    ids |= {r[0] for r in conn.execute("SELECT case_pk FROM case_members WHERE user_id = ?", (p.id,))}
    return ids


# --------------------------------------------------------------------------- #
# Membership (owner / admin operations; call inside write_tx)
# --------------------------------------------------------------------------- #

def member_rows(conn, case_pk: int, owner_id: int | None) -> list[dict]:
    """Everyone with access to the case: the owner first (marked), then members by username."""
    out: list[dict] = []
    if owner_id is not None:
        o = conn.execute("SELECT id, username, investigator FROM users WHERE id = ?", (owner_id,)).fetchone()
        if o:
            out.append({"user_id": o["id"], "username": o["username"], "investigator": o["investigator"],
                        "permission": "editor", "is_owner": True, "added_at": None, "added_by": ""})
    rows = conn.execute(
        "SELECT cm.user_id, cm.permission, cm.added_at, cm.added_by, u.username, u.investigator "
        "FROM case_members cm JOIN users u ON u.id = cm.user_id WHERE cm.case_pk = ? ORDER BY u.username",
        (case_pk,)).fetchall()
    for r in rows:
        out.append({"user_id": r["user_id"], "username": r["username"], "investigator": r["investigator"],
                    "permission": r["permission"], "is_owner": False,
                    "added_at": r["added_at"], "added_by": r["added_by"]})
    return out


def add_member(conn, case_pk: int, owner_id: int | None, user_id: int, permission: str, by: str) -> None:
    """Directly add a user to a case (administrator action - admins can enumerate users; owners use invite
    codes instead). No-op-safe: errors if the user is missing/inactive, is the owner, or is already a member."""
    if permission not in PERMISSIONS:
        raise HTTPException(400, "permission must be editor or viewer")
    if not conn.execute("SELECT 1 FROM users WHERE id = ? AND active = 1", (user_id,)).fetchone():
        raise HTTPException(404, "User not found")
    if user_id == owner_id:
        raise HTTPException(409, "That user already owns this case")
    if conn.execute("SELECT 1 FROM case_members WHERE case_pk = ? AND user_id = ?", (case_pk, user_id)).fetchone():
        raise HTTPException(409, "That user is already a member of this case")
    conn.execute("INSERT INTO case_members (case_pk, user_id, permission, added_at, added_by) VALUES (?,?,?,?,?)",
                 (case_pk, user_id, permission, int(time.time()), by))


def set_permission(conn, case_pk: int, owner_id: int | None, user_id: int, permission: str, by: str) -> None:
    if permission not in PERMISSIONS:
        raise HTTPException(400, "permission must be editor or viewer")
    if user_id == owner_id:
        raise HTTPException(400, "The owner always has editor rights; transfer ownership to change this")
    if not conn.execute("SELECT 1 FROM case_members WHERE case_pk = ? AND user_id = ?",
                        (case_pk, user_id)).fetchone():
        raise HTTPException(404, "That user is not a member of this case")
    conn.execute("UPDATE case_members SET permission = ? WHERE case_pk = ? AND user_id = ?",
                 (permission, case_pk, user_id))


def remove_member(conn, case_pk: int, owner_id: int | None, user_id: int) -> None:
    if user_id == owner_id:
        raise HTTPException(400, "Transfer ownership before removing the owner")
    cur = conn.execute("DELETE FROM case_members WHERE case_pk = ? AND user_id = ?", (case_pk, user_id))
    if not getattr(cur, "rowcount", 0):
        raise HTTPException(404, "That user is not a member of this case")


def transfer_owner(conn, case_pk: int, current_owner_id: int | None, new_owner_id: int,
                   by: str, allow_any: bool) -> None:
    """Make `new_owner_id` the owner. An owner-initiated transfer (allow_any=False) may only target a current
    member; an administrator (allow_any=True) may target any active user, who is added as a member if needed.
    The previous owner stays on as an editor member."""
    if not conn.execute("SELECT 1 FROM users WHERE id = ? AND active = 1", (new_owner_id,)).fetchone():
        raise HTTPException(404, "User not found")
    if new_owner_id == current_owner_id:
        return
    is_member = conn.execute("SELECT 1 FROM case_members WHERE case_pk = ? AND user_id = ?",
                             (case_pk, new_owner_id)).fetchone()
    if not is_member and not allow_any:
        raise HTTPException(400, "You can only transfer ownership to a current member of the case")
    now = int(time.time())
    conn.execute("UPDATE cases SET owner_id = ? WHERE id = ?", (new_owner_id, case_pk))
    conn.execute("DELETE FROM case_members WHERE case_pk = ? AND user_id = ?", (case_pk, new_owner_id))
    if current_owner_id is not None:
        conn.execute(
            "INSERT INTO case_members (case_pk, user_id, permission, added_at, added_by) VALUES (?,?,?,?,?) "
            "ON DUPLICATE KEY UPDATE permission = 'editor'",
            (case_pk, current_owner_id, "editor", now, by))


# --------------------------------------------------------------------------- #
# Invite codes (owner / admin issue; any user redeems with uuid + code)
# --------------------------------------------------------------------------- #

def public_invite(row) -> dict:
    now = time.time()
    return {"id": row["id"], "prefix": row["prefix"], "permission": row["permission"],
            "max_redeems": row["max_redeems"], "redeems_used": row["redeems_used"],
            "expires_at": row["expires_at"], "enabled": bool(row["enabled"]),
            "expired": bool(row["expires_at"] and row["expires_at"] < now),
            "created_at": row["created_at"], "created_by": row["created_by"]}


def list_invites(conn, case_pk: int) -> list[dict]:
    return [public_invite(r) for r in conn.execute(
        "SELECT * FROM case_invites WHERE case_pk = ? ORDER BY id DESC", (case_pk,))]


def create_invite(conn, case_pk: int, permission: str, max_redeems: int,
                  expires_at: int | None, by: str) -> tuple[str, dict]:
    if permission not in PERMISSIONS:
        raise HTTPException(400, "permission must be editor or viewer")
    if not isinstance(max_redeems, int) or max_redeems < 0 or max_redeems > MAX_REDEEMS:
        raise HTTPException(400, f"redeems must be between 0 (unlimited) and {MAX_REDEEMS}")
    code = INVITE_PREFIX + secrets.token_urlsafe(24)
    now = int(time.time())
    cur = conn.execute(
        "INSERT INTO case_invites (case_pk, code_hash, prefix, permission, max_redeems, redeems_used, "
        "expires_at, enabled, created_at, created_by) VALUES (?,?,?,?,?,0,?,1,?,?)",
        (case_pk, _th(code), code[:14], permission, max_redeems, expires_at, now, by))
    row = conn.execute("SELECT * FROM case_invites WHERE id = ?", (cur.lastrowid,)).fetchone()
    return code, public_invite(row)


def revoke_invite(conn, case_pk: int, invite_id: int) -> None:
    row = conn.execute("SELECT * FROM case_invites WHERE id = ? AND case_pk = ?", (invite_id, case_pk)).fetchone()
    if not row:
        # Either it does not exist or belongs to another case: do not confirm which.
        raise HTTPException(404, "Invitation not found")
    now = int(time.time())
    exhausted = row["max_redeems"] and row["redeems_used"] >= row["max_redeems"]
    if not row["enabled"] or (row["expires_at"] and row["expires_at"] < now) or exhausted:
        # Already unusable: revoking would only muddy its status (used-up -> revoked). Refuse.
        raise HTTPException(409, "This invitation is already used up, expired or revoked")
    conn.execute("UPDATE case_invites SET enabled = 0 WHERE id = ? AND case_pk = ?", (invite_id, case_pk))


def redeem_invite(conn, user_id: int, case_uuid: str, code: str) -> tuple[int, str]:
    """Join a case with its uuid + an invite code. Returns (case_pk, permission). Call inside write_tx so the
    redeem-count check and increment are atomic. Every failure gives the same vague message, so a code cannot
    be probed and case ids are not revealed."""
    vague = HTTPException(400, "Invalid, used-up, revoked or expired invitation (check the case id and the code)")
    if not isinstance(code, str) or not isinstance(case_uuid, str):
        raise vague
    row = conn.execute("SELECT * FROM case_invites WHERE code_hash = ?", (_th(code),)).fetchone()
    if not row or not row["enabled"]:
        raise vague
    case = conn.execute("SELECT id, uuid, owner_id FROM cases WHERE id = ?", (row["case_pk"],)).fetchone()
    if not case or not case["uuid"] or not secrets.compare_digest(case_uuid, case["uuid"]):
        raise vague
    now = int(time.time())
    if row["expires_at"] and row["expires_at"] < now:
        raise vague
    if row["max_redeems"] and row["redeems_used"] >= row["max_redeems"]:
        raise vague
    if case["owner_id"] == user_id:
        raise HTTPException(409, "You already own this case")
    if conn.execute("SELECT 1 FROM case_members WHERE case_pk = ? AND user_id = ?",
                    (case["id"], user_id)).fetchone():
        raise HTTPException(409, "You are already a member of this case")
    conn.execute("INSERT INTO case_members (case_pk, user_id, permission, added_at, added_by) VALUES (?,?,?,?,?)",
                 (case["id"], user_id, row["permission"], now, "invite:" + row["prefix"]))
    conn.execute("UPDATE case_invites SET redeems_used = redeems_used + 1 WHERE id = ?", (row["id"],))
    return case["id"], row["permission"]

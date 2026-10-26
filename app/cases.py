"""
Case data operations: .fox import/export, record CRUD with optimistic field-level
merging, and referential-integrity enforcement.

All mutating functions must be called inside `db.write_tx(conn)`.
"""
from __future__ import annotations

import copy
import csv
import io
import json
import time
import uuid as _uuid
from typing import Any

from . import schema as S
from . import security
from .config import settings
from .schema import FieldError, ValidationError

MAX_RECORDS_PER_SECTION = 100_000


def _case_record_count(conn, case_pk: int) -> int:
    return conn.execute("SELECT count(*) FROM records WHERE case_pk=?", (case_pk,)).fetchone()[0]


def _check_case_cap(conn, case_pk: int, adding: int) -> None:
    """Refuse once a case would exceed MAX_RECORDS_PER_CASE total records (0 = unlimited)."""
    cap = settings.max_records_per_case
    if cap and _case_record_count(conn, case_pk) + adding > cap:
        raise ValidationError([{"field": "records",
                                "message": f"case record limit reached (MAX_RECORDS_PER_CASE={cap})"}])
CONFLICT = object()


class ConflictError(Exception):
    def __init__(self, message: str, payload: dict):
        super().__init__(message)
        self.payload = payload


class NotFound(Exception):
    pass


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def seal_secrets(meta: dict) -> dict:
    """Encrypt the MISP / VirusTotal API keys before the case details are stored (AES-GCM, SECRET_KEY)."""
    for k in S.SECRET_CASE_FIELDS:
        v = meta.get(k) or ""
        if v and not v.startswith("v1:"):
            meta[k] = security.encrypt(v)
    return meta


def secret(meta: dict, k: str) -> str:
    """Plain-text API key for an outbound call (never returned to clients or written to exports)."""
    return security.decrypt(meta.get(k) or "")


def _dumps(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))


def _same(f: S.Field, a: Any, b: Any) -> bool:
    if f.kind == "bool":
        return bool(a) == bool(b)
    a = "" if a is None else a
    b = "" if b is None else b
    return str(a) == str(b)


def lookup_texts(meta: dict, key: str) -> list[str]:
    return [i.get("text") for i in meta["lookups"].get(key, []) if isinstance(i, dict)]


def get_case_row(conn, case_pk: int) :
    row = conn.execute("SELECT * FROM cases WHERE id = ?", (case_pk,)).fetchone()
    if not row:
        raise NotFound("case not found")
    return row


def get_meta(conn, case_pk: int) -> dict:
    return json.loads(get_case_row(conn, case_pk)["meta"])


def _bump(conn, case_pk: int, user: str) -> int:
    now = int(time.time())
    conn.execute("UPDATE cases SET revision = revision + 1, updated_at = ?, updated_by = ? WHERE id = ?",
                 (now, user, case_pk))
    return conn.execute("SELECT revision FROM cases WHERE id = ?", (case_pk,)).fetchone()[0]


def _audit(conn, case_pk: int, user: str, action: str, section=None, recid=None, before=None, after=None):
    conn.execute(
        "INSERT INTO audit (case_pk, ts, username, action, section, recid, before_data, after_data) "
        "VALUES (?,?,?,?,?,?,?,?)",
        (case_pk, int(time.time()), user, action, section, recid,
         None if before is None else _dumps(before), None if after is None else _dumps(after)))


def _key_values(conn, case_pk: int, section: str) -> set[str]:
    key = S.SECTIONS[section].key_field
    rows = conn.execute("SELECT JSON_UNQUOTE(JSON_EXTRACT(data, CONCAT('$.', ?))) FROM records WHERE case_pk=? AND section=?",
                        (key, case_pk, section)).fetchall()
    return {r[0] for r in rows if isinstance(r[0], str) and r[0] != ""}


def _row_out(row) -> dict:
    return {"recid": row["recid"], "version": row["version"], "updated_at": row["updated_at"],
            "updated_by": row["updated_by"], "data": json.loads(row["data"])}


# --------------------------------------------------------------------------- #
# .fox parsing / validation (import)
# --------------------------------------------------------------------------- #

def _reject_constant(name: str):
    raise ValueError(f"{name} is not allowed in JSON")


def _finite_float(text: str) -> float:
    v = float(text)
    if v in (float("inf"), float("-inf")):
        raise ValueError(f"number {text[:20]} is out of range")
    return v


MAX_JSON_DEPTH = 64          # a real Aurora .fox nests ~4 deep; this stops nesting bombs in unknown keys


def _too_deep(obj, limit: int = MAX_JSON_DEPTH) -> bool:
    """Iterative depth check (no recursion of our own): True if any part nests deeper than `limit`.
    A .fox may carry unknown top-level keys verbatim (Aurora forward-compat); without this a deeply nested
    one would be stored and then break .fox export (json.dumps recursion) or other walks."""
    stack = [(obj, 1)]
    while stack:
        cur, d = stack.pop()
        if d > limit:
            return True
        if isinstance(cur, dict):
            for v in cur.values():
                stack.append((v, d + 1))
        elif isinstance(cur, list):
            for v in cur:
                stack.append((v, d + 1))
    return False


def parse_fox(raw: bytes, declare_missing: bool = False) -> tuple[dict, dict[str, list[dict]], list[str]]:
    """
    Parse and strictly validate a .fox document.
    Returns (meta, sections, warnings). Raises ValidationError with a list of problems.
    """
    try:
        # Strict JSON: NaN / Infinity (and numbers that overflow to infinity) are not JSON. Python would accept
        # them, but the exported .fox would then fail to load in Aurora (JavaScript's JSON.parse).
        doc = json.loads(raw.decode("utf-8-sig"), parse_constant=_reject_constant, parse_float=_finite_float)
    except (UnicodeDecodeError, ValueError, RecursionError) as e:
        raise ValidationError([{"field": "file", "message": f"not valid JSON: {e}"[:300]}])
    if _too_deep(doc):
        raise ValidationError([{"field": "file", "message": f"JSON nested too deeply (over {MAX_JSON_DEPTH} levels)"}])
    if not isinstance(doc, dict):
        raise ValidationError([{"field": "file", "message": "top level must be a JSON object"}])

    errors: list[dict] = []
    warnings: list[str] = []
    joined = 0

    def single_line(v):
        """Aurora files may hold multi-line text; this application keeps every value on one line."""
        nonlocal joined
        if S.has_line_breaks(v):
            joined += 1
            return S.join_lines(v)
        return v

    def prep(f, v):
        """Normalise a raw .fox value before validation: convert Aurora's epoch-ms date pickers (e.g. the
        actions `date_due`) to the string this application expects, and keep strings single-line. Non-string,
        non-ms values pass through untouched."""
        v = S.coerce_fox_date(f, v)
        if f.kind == "multiline":
            return v
        return single_line(v) if isinstance(v, str) else v

    def err(where: str, msg: str):
        if len(errors) < 200:
            errors.append({"field": where, "message": msg})

    ver = doc.get("storage_format_version")
    if not isinstance(ver, int) or isinstance(ver, bool):
        err("storage_format_version", "missing or not an integer - is this an Aurora .fox file?")
    elif ver > S.STORAGE_FORMAT_VERSION:
        err("storage_format_version", f"version {ver} is newer than supported ({S.STORAGE_FORMAT_VERSION})")
    elif ver < S.STORAGE_FORMAT_VERSION:
        warnings.append(f"storage format {ver} upgraded to {S.STORAGE_FORMAT_VERSION}")

    meta: dict = {"lookups": {}, "extra": {}}
    for name, f in S.CASE_FIELDS.items():
        if name in S.PLATFORM_CASE_FIELDS:  # platform-only: never taken from a file
            meta[name] = ""
            continue
        if name in doc:
            try:
                meta[name] = S.validate_value(f, prep(f, doc[name]))
            except FieldError as e:
                err(name, str(e))
        else:
            meta[name] = ""
    if not meta.get("case_id"):
        meta["case_id"] = "XXX"
    # A MISP server in the file is the case's own MISP (an equal server-wide URL is adopted later, on import);
    # a .fox never carries a VirusTotal key, so VirusTotal starts on the server-wide key.
    meta["use_server_misp"] = not meta.get("mispserver")
    meta["use_server_vt"] = True

    defaults = S.default_lookups()
    for key in S.LOOKUP_KEYS:
        lst = doc.get(key)
        if lst is None:
            meta["lookups"][key] = defaults[key]
            warnings.append(f"lookup list '{key}' missing - Aurora defaults used")
            continue
        if not isinstance(lst, list) or not all(
                isinstance(i, dict) and isinstance(i.get("text"), str) and isinstance(i.get("id"), int)
                for i in lst):
            err(key, "lookup list must be a list of {id, text}")
            continue
        lst = [{"id": i["id"], "text": single_line(i["text"])} for i in lst]
        for i in lst:
            try:
                S._check_text(i["text"], 200)
            except FieldError as e:
                err(key, str(e))
        meta["lookups"][key] = lst

    known = set(S.TOP_LEVEL_ORDER) | set(S.CASE_FIELDS)
    for k, v in doc.items():
        if k not in known:
            meta["extra"][k] = v
    hosts = doc.get("hosts", [])
    meta["extra"]["hosts"] = hosts if isinstance(hosts, list) else []

    sections: dict[str, list[dict]] = {}
    for key in S.SECTION_ORDER:
        sec = S.SECTIONS[key]
        lst = doc.get(key, [])
        if lst is None:
            lst = []
        if not isinstance(lst, list):
            err(key, "must be a list")
            continue
        if len(lst) > MAX_RECORDS_PER_SECTION:
            err(key, "too many records")
            continue
        out, seen = [], set()
        for idx, rec in enumerate(lst):
            if not isinstance(rec, dict):
                err(f"{key}[{idx}]", "record must be an object")
                continue
            data: dict = {}
            recid = rec.get("recid")
            for k, v in rec.items():
                if k == "recid":
                    continue
                if k == "w2ui":
                    data[k] = {}           # drop any pending w2ui UI state, keep key position
                    continue
                f = sec.fieldmap.get(k)
                if f is not None and f.kind == "bool" and v == "":
                    data[k] = ""           # Aurora leaves untouched checkboxes as ""; keep verbatim
                    continue
                if f is None:
                    data[k] = v            # unknown/legacy key (e.g. date_added_): carried through
                    continue
                try:
                    data[k] = S.validate_value(f, prep(f, v))
                except FieldError as e:
                    err(f"{key} recid {recid} . {k}", str(e))
            if not isinstance(recid, int) or isinstance(recid, bool) or recid < 1 or recid in seen:
                warnings.append(f"{key}: record #{idx + 1} had a missing/duplicate recid - renumbered")
                recid = None
            else:
                seen.add(recid)
            out.append({"recid": recid, "data": data})
        nxt = max(seen, default=0) + 1
        for r in out:
            if r["recid"] is None:
                r["recid"] = nxt
                nxt += 1
        sections[key] = out

    if joined:
        warnings.append(f"{joined} value(s) contained line breaks; they were joined into single lines")
    if errors:
        raise ValidationError(errors)

    # Key-field rules: systems/investigators must have unique, non-empty names.
    for key, sec in S.SECTIONS.items():
        if not sec.unique_key:
            continue
        names: dict[str, int] = {}
        for r in sections[key]:
            v = r["data"].get(sec.key_field, "")
            if not v:
                err(f"{key} recid {r['recid']} . {sec.key_field}", "must not be empty")
                continue
            low = v.lower()
            if low in names:
                err(f"{key} recid {r['recid']} . {sec.key_field}",
                    f"duplicate '{v}' (also recid {names[low]})")
            names[low] = r["recid"]

    # Lookup and reference membership
    for key, sec in S.SECTIONS.items():
        for r in sections[key]:
            for f in sec.fields:
                v = r["data"].get(f.name, "")
                if not v:
                    continue
                if f.kind == "enum" and v not in lookup_texts(meta, f.enum):
                    if declare_missing:
                        lst = meta["lookups"][f.enum]
                        lst.append({"id": max((i["id"] for i in lst), default=0) + 1, "text": v})
                        warnings.append(f"added '{v}' to lookup list {f.enum}")
                    else:
                        err(f"{key} recid {r['recid']} . {f.name}", f"'{v}' is not in lookup list {f.enum}")
                if f.kind == "ref":
                    tsec = S.SECTIONS[f.ref]
                    present = {x["data"].get(tsec.key_field) for x in sections[f.ref]}
                    if v not in present:
                        if declare_missing:
                            rid = max((x["recid"] for x in sections[f.ref]), default=0) + 1
                            sections[f.ref].append({"recid": rid, "data": _new_record_data(tsec, {tsec.key_field: v})})
                            warnings.append(f"declared missing {tsec.label} entry '{v}'")
                        else:
                            err(f"{key} recid {r['recid']} . {f.name}",
                                f"'{v}' is not declared in {tsec.label}")
    if errors:
        raise ValidationError(errors)
    return meta, sections, warnings


def _new_record_data(sec: S.Section, values: dict) -> dict:
    data: dict = {"w2ui": {}}
    now = S.now_ms()
    for f in sec.fields:
        if f.kind == "auto_ms":
            data[f.name] = now
            data[f.name + "_"] = S.ms_to_iso(now)
        elif f.kind == "readonly":
            continue
        else:
            data[f.name] = values.get(f.name, f.default())
    return data


# --------------------------------------------------------------------------- #
# Case lifecycle
# --------------------------------------------------------------------------- #

def _insert_sections(conn, case_pk: int, sections: dict[str, list[dict]], user: str):
    _check_case_cap(conn, case_pk, sum(len(recs) for recs in sections.values()))
    now = int(time.time())
    for key, recs in sections.items():
        for pos, r in enumerate(recs):
            conn.execute(
                "INSERT INTO records (case_pk, section, recid, position, data, version, updated_at, updated_by) "
                "VALUES (?,?,?,?,?,1,?,?)", (case_pk, key, r["recid"], pos, _dumps(r["data"]), now, user))


def create_case(conn, meta: dict, sections: dict[str, list[dict]], user: str, action="import",
                owner_id: int | None = None) -> int:
    seal_secrets(meta)
    now = int(time.time())
    cur = conn.execute(
        "INSERT INTO cases (uuid, owner_id, meta, revision, created_at, updated_at, updated_by) "
        "VALUES (?,?,?,1,?,?,?)", (str(_uuid.uuid4()), owner_id, _dumps(meta), now, now, user))
    pk = cur.lastrowid
    _insert_sections(conn, pk, sections, user)
    _audit(conn, pk, user, action, after={"case_id": meta.get("case_id"), "owner_id": owner_id})
    return pk


def new_empty_case(conn, case_id: str, client: str, user: str, owner_id: int | None = None) -> int:
    meta = {name: S.LOCAL_CASE_FIELDS.get(name, "") for name in S.CASE_FIELDS}
    meta.update(case_id=case_id, client=client, lookups=S.default_lookups(), extra={"hosts": []})
    return create_case(conn, meta, {k: [] for k in S.SECTION_ORDER}, user, action="create", owner_id=owner_id)


def replace_case(conn, case_pk: int, meta: dict, sections: dict, user: str) -> None:
    old = get_meta(conn, case_pk)
    for k in S.SECRET_CASE_FIELDS:     # exported .fox files carry blank API keys: keep the stored ones
        if not meta.get(k) and old.get(k):
            meta[k] = old[k]
    for k in S.PLATFORM_CASE_FIELDS:   # platform-only details are not in the file: keep the case's own
        meta[k] = S.case_value(old, k)
    seal_secrets(meta)
    conn.execute("DELETE FROM records WHERE case_pk = ?", (case_pk,))
    conn.execute("UPDATE cases SET meta = ? WHERE id = ?", (_dumps(meta), case_pk))
    _insert_sections(conn, case_pk, sections, user)
    _bump(conn, case_pk, user)
    _audit(conn, case_pk, user, "replace", after={"case_id": meta.get("case_id")})


def delete_case(conn, case_pk: int) -> None:
    get_case_row(conn, case_pk)
    conn.execute("DELETE FROM records WHERE case_pk = ?", (case_pk,))
    conn.execute("DELETE FROM audit WHERE case_pk = ?", (case_pk,))
    # case_members / case_invites cascade via FK; api_keys.case_pk has none, so drop single-case keys explicitly.
    conn.execute("DELETE FROM api_keys WHERE case_pk = ?", (case_pk,))
    conn.execute("DELETE FROM cases WHERE id = ?", (case_pk,))


def list_cases(conn, q: str = "", visible: set[int] | None = None, with_owner: bool = False) -> list[dict]:
    """Cases ordered by Case ID, newest first (natural order: IR-609 before IR-608, IR-1000 before IR-999).
    `q` filters case-insensitively on Case ID and client. `visible` is the set of case ids the caller may see
    (None = every case; an empty set = none). `with_owner` adds the owner's username (admin listing)."""
    if visible is not None and not visible:
        return []
    owners = {}
    if with_owner:
        owners = {r[0]: r[1] for r in conn.execute("SELECT id, username FROM users")}
    out = []
    for row in conn.execute("SELECT * FROM cases ORDER BY id DESC"):
        if visible is not None and row["id"] not in visible:
            continue
        m = json.loads(row["meta"])
        item = {"id": row["id"], "uuid": row["uuid"], "case_id": m.get("case_id", ""),
                "client": m.get("client", ""), "revision": row["revision"], "updated_at": row["updated_at"],
                "updated_by": row["updated_by"], "owner_id": row["owner_id"]}
        if with_owner:
            item["owner"] = owners.get(row["owner_id"], "")
        out.append(item)
    ql = q.strip().casefold()
    if ql:
        out = [c for c in out if ql in c["case_id"].casefold() or ql in c["client"].casefold()]
    out.sort(key=lambda c: S.natural_key(c["case_id"]), reverse=True)     # stable: same Case ID -> newest id first
    return out


def public_meta(meta: dict) -> dict:
    """Case details as returned to clients. API keys are write-only: their values are never returned to
    anyone (not even admins or editors); `secrets_set` only says whether one is stored."""
    out = {k: S.case_value(meta, k) for k in S.CASE_FIELDS}
    for k in S.SECRET_CASE_FIELDS:
        out[k] = ""
    out["secrets_set"] = {k: bool(meta.get(k)) for k in sorted(S.SECRET_CASE_FIELDS)}
    return out


def update_meta(conn, case_pk: int, changes: dict, expected: dict | None, user: str) -> dict:
    meta = get_meta(conn, case_pk)
    if expected is None:          # API clients may overwrite without a base (last writer wins)
        expected = {k: S.case_value(meta, k) for k in changes}
    errors, conflicts = [], []
    new_vals = {}
    for k, v in changes.items():
        f = S.CASE_FIELDS.get(k)
        if f is None:
            errors.append({"field": k, "message": "unknown field"})
            continue
        try:
            nv = S.validate_value(f, v)
        except FieldError as e:
            errors.append({"field": k, "message": str(e)})
            continue
        if f.required and not nv:
            errors.append({"field": k, "message": "required"})
            continue
        if k in S.SECRET_CASE_FIELDS:      # write-only: nobody can see the current value, last writer wins
            new_vals[k] = nv.strip()
            continue
        if k not in expected:
            errors.append({"field": k, "message": "missing expected (base) value"})
            continue
        cur = S.case_value(meta, k)
        if not _same(f, cur, expected[k]) and not _same(f, cur, nv):
            conflicts.append({"field": k, "current": cur, "base": expected[k], "yours": nv})
        new_vals[k] = nv
    start = new_vals.get("start_date", meta.get("start_date", ""))
    end = new_vals.get("end_date", meta.get("end_date", ""))
    if start and end and end < start and not errors:
        errors.append({"field": "end_date" if "end_date" in new_vals else "start_date",
                       "message": "the engagement end is before its start"})
    if errors:
        raise ValidationError(errors)
    if conflicts:
        raise ConflictError("Case details were changed by someone else", {
            "conflicts": conflicts, "current": public_meta(meta)})
    before = {k: S.case_value(meta, k) for k in new_vals}
    meta.update(new_vals)
    seal_secrets(meta)
    conn.execute("UPDATE cases SET meta = ? WHERE id = ?", (_dumps(meta), case_pk))
    _bump(conn, case_pk, user)
    redact = lambda d: {k: ("***" if k in S.SECRET_CASE_FIELDS and v else v) for k, v in d.items()}
    _audit(conn, case_pk, user, "update_case", before=redact(before), after=redact(new_vals))
    return meta


def options(conn, case_pk: int) -> dict:
    meta = get_meta(conn, case_pk)
    refs = {}
    for target in S.REFERENCES:
        refs[target] = sorted(_key_values(conn, case_pk, target), key=str.lower)
    return {"lookups": {k: lookup_texts(meta, k) for k in S.LOOKUP_KEYS}, "refs": refs}


# --------------------------------------------------------------------------- #
# Report page: executive summary, context, conclusions, lessons learned (never part of the .fox)
# --------------------------------------------------------------------------- #

REPORT_COLUMNS = ("executive_summary", "conclusions", "lessons_learned")


def get_report(conn, case_pk: int) -> dict:
    meta = get_meta(conn, case_pk)
    row = conn.execute("SELECT * FROM case_reports WHERE case_pk=?", (case_pk,)).fetchone()
    out = {k: (row[k] if row else "") for k in REPORT_COLUMNS}
    out["context"] = meta.get("summary", "")
    out["updated_at"] = row["updated_at"] if row else None
    out["updated_by"] = row["updated_by"] if row else ""
    return out


def update_report(conn, case_pk: int, changes: dict, expected: dict | None, user: str) -> dict:
    """Field-level optimistic merge, like case details. `context` is the case's Summary field."""
    cur = get_report(conn, case_pk)
    if not isinstance(changes, dict) or not changes:
        raise ValidationError([{"field": "changes", "message": "nothing to change"}])
    if expected is None:
        expected = {k: cur.get(k, "") for k in changes}
    errors, conflicts, new_vals = [], [], {}
    for k, v in changes.items():
        f = S.REPORT_FIELDS.get(k)
        if f is None:
            errors.append({"field": k, "message": "unknown field"})
            continue
        try:
            nv = S.validate_value(f, v)
        except FieldError as e:
            errors.append({"field": k, "message": str(e)})
            continue
        if k not in expected:
            errors.append({"field": k, "message": "missing expected (base) value"})
            continue
        base = S.check_multiline(str(expected[k] or ""), 10 ** 7)
        if cur[k] != base and cur[k] != nv:
            conflicts.append({"field": k, "current": cur[k], "base": expected[k], "yours": nv})
        new_vals[k] = nv
    if errors:
        raise ValidationError(errors)
    if conflicts:
        raise ConflictError("The executive summary was changed by someone else",
                            {"conflicts": conflicts, "current": cur})
    changed = {k: v for k, v in new_vals.items() if v != cur[k]}
    if not changed:
        return cur
    now = int(time.time())
    if "context" in changed:
        meta = get_meta(conn, case_pk)
        meta["summary"] = changed["context"]
        conn.execute("UPDATE cases SET meta = ? WHERE id = ?", (_dumps(meta), case_pk))
    cols = {k: changed.get(k, cur[k]) for k in REPORT_COLUMNS}
    conn.execute(
        "INSERT INTO case_reports (case_pk, executive_summary, conclusions, lessons_learned, updated_at, updated_by) "
        "VALUES (?,?,?,?,?,?) ON DUPLICATE KEY UPDATE executive_summary=VALUES(executive_summary), "
        "conclusions=VALUES(conclusions), lessons_learned=VALUES(lessons_learned), updated_at=VALUES(updated_at), "
        "updated_by=VALUES(updated_by)",
        (case_pk, cols["executive_summary"], cols["conclusions"], cols["lessons_learned"], now, user))
    _bump(conn, case_pk, user)
    _audit(conn, case_pk, user, "update_report", before={k: cur[k] for k in changed}, after=changed)
    return get_report(conn, case_pk)


# --------------------------------------------------------------------------- #
# Records
# --------------------------------------------------------------------------- #

def section_counts(conn, case_pk: int) -> dict[str, int]:
    counts = {k: 0 for k in S.SECTION_ORDER}
    for r in conn.execute("SELECT section, count(*) FROM records WHERE case_pk=? GROUP BY section", (case_pk,)):
        counts[r[0]] = r[1]
    return counts


def list_records(conn, case_pk: int, section: str) -> list[dict]:
    """All records of a section in the section's default order (see schema.Section.default_order)."""
    get_case_row(conn, case_pk)
    rows = conn.execute("SELECT * FROM records WHERE case_pk=? AND section=?", (case_pk, section)).fetchall()
    return S.sort_default(S.SECTIONS[section], [_row_out(r) for r in rows], lambda r: (r["data"], r["recid"]))


def _get_record(conn, case_pk: int, section: str, recid: int) :
    row = conn.execute("SELECT * FROM records WHERE case_pk=? AND section=? AND recid=?",
                       (case_pk, section, recid)).fetchone()
    if not row:
        raise NotFound("record not found (it may have been deleted by another user)")
    return row


def _validate_fields(conn, case_pk: int, meta: dict, sec: S.Section, values: dict, self_recid=None) -> dict:
    """Validate client-supplied values; returns normalised values. Raises ValidationError."""
    errors, out, missing = [], {}, []
    if not isinstance(values, dict):
        raise ValidationError([{"field": "data", "message": "must be an object"}])
    for k, v in values.items():
        f = sec.fieldmap.get(k)
        if f is None or not f.editable:
            errors.append({"field": k, "message": "unknown or read-only field"})
            continue
        try:
            nv = S.validate_value(f, v)
        except FieldError as e:
            errors.append({"field": k, "message": str(e)})
            continue
        if f.required and nv in ("", None):
            errors.append({"field": k, "message": "required"})
            continue
        if nv not in ("", None) and f.kind == "enum" and nv not in lookup_texts(meta, f.enum):
            errors.append({"field": k, "message": f"'{nv}' is not a valid choice"})
            continue
        if nv not in ("", None) and f.kind == "ref" and nv not in _key_values(conn, case_pk, f.ref):
            tsec = S.SECTIONS[f.ref]
            errors.append({"field": k, "message": f"'{nv}' is not declared in {tsec.label}"})
            missing.append({"field": k, "section": f.ref, "value": nv})
            continue
        out[k] = nv
    if sec.unique_key and sec.key_field in out:
        v = out[sec.key_field]
        dup = conn.execute(
            "SELECT recid FROM records WHERE case_pk=? AND section=? "
            "AND lower(JSON_UNQUOTE(JSON_EXTRACT(data, CONCAT('$.', ?)))) = lower(?) AND NOT (recid <=> ?)",
            (case_pk, sec.key, sec.key_field, v, self_recid)).fetchone()
        if dup:
            errors.append({"field": sec.key_field, "message": f"'{v}' already exists (recid {dup[0]})"})
    if errors:
        e = ValidationError(errors)
        e.missing_refs = missing
        raise e
    return out


def _declare_missing_refs(conn, case_pk: int, missing: list[dict], user: str) -> None:
    """Create minimal Systems / Investigators / Malware entries for referenced-but-undeclared names."""
    seen = set()
    for m in missing:
        key = (m["section"], m["value"])
        if key in seen:
            continue
        seen.add(key)
        tsec = S.SECTIONS[m["section"]]
        create_record(conn, case_pk, m["section"], {tsec.key_field: m["value"]}, user)


def create_record(conn, case_pk: int, section: str, values: dict, user: str, declare_missing: bool = False) -> dict:
    sec = S.SECTIONS[section]
    meta = get_meta(conn, case_pk)
    count = conn.execute("SELECT count(*) FROM records WHERE case_pk=? AND section=?", (case_pk, section)).fetchone()[0]
    if count >= MAX_RECORDS_PER_SECTION:
        raise ValidationError([{"field": "data", "message": "section is full"}])
    _check_case_cap(conn, case_pk, 1)
    try:
        vals = _validate_fields(conn, case_pk, meta, sec, values)
    except ValidationError as e:
        missing = getattr(e, "missing_refs", [])
        # only auto-declare when missing references are the *only* problem
        if not (declare_missing and missing and len(missing) == len(e.errors)):
            raise
        _declare_missing_refs(conn, case_pk, missing, user)
        vals = _validate_fields(conn, case_pk, meta, sec, values)
    missing_req = [f.name for f in sec.fields if f.required and f.editable and not vals.get(f.name)]
    if missing_req:
        raise ValidationError([{"field": n, "message": "required"} for n in missing_req])
    data = _new_record_data(sec, vals)
    if sec.auto_date_updated:
        data["date_updated"] = data["date_added"]
        data["date_updated_"] = data["date_added_"]
    recid = conn.execute("SELECT coalesce(max(recid),0)+1 FROM records WHERE case_pk=? AND section=?",
                         (case_pk, section)).fetchone()[0]
    pos = conn.execute("SELECT coalesce(max(position),-1)+1 FROM records WHERE case_pk=? AND section=?",
                       (case_pk, section)).fetchone()[0]
    now = int(time.time())
    conn.execute("INSERT INTO records (case_pk, section, recid, position, data, version, updated_at, updated_by) "
                 "VALUES (?,?,?,?,?,1,?,?)", (case_pk, section, recid, pos, _dumps(data), now, user))
    _bump(conn, case_pk, user)
    _audit(conn, case_pk, user, "create", section, recid, after=data)
    return _row_out(_get_record(conn, case_pk, section, recid))


def update_record(conn, case_pk: int, section: str, recid: int, changes: dict, expected: dict | None, user: str,
                  version: int | None = None, declare_missing: bool = False) -> dict:
    """
    Field-level optimistic merge: for each changed field the client sends the value it
    originally saw (`expected`). If the stored value still equals that base (or already
    equals the new value) the change is applied, so two people editing different fields
    of the same record never collide. Otherwise a ConflictError lists the clashing fields.
    """
    sec = S.SECTIONS[section]
    meta = get_meta(conn, case_pk)
    row = _get_record(conn, case_pk, section, recid)
    data = json.loads(row["data"])
    if not isinstance(changes, dict) or not changes:
        raise ValidationError([{"field": "changes", "message": "nothing to change"}])
    if expected is None:
        # Simpler mode for API clients: whole-record optimistic locking on `version`.
        if version is None:
            raise ValidationError([{"field": "expected", "message": "send either `expected` (field values you "
                                    "started from) or `version` (record version you read)"}])
        if version != row["version"]:
            raise ConflictError(f"Record is at version {row['version']}, not {version}; re-read and retry",
                                {"current": _row_out(row)})
        expected = {k: data.get(k, sec.fieldmap[k].default() if k in sec.fieldmap else "") for k in changes}
    if not isinstance(expected, dict):
        raise ValidationError([{"field": "expected", "message": "must be an object"}])
    try:
        vals = _validate_fields(conn, case_pk, meta, sec, changes, self_recid=recid)
    except ValidationError as e:
        missing = getattr(e, "missing_refs", [])
        if not (declare_missing and missing and len(missing) == len(e.errors)):
            raise
        _declare_missing_refs(conn, case_pk, missing, user)
        vals = _validate_fields(conn, case_pk, meta, sec, changes, self_recid=recid)
    conflicts = []
    for k, nv in vals.items():
        f = sec.fieldmap[k]
        if k not in expected:
            raise ValidationError([{"field": k, "message": "missing expected (base) value"}])
        cur = data.get(k, f.default())
        if not _same(f, cur, expected[k]) and not _same(f, cur, nv):
            conflicts.append({"field": k, "current": cur, "base": expected[k], "yours": nv})
    if conflicts:
        raise ConflictError("This record was changed by someone else", {
            "conflicts": conflicts, "current": _row_out(row)})
    before = {k: data.get(k) for k in vals}
    changed = {k: v for k, v in vals.items() if not _same(sec.fieldmap[k], data.get(k, sec.fieldmap[k].default()), v)
               or k not in data}
    if not changed:
        return _row_out(row)
    old_key = data.get(sec.key_field) if sec.key_field else None
    data.update(changed)
    if sec.auto_date_updated:
        now_ms = S.now_ms()
        data["date_updated"] = now_ms
        data["date_updated_"] = S.ms_to_iso(now_ms)
    now = int(time.time())
    conn.execute("UPDATE records SET data=?, version=version+1, updated_at=?, updated_by=? "
                 "WHERE case_pk=? AND section=? AND recid=?", (_dumps(data), now, user, case_pk, section, recid))
    _audit(conn, case_pk, user, "update", section, recid, before=before, after=changed)

    # Cascade a rename of a referenced key (system hostname, investigator, malware name)
    if sec.key_field and sec.key_field in changed and old_key and old_key != data[sec.key_field]:
        if old_key not in _key_values(conn, case_pk, section):
            _cascade_rename(conn, case_pk, section, old_key, data[sec.key_field], user)
    _bump(conn, case_pk, user)
    return _row_out(_get_record(conn, case_pk, section, recid))


def _references_to(conn, case_pk: int, target: str, value: str) -> list[dict]:
    out = []
    for src, fname in S.REFERENCES.get(target, []):
        rows = conn.execute("SELECT recid FROM records WHERE case_pk=? AND section=? "
                            "AND JSON_UNQUOTE(JSON_EXTRACT(data, CONCAT('$.', ?))) COLLATE utf8mb4_bin = ?",
                            (case_pk, src, fname, value)).fetchall()
        out += [{"section": src, "recid": r[0], "field": fname} for r in rows]
    return out


def _cascade_rename(conn, case_pk: int, target: str, old: str, new: str, user: str):
    now = int(time.time())
    for ref in _references_to(conn, case_pk, target, old):
        row = _get_record(conn, case_pk, ref["section"], ref["recid"])
        data = json.loads(row["data"])
        data[ref["field"]] = new
        conn.execute("UPDATE records SET data=?, version=version+1, updated_at=?, updated_by=? "
                     "WHERE case_pk=? AND section=? AND recid=?",
                     (_dumps(data), now, user, case_pk, ref["section"], ref["recid"]))
        _audit(conn, case_pk, user, "cascade_rename", ref["section"], ref["recid"],
               before={ref["field"]: old}, after={ref["field"]: new})


def delete_record(conn, case_pk: int, section: str, recid: int, version: int | None, user: str) -> None:
    sec = S.SECTIONS[section]
    row = _get_record(conn, case_pk, section, recid)
    if version is not None and row["version"] != version:
        raise ConflictError("Record was modified by someone else since you loaded it; review before deleting",
                            {"current": _row_out(row)})
    data = json.loads(row["data"])
    if sec.key_field:
        key = data.get(sec.key_field)
        if key:
            others = conn.execute(
                "SELECT count(*) FROM records WHERE case_pk=? AND section=? AND recid<>? "
                "AND JSON_UNQUOTE(JSON_EXTRACT(data, CONCAT('$.', ?))) COLLATE utf8mb4_bin = ?",
                (case_pk, section, recid, sec.key_field, key)).fetchone()[0]
            refs = [] if others else _references_to(conn, case_pk, section, key)
            if refs:
                raise ConflictError(
                    f"'{key}' is still referenced by {len(refs)} record(s); change those first",
                    {"references": refs[:50]})
    conn.execute("DELETE FROM records WHERE case_pk=? AND section=? AND recid=?", (case_pk, section, recid))
    _bump(conn, case_pk, user)
    _audit(conn, case_pk, user, "delete", section, recid, before=data)


def set_system_field(conn, case_pk: int, section: str, recid: int, name: str, value: Any, user: str,
                     only_if: dict | None = None, action: str = "update", note: dict | None = None) -> dict:
    """Server-side write of a read-only field (e.g. the VirusTotal verdict `vt`). `only_if` guards against the
    record having changed meanwhile (e.g. the hash that was checked)."""
    sec = S.SECTIONS[section]
    f = sec.fieldmap[name]
    if f.choices is not None and value not in f.choices:
        raise ValidationError([{"field": name, "message": "invalid value"}])
    row = _get_record(conn, case_pk, section, recid)
    data = json.loads(row["data"])
    for k, v in (only_if or {}).items():
        if data.get(k) != v:
            raise ConflictError(f"{sec.fieldmap[k].label} was changed by someone else meanwhile; try again",
                                {"current": _row_out(row)})
    before = data.get(name, "")
    data[name] = value
    conn.execute("UPDATE records SET data=?, version=version+1, updated_at=?, updated_by=? "
                 "WHERE case_pk=? AND section=? AND recid=?",
                 (_dumps(data), int(time.time()), user, case_pk, section, recid))
    _audit(conn, case_pk, user, action, section, recid, before={name: before}, after={name: value, **(note or {})})
    _bump(conn, case_pk, user)
    return _row_out(_get_record(conn, case_pk, section, recid))


def get_record(conn, case_pk: int, section: str, recid: int) -> dict:
    get_case_row(conn, case_pk)
    return _row_out(_get_record(conn, case_pk, section, recid))


def _text_of(data: dict) -> str:
    return " ".join(str(v) for k, v in data.items() if k not in ("w2ui",) and v not in (None, "", False)).lower()


def query_records(conn, case_pk: int, section: str, q: str = "", limit: int | None = None, offset: int = 0,
                  sort: str | None = None, order: str = "asc", filters: dict | None = None) -> tuple[int, list[dict]]:
    """Filter (case-insensitive substring over all fields, plus exact field=value filters), sort and page."""
    recs = list_records(conn, case_pk, section)
    sec = S.SECTIONS[section]
    if q:
        ql = q.lower()
        recs = [r for r in recs if ql in _text_of(r["data"])]
    for k, v in (filters or {}).items():
        f = sec.fieldmap.get(k)
        if f is None:
            raise ValidationError([{"field": k, "message": "unknown field to filter on"}])
        recs = [r for r in recs if _same(f, r["data"].get(k, f.default()), v)]
    if sort:
        if sort not in sec.fieldmap and sort != "recid":
            raise ValidationError([{"field": "sort", "message": "unknown field"}])
        if order not in ("asc", "desc"):
            raise ValidationError([{"field": "order", "message": "must be asc or desc"}])
        if sort == "recid":
            recs.sort(key=lambda r: r["recid"], reverse=(order == "desc"))
        else:   # same comparison rules as the default order; ties keep the default order
            recs = S.sort_by_fields(sec, recs, [(sort, order)], lambda r: (r["data"], r["recid"]))
    total = len(recs)
    if offset:
        recs = recs[offset:]
    if limit is not None:
        recs = recs[:limit]
    return total, recs


def search(conn, case_pk: int, q: str, sections: list[str] | None = None, limit: int = 50) -> list[dict]:
    if not q or not q.strip():
        raise ValidationError([{"field": "q", "message": "search text required"}])
    ql = q.strip().lower()
    out = []
    for section in sections or S.SECTION_ORDER:
        if section not in S.SECTIONS:
            raise ValidationError([{"field": "sections", "message": f"unknown section {section}"}])
        for r in list_records(conn, case_pk, section):
            fields = [k for k, v in r["data"].items() if k != "w2ui" and ql in str(v).lower()]
            if fields:
                out.append({"section": section, "recid": r["recid"], "matched_fields": fields, "data": r["data"]})
                if len(out) >= limit:
                    return out
    return out


MAX_BULK = 1000


def bulk_create(conn, case_pk: int, section: str, records: list, user: str, declare_missing: bool = False) -> list[dict]:
    """All-or-nothing: the caller's transaction is rolled back if any record fails."""
    if not isinstance(records, list) or not records:
        raise ValidationError([{"field": "records", "message": "must be a non-empty list"}])
    if len(records) > MAX_BULK:
        raise ValidationError([{"field": "records", "message": f"at most {MAX_BULK} records per call"}])
    _check_case_cap(conn, case_pk, len(records))     # fail up front; create_record also re-checks per record
    out = []
    for i, data in enumerate(records):
        try:
            out.append(create_record(conn, case_pk, section, data, user, declare_missing=declare_missing))
        except ValidationError as e:
            err = ValidationError([{"index": i, **x} for x in e.errors])
            err.missing_refs = [{"index": i, **m} for m in getattr(e, "missing_refs", [])]
            raise err
    return out


# --------------------------------------------------------------------------- #
# CSV import / export (one section at a time)
# --------------------------------------------------------------------------- #
# Standardised format: RFC 4180 - comma-separated, CRLF line endings, double-quote quoting (so a value that
# contains a comma, a semicolon, a quote or a newline is quoted and cannot break the columns), UTF-8 (a BOM is
# accepted). The header row names the columns; only a section's editable fields are columns (server-managed
# fields - recid, date_added/date_updated, vt - are never imported or exported). On IMPORT every cell is run
# through the same field validation as the API/.fox import (types, lengths, control-character rejection,
# reference and uniqueness checks), the column count of every row must match the header, unknown/duplicate
# columns and non-UTF-8 / NUL input are refused, and the whole file is rejected if any cell fails (all-or-
# nothing). On EXPORT a cell that could be read as a spreadsheet formula (it starts with = + - @, a tab or a
# CR) is prefixed with a single quote to neutralise CSV/formula injection; import strips that guard back off.

_CSV_FORMULA = ("=", "+", "-", "@", "\t", "\r")


def _csv_cols(section: str) -> list:
    return [f for f in S.SECTIONS[section].fields if f.editable]


def _csv_guard(s: str) -> str:
    return "'" + s if s[:1] in _CSV_FORMULA else s


def _csv_unguard(s: str) -> str:
    return s[1:] if len(s) >= 2 and s[0] == "'" and s[1] in "=+-@\t\r" else s


def export_csv(conn, case_pk: int, section: str) -> str:
    get_case_row(conn, case_pk)
    cols = _csv_cols(section)
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\r\n")
    w.writerow([f.name for f in cols])
    for r in list_records(conn, case_pk, section):
        data = r["data"]
        w.writerow([_csv_guard("" if data.get(f.name) is None else str(data.get(f.name))) for f in cols])
    return buf.getvalue()


def import_csv(conn, case_pk: int, section: str, raw: bytes, user: str, declare_missing: bool = False) -> list:
    get_case_row(conn, case_pk)
    editable = {f.name: f for f in _csv_cols(section)}
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise ValidationError([{"field": "csv", "message": "the file is not valid UTF-8"}])
    if "\x00" in text:
        raise ValidationError([{"field": "csv", "message": "the file contains NUL bytes"}])
    try:
        rows = [r for r in csv.reader(io.StringIO(text)) if r != []]
    except csv.Error as e:
        raise ValidationError([{"field": "csv", "message": f"malformed CSV: {e}"}])
    if not rows:
        raise ValidationError([{"field": "csv", "message": "the file is empty"}])
    header = [h.strip() for h in rows[0]]
    if not header or header == [""]:
        raise ValidationError([{"field": "csv", "message": "missing header row"}])
    seen = set()
    for h in header:
        if h not in editable:
            raise ValidationError([{"field": "csv", "message": f"unknown or non-importable column '{h}'. "
                                    f"Allowed columns: {', '.join(editable)}"}])
        if h in seen:
            raise ValidationError([{"field": "csv", "message": f"duplicate column '{h}'"}])
        seen.add(h)
    ncol = len(header)
    records = []
    for i, row in enumerate(rows[1:], start=2):
        if len(row) != ncol:
            raise ValidationError([{"field": "csv",
                                    "message": f"line {i}: {len(row)} value(s) but the header has {ncol}"}])
        records.append({h: _csv_unguard(v) for h, v in zip(header, row)})
    if not records:
        raise ValidationError([{"field": "csv", "message": "no data rows after the header"}])
    return bulk_create(conn, case_pk, section, records, user, declare_missing=declare_missing)


def incident_summary(conn, case_pk: int) -> dict:
    """The figures behind the reporting views (overview, lateral movement, activity plot), as data."""
    row = get_case_row(conn, case_pk)
    meta = json.loads(row["meta"])
    sec = {k: [r["data"] | {"recid": r["recid"]} for r in list_records(conn, case_pk, k)] for k in S.SECTION_ORDER}
    tl = sec["timeline"]
    attacker = [e for e in tl if e.get("event_type") != "Engagement" and e.get("date_time")]
    times = sorted(e["date_time"] for e in attacker)
    hours = [0] * 24
    for e in attacker:
        hours[int(e["date_time"][11:13])] += 1
    sysmap = {s.get("text"): s for s in sec["systems"]}
    edges = []
    for e in tl:
        if e.get("event_host") and e.get("event_source_host"):
            src, dst = ((e["event_host"], e["event_source_host"]) if e.get("direction") == "->"
                        else (e["event_source_host"], e["event_host"]))
            edges.append({"from": src, "to": dst, "date_time": e.get("date_time", ""), "event_type": e.get("event_type", ""),
                          "event": e.get("event_data", ""), "visual": bool(e.get("visual")), "timeline_recid": e["recid"]})
    hosts = sorted({h for ed in edges for h in (ed["from"], ed["to"])})
    return {
        "case": public_meta(meta), "revision": row["revision"], "timezone": "UTC",
        "counts": {k: len(v) for k, v in sec.items()},
        "first_attacker_activity": times[0] if times else None,
        "last_attacker_activity": times[-1] if times else None,
        "killchain": {k: sum(1 for e in tl if e.get("killchain") == k) for k in lookup_texts(meta, "killchain")},
        "event_types": {k: sum(1 for e in tl if e.get("event_type") == k) for k in lookup_texts(meta, "event_types")
                        if any(e.get("event_type") == k for e in tl)},
        "activity_by_hour_utc": hours,
        "investigated_systems": [{k: s.get(k, "") for k in ("hostname", "verdict", "first_compromise",
                                  "analysis_status", "analyst", "summary")} for s in sec["investigated_systems"]],
        "compromised_accounts": [{k: a.get(k, "") for k in ("account_name", "domain", "sid", "context")}
                                 for a in sec["compromised_accounts"]],
        "exfiltration": [{k: x.get(k, "") for k in ("exfiltime", "stagingsystem", "exfil_to", "filename", "contents")}
                         for x in sec["exfiltration"]],
        "lateral_movement": {"nodes": [{"host": h, "ip": (sysmap.get(h) or {}).get("ip", ""),
                                        "system_type": (sysmap.get(h) or {}).get("system_type", "")} for h in hosts],
                             "edges": edges},
    }


def audit_log(conn, case_pk: int, limit: int = 200, before_id: int | None = None) -> list[dict]:
    q = "SELECT * FROM audit WHERE case_pk=?"
    args: list = [case_pk]
    if before_id:
        q += " AND id < ?"
        args.append(before_id)
    q += " ORDER BY id DESC LIMIT ?"
    args.append(limit)
    return [{"id": r["id"], "ts": r["ts"], "username": r["username"], "action": r["action"],
             "section": r["section"], "recid": r["recid"],
             "before": json.loads(r["before_data"]) if r["before_data"] else None,
             "after": json.loads(r["after_data"]) if r["after_data"] else None} for r in conn.execute(q, args)]


# --------------------------------------------------------------------------- #
# Export
# --------------------------------------------------------------------------- #

def build_fox(conn, case_pk: int, locked: bool = False) -> tuple[dict, int]:
    """Must be called inside read_tx for a consistent snapshot."""
    row = get_case_row(conn, case_pk)
    meta = json.loads(row["meta"])
    sections = {}
    for key in S.SECTION_ORDER:
        recs = []
        for r in conn.execute("SELECT recid, data FROM records WHERE case_pk=? AND section=?", (case_pk, key)):
            data = json.loads(r["data"])
            rec = {"recid": r["recid"]}
            rec.update(data)
            if "w2ui" in rec:
                rec["w2ui"] = {}
            recs.append(rec)
        # Same default order as the UI and the API (the Excel export is built from this document too).
        sections[key] = S.sort_default(S.SECTIONS[key], recs, lambda rec: (rec, rec["recid"]))

    doc: dict = {}
    for k in S.TOP_LEVEL_ORDER:
        if k == "storage_format_version":
            doc[k] = S.STORAGE_FORMAT_VERSION
        elif k == "locked":
            doc[k] = bool(locked)
        elif k in ("case_id", "client", "start_date"):
            doc[k] = meta.get(k, "")
        elif k == "summary":
            doc[k] = S.join_lines(meta.get(k, "")).strip()     # Aurora's summary is a single line
        elif k == "hosts":
            doc[k] = meta.get("extra", {}).get("hosts", [])
        elif k in sections:
            doc[k] = sections[k]
        elif k in S.LOOKUP_KEYS:
            doc[k] = meta["lookups"].get(k) or S.default_lookups()[k]
    # Integration settings: the MISP server/event are exported, API keys always as blanks (privacy). They stay
    # in the server database only; whoever opens the file in Aurora enters their own keys.
    if any(meta.get(k) for k in ("mispserver", "mispapikey", "mispeventid", "vtapikey")):
        for k in ("mispserver", "mispapikey", "mispeventid", "vtapikey"):
            doc[k] = "" if k in S.SECRET_CASE_FIELDS else meta.get(k, "")
    for k, v in meta.get("extra", {}).items():
        if k not in doc:
            doc[k] = v
    return doc, row["revision"]


def integrity_errors(doc: dict) -> list[str]:
    """Independent re-check of an exported document before it leaves the server."""
    errs = []
    for k in S.TOP_LEVEL_ORDER:
        if k not in doc:
            errs.append(f"missing top-level key {k}")
    if doc.get("storage_format_version") != S.STORAGE_FORMAT_VERSION:
        errs.append("wrong storage_format_version")
    for k in S.SECTION_ORDER + S.LOOKUP_KEYS + ["hosts"]:
        if not isinstance(doc.get(k), list):
            errs.append(f"{k} is not a list")
    if errs:
        return errs
    keysets = {}
    for key, sec in S.SECTIONS.items():
        ids = set()
        for r in doc[key]:
            if not isinstance(r, dict) or not isinstance(r.get("recid"), int):
                errs.append(f"{key}: bad record")
                continue
            if r["recid"] in ids:
                errs.append(f"{key}: duplicate recid {r['recid']}")
            ids.add(r["recid"])
            for f in sec.fields:
                if f.name in r:
                    try:
                        S.validate_value(f, r[f.name])
                    except FieldError as e:
                        errs.append(f"{key} recid {r['recid']} {f.name}: {e}")
        if sec.key_field:
            vals = [r.get(sec.key_field) for r in doc[key] if isinstance(r, dict)]
            keysets[key] = {v for v in vals if v}
            if sec.unique_key:
                low = [v.lower() for v in vals if isinstance(v, str)]
                if len(low) != len(set(low)) or any(not v for v in vals):
                    errs.append(f"{key}: empty or duplicate {sec.key_field}")
    lookups = {k: {i.get("text") for i in doc[k] if isinstance(i, dict)} for k in S.LOOKUP_KEYS}
    for key, sec in S.SECTIONS.items():
        for r in doc[key]:
            for f in sec.fields:
                v = r.get(f.name) if isinstance(r, dict) else None
                if not v:
                    continue
                if f.kind == "ref" and v not in keysets[f.ref]:
                    errs.append(f"{key} recid {r['recid']} {f.name}: '{v}' not declared in {f.ref}")
                if f.kind == "enum" and v not in lookups[f.enum]:
                    errs.append(f"{key} recid {r['recid']} {f.name}: '{v}' not in {f.enum}")
    return errs[:100]


def serialize_fox(doc: dict) -> bytes:
    """Byte-compatible with Aurora's JSON.stringify(case_data, null, "\\t")."""
    text = json.dumps(doc, ensure_ascii=False, indent="\t", allow_nan=False)   # ValueError on NaN/Infinity
    out = text.encode("utf-8")
    if json.loads(out.decode("utf-8")) != doc:      # paranoia: round-trip check
        raise RuntimeError("serialisation round-trip mismatch")
    return out


def export_fox(conn, case_pk: int, locked: bool = False) -> tuple[bytes, dict, int]:
    from .db import read_tx
    with read_tx(conn):
        doc, rev = build_fox(conn, case_pk, locked)
    errs = integrity_errors(doc)
    if errs:
        raise RuntimeError("export failed integrity check: " + "; ".join(errs))
    return serialize_fox(doc), doc, rev

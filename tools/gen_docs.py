#!/usr/bin/env python3
"""
Regenerate the code-derived documentation so it can never drift from the implementation:

    docs/data-model.md   sections, fields, kinds, limits, references (from app/schema.py)
    docs/openapi.json    OpenAPI 3 description of the REST API (from app/main.py)
    docs/schema.sql      database schema (from app/db.py)

Run from the repository root:  python3 tools/gen_docs.py
"""
import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ.setdefault("DATA_DIR", tempfile.mkdtemp(prefix="aurora-docs-"))
os.environ.setdefault("ADMIN_PASSWORD", "docs-generation-only")

from app import schema as S  # noqa: E402
from app.main import app  # noqa: E402

DOCS = ROOT / "docs"

KIND_HELP = {
    "text": "single-line text (no line breaks / control characters; TAB and Unicode are allowed)",
    "longtext": "longer single-line text (shown wrapped in a text box; line breaks are rejected as in `text`)",
    "multiline": "free text that may span lines (case summary and Report page only; never a record field)",
    "bool": "true / false",
    "datetime": "UTC `YYYY-MM-DD HH:MM:SS`; ISO 8601 input with `T`, `Z`, `UTC` or `±HH:MM` is converted to UTC",
    "date": "`YYYY-MM-DD`",
    "ip": "IPv4 or IPv6 address (normalised)",
    "port": "0-65535, stored as a string (Aurora format)",
    "int": "non-negative integer",
    "hash": "hex digest of 32/40/56/64/96/128 characters (MD5, SHA-1, SHA-2)",
    "email": "e-mail address",
    "url": "URL / URI without whitespace (stored as text, never rendered as a link)",
    "enum": "must be a value of the case's lookup list (see `GET /api/cases/{id}/options`)",
    "ref": "must equal the key of an existing record in the referenced section",
    "auto_ms": "set by the server: epoch milliseconds (UTC), plus an ISO twin `<field>_`",
    "readonly": "carried through from Aurora, not editable",
}


def data_model() -> str:
    out = ["# Data model", "",
           "_Generated from `app/schema.py` by `tools/gen_docs.py`. Do not edit by hand._", "",
           "A case is an Aurora `.fox` document (storage format "
           f"{S.STORAGE_FORMAT_VERSION}). Each **section** is a list of records; every record has a `recid` "
           "(unique within its section) and, in this application, a `version` used for optimistic locking.", "",
           "## Field kinds", "", "| kind | accepted values |", "|---|---|"]
    out += [f"| `{k}` | {v} |" for k, v in KIND_HELP.items()]
    out += ["", "## Relational rules", "",
            "| referenced section (key field) | referenced from |", "|---|---|"]
    for target, srcs in S.REFERENCES.items():
        out.append(f"| `{target}` (`{S.SECTIONS[target].key_field}`) | "
                   + ", ".join(f"`{s}.{f}`" for s, f in srcs) + " |")
    out += ["",
            "* Systems hostnames and investigator short names are unique (case-insensitive).",
            "* Renaming a referenced record updates every reference; deleting one that is still referenced is refused (409).",
            "* `declare_missing=true` on create/update/bulk/import creates missing referenced records (key field only).",
            "", "## Case details", "", "| field | label | kind | max | notes |", "|---|---|---|---|---|"]
    for f in S.CASE_FIELDS.values():
        note = ("secret, write-only and encrypted at rest: never returned by the API, exported blank in .fox, absent from Excel/PDF/LaTeX"
                if f.name in S.SECRET_CASE_FIELDS else
                "platform only (never in the .fox), default true" if f.name in S.LOCAL_CASE_FIELDS else
                "platform only (never in the .fox); shown in the Excel, PDF and LaTeX reports" if f.name in S.PLATFORM_CASE_FIELDS else
                ("required" if f.required else ""))
        out.append(f"| `{f.name}` | {f.label} | `{f.kind}` | {f.max_len if f.kind in ('text', 'longtext') else ''} | {note} |")
    out += ["", "## Single-line text", "",
            "Every record field, case detail (except the summary) and lookup value must be a single line, because "
            "multi-line values break the Aurora desktop grids. The API rejects line breaks (`\\n`, `\\r`, "
            "U+2028, U+2029) with a 422 validation error. A `.fox` import joins line breaks in records with a space "
            "and reports it as a warning. The browser keeps wrapping text boxes but ignores Enter and joins pasted "
            "lines. The case `summary` (= executive-summary context) may span lines; the `.fox` export writes it as "
            "one line.", "",
            "## Report page", "",
            "Stored per case, never written to the `.fox` (`GET`/`PATCH /api/cases/{id}/report`); included in the "
            "Excel, PDF and LaTeX exports.", "",
            "| field | label | kind | max |", "|---|---|---|---|"]
    out += [f"| `{f.name}` | {f.label} | `{f.kind}` | {f.max_len} |" for f in S.REPORT_FIELDS.values()]
    out += ["", "`context` is the case's `summary` field.", "",
            "## Default record order", "",
            "Records are returned by the API, shown in the UI and written to the `.fox`, Excel, PDF and LaTeX exports "
            "in this order. Empty values always come last; equal values keep `recid` order. Text compares "
            "case-insensitively with numbers in natural order (`host2` before `host10`), IP addresses "
            "numerically (IPv4 before IPv6). `sort`/`order` on `GET .../sections/{section}` "
            "override it for one request.", "",
            "| section | default order |", "|---|---|"]
    for key in S.SECTION_ORDER:
        sec = S.SECTIONS[key]
        out.append(f"| `{key}` | " + ", then ".join(
            f"{sec.fieldmap[n].label} (`{n}`) {'newest first' if o == 'desc' and sec.fieldmap[n].kind in ('datetime', 'date', 'auto_ms') else 'oldest first' if sec.fieldmap[n].kind in ('datetime', 'date', 'auto_ms') else 'descending' if o == 'desc' else 'ascending'}"
            for n, o in sec.default_order) + " |")
    out += ["", "## Lookup lists (defaults)", "",
            "Enum fields take their allowed values from these per-case lists (imported from the .fox).", ""]
    for k, items in S.default_lookups().items():
        out.append(f"* `{k}`: " + ", ".join(f"`{i['text']}`" for i in items))
    out += ["", "## Sections", ""]
    for key in S.SECTION_ORDER:
        sec = S.SECTIONS[key]
        out += [f"### `{key}` ({sec.label})", ""]
        if sec.key_field:
            out.append(f"Key field: `{sec.key_field}`{' (unique)' if sec.unique_key else ''}. ")
        if sec.auto_date_updated:
            out.append("`date_updated` is refreshed by the server on every change. ")
        if sec.default_order:
            out.append("Default order: " + ", then ".join(f"`{n}` {o}" for n, o in sec.default_order) + ". ")
        out += ["", "| field | label | kind | required | max | allowed / references |", "|---|---|---|---|---|---|"]
        for f in sec.fields:
            allowed = (f"lookup `{f.enum}`" if f.kind == "enum" else f"→ `{f.ref}`" if f.kind == "ref"
                       else ", ".join(f"`{c}`" for c in f.choices if c) if f.choices else "")
            mx = f.max_len if f.kind in ("text", "longtext") else ""
            out.append(f"| `{f.name}` | {f.label} | `{f.kind}` | {'yes' if f.required else ''} | {mx} | {allowed} |")
        out.append("")
    return "\n".join(out) + "\n"


def schema_sql() -> str:
    from app.db import schema_sql as ddl
    return ("-- Aurora IR Web database schema (MariaDB 10.6+ / MySQL 8.0+, InnoDB, utf8mb4).\n"
            "-- Generated from app/db.py by tools/gen_docs.py. Do not edit by hand.\n"
            "-- The application creates these tables itself on start-up (CREATE TABLE IF NOT EXISTS). Use this file\n"
            "-- to review the schema or to pre-create the tables on an external server.\n\n" + ddl())


def main():
    DOCS.mkdir(exist_ok=True)
    (DOCS / "data-model.md").write_text(data_model(), encoding="utf-8")
    (DOCS / "schema.sql").write_text(schema_sql(), encoding="utf-8")
    (DOCS / "openapi.json").write_text(json.dumps(app.openapi(), indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print("wrote docs/data-model.md, docs/schema.sql, docs/openapi.json")


if __name__ == "__main__":
    main()

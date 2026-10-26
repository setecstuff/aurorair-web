"""
Section / field definitions for Aurora IR storage format v7, plus validators.

This module is the single source of truth: the API validates against it, the
browser UI renders forms/tables from it (via /api/schema) and the exporter uses
it to build records that Aurora can load.

Field names and value formats mirror Aurora's gui_definitions.js / controller.js:
  * list editors (systems, investigators, lookups) store the plain `text` string
  * datetime editors store "YYYY-MM-DD HH:MM:SS" - always UTC in this application
  * date editors store "YYYY-MM-DD"
  * date_added / date_updated are JS epoch milliseconds (int)
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

STORAGE_FORMAT_VERSION = 7

# Fox keys that are record grids (in Aurora's data_template order).
SECTION_ORDER = [
    "timeline", "investigated_systems", "malware", "compromised_accounts",
    "network_indicators", "exfiltration", "systems", "osint",
    "investigators", "evidence", "actions", "casenotes",
]

# Fox keys holding lookup lists ({id, text}) used by the dropdowns.
LOOKUP_KEYS = [
    "event_types", "system_types", "verdicts", "status", "task_types",
    "direction", "killchain", "evidence_types",
]

# Top-level key order of data_template.js. "hosts" is a legacy, UI-less list
# that is carried through untouched.
TOP_LEVEL_ORDER = (
    ["storage_format_version", "locked", "case_id", "client", "start_date", "summary"]
    + ["timeline", "investigated_systems", "malware", "compromised_accounts",
       "network_indicators", "exfiltration", "hosts", "systems", "osint",
       "investigators", "evidence", "actions", "casenotes"]
    + LOOKUP_KEYS
)

DEFAULT_LOOKUPS = {
    "event_types": ["EventLog", "File", "Human", "Engagement", "Lateral Movement", "Exfil",
                    "Tanium Trace", "Malware", "eMail", "Misc", "C2"],
    "system_types": ["Desktop", "Server", "Phone", "Tablet", "TV", "Networking device",
                     "IoT device", "Other", "Attacker Infra"],
    "verdicts": [(1, "Infected"), (2, "Accessed"), (3, "Commodity"), (3, "Clean")],
    "status": ["Assigned", "In Progress", "Completed", "Closed", "Rejected"],
    "task_types": ["Information request", "Analysis", "Deliverable", "Checkpoint", "Other"],
    "direction": ["<-", "->"],
    "killchain": ["Recon", "Weaponization", "Delivery", "Exploitation", "Installation",
                  "C2", "Actions on Obj."],
    "evidence_types": ["File", "System Logs", "Network Logs", "Triaged System", "Cloned System",
                       "Memory Dump", "External Source", "Other"],
}


def default_lookups() -> dict[str, list[dict]]:
    out = {}
    for key, items in DEFAULT_LOOKUPS.items():
        lst = []
        for i, it in enumerate(items, 1):
            if isinstance(it, tuple):
                lst.append({"id": it[0], "text": it[1]})
            else:
                lst.append({"id": i, "text": it})
        out[key] = lst
    return out


class ValidationError(Exception):
    def __init__(self, errors: list[dict]):
        super().__init__("; ".join(f"{e.get('field')}: {e.get('message')}" for e in errors))
        self.errors = errors


# --------------------------------------------------------------------------- #
# Field definitions
# --------------------------------------------------------------------------- #

@dataclass
class Field:
    name: str
    label: str
    kind: str                 # text | longtext | bool | datetime | date | ip | port | int |
                              # hash | email | url | enum | ref | auto_ms | readonly
    max_len: int = 1000
    required: bool = False
    enum: str | None = None   # lookup list key (for kind=enum)
    ref: str | None = None    # target section (for kind=ref)
    choices: list[str] | None = None  # fixed choices (kind=readonly enums like vt)
    in_table: bool = True
    width: str = ""

    @property
    def editable(self) -> bool:
        return self.kind not in ("auto_ms", "readonly")

    def default(self) -> Any:
        if self.kind == "bool":
            return False
        return ""

    def to_public(self) -> dict:
        return {
            "name": self.name, "label": self.label, "kind": self.kind,
            "max_len": self.max_len, "required": self.required, "enum": self.enum,
            "ref": self.ref, "editable": self.editable, "in_table": self.in_table,
            "width": self.width,
        }


@dataclass
class Section:
    key: str
    label: str
    group: str
    fields: list[Field]
    key_field: str | None = None      # field other sections reference
    unique_key: bool = False          # key_field must be unique within the case
    auto_date_updated: bool = False   # investigated_systems maintains date_updated
    # Default record order everywhere (UI, API, .fox, Excel, PDF and LaTeX exports): (field, "asc" | "desc") pairs,
    # most significant first. Empty values always sort last; ties keep recid order.
    default_order: tuple[tuple[str, str], ...] = ()
    fieldmap: dict[str, Field] = field(init=False)

    def __post_init__(self):
        self.fieldmap = {f.name: f for f in self.fields}

    def to_public(self) -> dict:
        return {"key": self.key, "label": self.label, "group": self.group,
                "key_field": self.key_field, "fields": [f.to_public() for f in self.fields],
                "default_order": [{"field": n, "order": o} for n, o in self.default_order]}


T, L = 1000, 20000   # default max lengths: single-line text / long text

SECTIONS: dict[str, Section] = {s.key: s for s in [
    Section("timeline", "Timeline", "Investigation", default_order=(("date_time", "desc"),), fields=[
        Field("date_time", "Date/Time", "datetime", width="150px"),
        Field("event_type", "Type", "enum", enum="event_types", width="90px"),
        Field("event_host", "Event System", "ref", ref="systems", width="160px"),
        Field("direction", "⇄", "enum", enum="direction", width="40px"),
        Field("event_source_host", "Remote System", "ref", ref="systems", width="160px"),
        Field("killchain", "Killchain", "enum", enum="killchain", width="110px"),
        Field("event_data", "Event", "longtext", max_len=L, width="40%"),
        Field("notes", "Notes", "longtext", max_len=L, width="25%"),
        Field("visual", "Visual?", "bool", width="50px"),
        Field("followup", "Followup", "bool", width="50px"),
        Field("attribution", "Attribution", "text", max_len=200, width="90px"),
        Field("owner", "Owner", "ref", ref="investigators", width="70px"),
    ]),
    Section("investigated_systems", "Investigated Systems", "Investigation", auto_date_updated=True,
            default_order=(("hostname", "asc"),), fields=[
        Field("date_added", "Date added", "auto_ms", width="95px"),
        Field("date_updated", "Date updated", "auto_ms", width="95px"),
        Field("first_compromise", "First Compromise", "datetime", width="150px"),
        Field("hostname", "Hostname", "ref", ref="systems", required=True, width="180px"),
        Field("verdict", "Verdict", "enum", enum="verdicts", width="90px"),
        Field("summary", "Summary", "longtext", max_len=L, width="40%"),
        Field("analysis_required", "Analysis req?", "bool", width="60px"),
        Field("analysis_status", "Analysis status", "enum", enum="status", width="100px"),
        Field("analyst", "Analyst", "ref", ref="investigators", width="70px"),
        Field("report_status", "Report Status", "enum", enum="status", width="100px"),
    ]),
    Section("malware", "Malware/Tools", "Investigation", key_field="text",
            default_order=(("hostname", "asc"), ("text", "asc")), fields=[
        Field("date_added", "Date added", "auto_ms", width="95px"),
        Field("text", "Filename", "text", max_len=500, required=True, width="140px"),
        Field("path_on_disk", "Path on Disk", "text", max_len=4000, width="200px"),
        Field("creation_date", "Creation Date", "datetime", width="150px"),
        Field("modification_date", "Last modified", "datetime", width="150px"),
        Field("hostname", "Host", "ref", ref="systems", width="160px"),
        Field("md5", "Hash", "hash", width="140px"),
        Field("vt", "vt", "readonly", choices=["", "infected", "clean", "noresult"], width="40px"),
        Field("attribution", "Attribution", "text", max_len=200, width="90px"),
        Field("notes", "notes", "longtext", max_len=L, width="35%"),
    ]),
    Section("compromised_accounts", "Compromised Accounts", "Investigation",
            default_order=(("domain", "asc"), ("account_name", "asc")), fields=[
        Field("date_added", "Date added", "auto_ms", width="95px"),
        Field("account_name", "Account Name", "text", max_len=256, required=True, width="130px"),
        Field("domain", "Account Domain", "text", max_len=256, width="120px"),
        Field("sid", "SID", "text", max_len=256, width="200px"),
        Field("context", "Context", "longtext", max_len=L, width="40%"),
        Field("last_activity", "Last Activity", "datetime", width="150px"),
        Field("privileges", "Privileges", "text", max_len=T, width="110px"),
        Field("attribution", "Attribution", "text", max_len=200, width="90px"),
    ]),
    Section("network_indicators", "Network Indicators", "Investigation",
            default_order=(("ip", "asc"), ("domainname", "asc")), fields=[
        Field("date_added", "Date added", "auto_ms", width="95px"),
        Field("ip", "IP", "ip", width="120px"),
        Field("domainname", "Domainname", "text", max_len=500, width="180px"),
        Field("port", "Port", "port", width="60px"),
        Field("context", "Context", "longtext", max_len=L, width="40%"),
        Field("last_activity", "Last activity", "datetime", width="150px"),
        Field("malware", "Malware", "ref", ref="malware", width="120px"),
        Field("whois", "Whois", "longtext", max_len=50000, width="100px"),
        Field("attribution", "Attribution", "text", max_len=200, width="90px"),
    ]),
    Section("exfiltration", "Exfiltration", "Investigation", default_order=(("exfiltime", "desc"),), fields=[
        Field("created", "Created", "datetime", width="150px"),
        Field("exfiltime", "Exfil Time", "datetime", width="150px"),
        Field("stagingsystem", "Staging System", "ref", ref="systems", width="150px"),
        Field("original", "Original System", "ref", ref="systems", width="150px"),
        Field("exfil_to", "Exfiltrated to", "ref", ref="systems", width="150px"),
        Field("filename", "Filename", "text", max_len=1000, width="130px"),
        Field("size", "Size", "int", width="80px"),
        Field("contents", "Contents", "longtext", max_len=L, width="35%"),
        Field("notes", "Context", "longtext", max_len=L, width="20%"),
        Field("attribution", "Attribution", "text", max_len=200, width="90px"),
    ]),
    Section("osint", "OSInt", "Investigation", default_order=(("text", "asc"),), fields=[
        Field("text", "Short Name", "text", max_len=200, width="120px"),
        Field("url", "URL", "url", width="35%"),
        Field("desc", "Description", "longtext", max_len=L, width="50%"),
    ]),
    Section("systems", "Systems", "Investigation", key_field="text", unique_key=True,
            default_order=(("text", "asc"),), fields=[
        Field("text", "Hostname", "text", max_len=255, required=True, width="240px"),
        Field("ip", "IP", "ip", width="120px"),
        Field("system_type", "Type", "enum", enum="system_types", width="110px"),
        Field("os", "Operating System", "text", max_len=200, width="160px"),
        Field("owner", "Owner", "text", max_len=200, width="130px"),
        Field("description", "Description", "longtext", max_len=L, width="40%"),
        Field("pin", "Pin", "bool", width="45px"),
    ]),
    Section("investigators", "Investigators", "Case Management", key_field="text", unique_key=True,
            default_order=(("text", "asc"),), fields=[
        Field("text", "Short Name", "text", max_len=20, required=True, width="100px"),
        Field("full_name", "Full Name", "text", max_len=200, width="25%"),
        Field("affiliation", "🏢 Affiliation", "text", max_len=200, width="130px"),
        Field("role", "🙋 Role", "text", max_len=200, width="150px"),
        Field("contact_email", "📬 Email", "email", width="170px"),
        Field("contact_phone", "📱 Phone", "text", max_len=60, width="120px"),
        Field("contact_other", "📖 Other", "text", max_len=T, width="20%"),
    ]),
    Section("evidence", "Evidence", "Case Management",
            default_order=(("date_acquired", "desc"), ("name", "asc")), fields=[
        Field("date_acquired", "Date Acquired", "datetime", width="150px"),
        Field("type", "Type", "enum", enum="evidence_types", width="120px"),
        Field("name", "Name", "text", max_len=500, required=True, width="140px"),
        Field("description", "Description", "longtext", max_len=L, width="35%"),
        Field("size", "Size", "text", max_len=100, width="80px"),
        Field("hash", "Hash", "text", max_len=500, width="150px"),
        Field("provider", "Provided by", "ref", ref="investigators", width="100px"),
        Field("location", "Location", "text", max_len=T, width="150px"),
    ]),
    Section("actions", "Action Items", "Case Management", default_order=(("date_added", "asc"),), fields=[
        Field("date_added", "Date added", "auto_ms", width="95px"),
        Field("date_due", "Date Due", "date", width="100px"),
        Field("task_type", "Type", "enum", enum="task_types", width="140px"),
        Field("task", "Task", "longtext", max_len=L, required=True, width="50%"),
        Field("status", "Status", "enum", enum="status", width="110px"),
        Field("owner", "Owner", "ref", ref="investigators", width="80px"),
    ]),
    Section("casenotes", "Case Notes", "Case Management", default_order=(("date_added", "desc"),), fields=[
        Field("date_added", "Date added", "auto_ms", width="95px"),
        Field("note", "Note", "longtext", max_len=L, required=True, width="75%"),
        Field("owner", "Owner", "ref", ref="investigators", width="80px"),
    ]),
]}

# Reverse index: target section -> [(source section, field name)]
REFERENCES: dict[str, list[tuple[str, str]]] = {}
for _s in SECTIONS.values():
    for _f in _s.fields:
        if _f.kind == "ref":
            REFERENCES.setdefault(_f.ref, []).append((_s.key, _f.name))

# Case metadata (the "Case Configuration" popup in Aurora).
CASE_FIELDS: dict[str, Field] = {f.name: f for f in [
    Field("case_id", "Case ID", "text", max_len=100, required=True),
    Field("client", "Client", "text", max_len=200),
    Field("start_date", "Engagement start", "date"),
    Field("end_date", "Engagement end", "date"),          # platform only: for the reports, never in the .fox
    # Multi-line here; written to the .fox as one line (line breaks become spaces).
    Field("summary", "Summary / context", "multiline", max_len=100000),
    Field("mispeventid", "MISP event ID", "text", max_len=50),
    Field("use_server_misp", "Use the server-wide MISP", "bool"),
    Field("mispserver", "MISP server URL", "url"),
    Field("mispapikey", "MISP API key", "text", max_len=200),
    Field("use_server_vt", "Use the server-wide VirusTotal key", "bool"),
    Field("vtapikey", "VirusTotal API key", "text", max_len=200),
]}
SECRET_CASE_FIELDS = {"mispapikey", "vtapikey"}
# Platform-only case settings: never written to a .fox (Aurora has no such fields), on by default. On: the
# server-wide settings; off: the case's own (stored values are kept while the switch is on, just not used).
LOCAL_CASE_FIELDS = {"use_server_misp": True, "use_server_vt": True}
_OWN_VALUES = {"use_server_misp": ("mispserver", "mispapikey"), "use_server_vt": ("vtapikey",)}
# Case details that exist only on this platform: never written to or read from a .fox, kept on a replace.
PLATFORM_CASE_FIELDS = {"end_date", *LOCAL_CASE_FIELDS}


def case_value(meta: dict, name: str):
    """A case detail, with the defaults of the platform-only settings. Cases stored before the switches existed
    keep using their own MISP / VirusTotal settings if they have any."""
    if name in LOCAL_CASE_FIELDS:
        v = meta.get(name)
        if v in (None, ""):
            return not any(meta.get(k) for k in _OWN_VALUES[name])
        return bool(v)
    return meta.get(name, "")

# Report page (executive summary, context, conclusions, lessons learned). Never written to the .fox; "context" is the case's Summary field (which is).
REPORT_FIELDS: dict[str, Field] = {f.name: f for f in [
    Field("executive_summary", "Executive summary", "multiline", max_len=200000),
    Field("context", "Context", "multiline", max_len=100000),
    Field("conclusions", "Conclusions", "multiline", max_len=200000),
    Field("lessons_learned", "Lessons learned", "multiline", max_len=200000),
]}


# --------------------------------------------------------------------------- #
# Value validators
# --------------------------------------------------------------------------- #

# All text is single-line (multi-line values break the Aurora desktop grids): C0 controls except TAB, DEL,
# C1 controls and the Unicode line/paragraph separators are rejected. Unicode is otherwise allowed, because
# forensic artefacts legitimately contain odd characters.
_BAD_TEXT = re.compile(r"[\x00-\x08\x0a-\x1f\x7f-\x9f\u2028\u2029]")
_LINE_BREAK = re.compile(r"[\r\n\u2028\u2029]")
_LINE_BREAK_RUN = re.compile(r"[ \t]*(?:\r\n|[\r\n\u2028\u2029])+[ \t]*")
# Accepts "YYYY-MM-DD HH:MM[:SS][.fff]" optionally followed by Z, UTC/GMT or a +HH:MM / -HHMM offset.
_DT_RE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2})(?::(\d{2}))?(?:\.\d+)?"
                    r"\s*(Z|UTC|GMT|[+-]\d{2}:?\d{2})?$", re.IGNORECASE)
_DATE_RE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})$")
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,255}$")
_URL_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")


class FieldError(Exception):
    pass


def _as_str(v: Any) -> str:
    if v is None:
        return ""
    if isinstance(v, bool):
        raise FieldError("expected text")
    if isinstance(v, (int, float)):
        return str(v)
    if isinstance(v, dict) and isinstance(v.get("text"), str):
        # some w2ui versions store list selections as {id, text}
        return v["text"]
    if not isinstance(v, str):
        raise FieldError("expected text")
    return v


def _check_text(s: str, max_len: int, multiline: bool = False) -> str:
    """`multiline` is kept for callers' readability only: line breaks are never accepted."""
    if len(s) > max_len:
        raise FieldError(f"too long (max {max_len} characters)")
    if _BAD_TEXT.search(s):
        if _LINE_BREAK.search(s):
            raise FieldError("line breaks are not allowed (text must be a single line)")
        raise FieldError("contains control characters")
    return s


_BAD_MULTILINE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")


def check_multiline(s: str, max_len: int) -> str:
    """Free text that may span several lines (case summary, Report page). Line endings are
    normalised to \\n; other control characters are rejected."""
    s = s.replace("\r\n", "\n").replace("\r", "\n").replace("\u2028", "\n").replace("\u2029", "\n\n")
    if len(s) > max_len:
        raise FieldError(f"too long (max {max_len} characters)")
    if _BAD_MULTILINE.search(s):
        raise FieldError("contains control characters")
    return s


def has_line_breaks(v: Any) -> bool:
    return isinstance(v, str) and bool(_LINE_BREAK.search(v))


def join_lines(s: str) -> str:
    """Replace each run of line breaks (and the blanks around it) by one space. Used for .fox imports and the
    one-time migration of data stored before single-line text was enforced."""
    return _LINE_BREAK_RUN.sub(" ", s)


def norm_datetime(s: str) -> str:
    s = s.strip()
    if not s:
        return ""
    m = _DT_RE.match(s)
    if not m:
        raise FieldError("expected YYYY-MM-DD HH:MM:SS (UTC, or with a +HH:MM offset to convert)")
    y, mo, d, h, mi, se, tz = m.groups()
    try:
        dt = datetime(int(y), int(mo), int(d), int(h), int(mi), int(se or 0))
    except ValueError:
        raise FieldError("not a valid date/time")
    # All stored times are UTC. A value without zone is taken as UTC; an explicit offset is converted.
    if tz and tz[0] in "+-":
        hh, mm = int(tz[1:3]), int(tz[-2:])
        if hh > 23 or mm > 59:
            raise FieldError("invalid UTC offset")
        sign = 1 if tz[0] == "+" else -1
        dt = dt - sign * timedelta(hours=hh, minutes=mm)
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def norm_date(s: str) -> str:
    s = s.strip()
    if not s:
        return ""
    m = _DATE_RE.match(s)
    if not m:
        raise FieldError("expected YYYY-MM-DD")
    try:
        datetime(int(m[1]), int(m[2]), int(m[3]))
    except ValueError:
        raise FieldError("not a valid date")
    return s


def validate_value(f: Field, v: Any) -> Any:
    """Validate and normalise a single value. Enum/ref membership is checked by the caller."""
    k = f.kind
    if k == "bool":
        if isinstance(v, bool):
            return v
        if v in (None, "", 0, "false", "False"):
            return False
        if v in (1, "true", "True"):
            return True
        raise FieldError("expected true/false")

    if k == "auto_ms":
        if v in (None, ""):
            return ""
        if isinstance(v, bool) or not isinstance(v, (int, float)):
            # Aurora writes epoch ms; tolerate date strings from older files
            s = _as_str(v)
            return _check_text(s, 64, False)
        return int(v)

    if k == "int":
        if v in (None, ""):
            return ""
        if isinstance(v, bool):
            raise FieldError("expected a number")
        if isinstance(v, str):
            v = v.strip()
            if not v:
                return ""
            if not v.isdigit():
                raise FieldError("expected a whole number")
            v = int(v)
        if isinstance(v, float) and v.is_integer():
            v = int(v)
        if not isinstance(v, int) or v < 0 or v > 10**18:
            raise FieldError("expected a non-negative whole number")
        return v

    if k == "port":
        if v in (None, ""):
            return ""
        if isinstance(v, bool):
            raise FieldError("expected a port number")
        s = str(v).strip()
        if not s:
            return ""
        if not s.isdigit() or not (0 <= int(s) <= 65535):
            raise FieldError("expected a port number 0-65535")
        return str(int(s))      # Aurora files store the port as a string

    s = _as_str(v)

    if k == "readonly":
        if f.choices is not None and s not in f.choices:
            raise FieldError("invalid value")
        return s
    if k == "datetime":
        return norm_datetime(s)
    if k == "date":
        return norm_date(s)
    if k == "ip":
        s = s.strip()
        if not s:
            return ""
        try:
            return str(ipaddress.ip_address(s))
        except ValueError:
            raise FieldError("not a valid IPv4/IPv6 address")
    if k == "hash":
        s = s.strip()
        if not s:
            return ""
        if not _HEX_RE.match(s) or len(s) not in (32, 40, 56, 64, 96, 128):
            raise FieldError("expected an MD5/SHA1/SHA2 hex digest")
        return s
    if k == "email":
        s = s.strip()
        if not s:
            return ""
        _check_text(s, 320, False)
        if not _EMAIL_RE.match(s):
            raise FieldError("not a valid e-mail address")
        return s
    if k == "url":
        s = s.strip()
        if not s:
            return ""
        _check_text(s, 4096, False)
        if any(c.isspace() for c in s):
            raise FieldError("URLs cannot contain whitespace")
        return s
    if k in ("text", "enum", "ref"):
        s = _check_text(s, f.max_len if k == "text" else 1000, False)
        return s.strip() if k != "text" or f.required else s
    if k == "longtext":
        return _check_text(s, f.max_len, True)
    if k == "multiline":
        return check_multiline(s, f.max_len)
    raise FieldError(f"unsupported field kind {k}")


def now_ms() -> int:
    return int(datetime.now(timezone.utc).timestamp() * 1000)


def ms_to_iso(ms: int) -> str:
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + \
        f"{ms % 1000:03d}Z"


def coerce_fox_date(f: "Field", v: Any) -> Any:
    """Aurora's desktop app stores its date-picker fields as epoch milliseconds (with a display twin such as
    `date_due_`), while free-text date/time fields are strings. On .fox import, convert an epoch-ms value for a
    `date` / `datetime` field to the string format this application expects (UTC, matching the display twin).
    Anything that is not epoch ms - the common case, a normal string - is returned unchanged for the usual
    validation to handle."""
    if f.kind not in ("date", "datetime") or isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        ms = int(v)
    elif isinstance(v, str) and v.strip().isdigit() and len(v.strip()) >= 12:
        ms = int(v.strip())                      # epoch ms as a numeric string (>= ~year 2001)
    else:
        return v
    try:
        dt = datetime.fromtimestamp(ms / 1000, tz=timezone.utc)
    except (ValueError, OverflowError, OSError):
        return v                                 # out of range: let validate_value raise the normal error
    return dt.strftime("%Y-%m-%d" if f.kind == "date" else "%Y-%m-%d %H:%M:%S")


# --------------------------------------------------------------------------- #
# Ordering
# --------------------------------------------------------------------------- #

_DIGITS = re.compile(r"(\d+)")


def natural_key(s: str) -> tuple:
    """Case-insensitive alphabetical order that compares digit runs as numbers (host2 < host10, IR-608 < IR-609)."""
    return tuple((0, int(p), "") if p.isdigit() else (1, 0, p) for p in _DIGITS.split(s.casefold()) if p != "")


def _value_key(f: Field | None, v: Any) -> tuple:
    if isinstance(v, bool):
        return (0, int(v))
    if isinstance(v, (int, float)):
        return (0, v)
    s = str(v)
    if f is not None and f.kind == "ip":
        try:
            a = ipaddress.ip_address(s.strip())
            return (1, a.version, int(a))
        except ValueError:
            pass
    if f is not None and f.kind in ("datetime", "date"):
        return (2, s)                        # normalised YYYY-MM-DD[ HH:MM:SS] sorts chronologically as text
    if f is not None and f.kind == "auto_ms" and s.strip().lstrip("-").isdigit():
        return (0, int(s))
    return (3, natural_key(s))


def is_empty(v: Any) -> bool:
    return v is None or v == "" or (isinstance(v, str) and not v.strip())


def sort_by_fields(sec: Section, items: list, order: list[tuple[str, str]], get=lambda x: x) -> list:
    """Stable multi-key sort. `get(item)` returns (data, recid). Empty values always come last, whatever the
    direction; remaining ties keep recid order."""
    out = sorted(items, key=lambda it: get(it)[1])
    for name, direction in reversed(order):
        f = sec.fieldmap.get(name)
        filled = [it for it in out if not is_empty(get(it)[0].get(name))]
        empty = [it for it in out if is_empty(get(it)[0].get(name))]
        filled.sort(key=lambda it: _value_key(f, get(it)[0].get(name)), reverse=(direction == "desc"))
        out = filled + empty
    return out


def sort_default(sec: Section, items: list, get=lambda x: x) -> list:
    return sort_by_fields(sec, items, list(sec.default_order), get)

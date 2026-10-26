# REST API

Everything the web UI does with case data is available as JSON over HTTPS: create cases, read and write records,
write the Report page, run the MISP / VirusTotal actions and download every export.

* Base URL: `https://<your-host>/api`. All times are UTC.
* OpenAPI spec: [openapi.json](openapi.json).
* Fields, kinds and limits: [data-model.md](data-model.md).
* In the app, **Integrations → API Explorer** documents every operation and sends test requests with an API key.

## Authentication

### API keys (for programs)

API keys belong to the **application**, not to a user. Administrators create and manage them under
**Administration → API Keys** in the web UI (or over the API with an existing **admin** key). Each key has a
**kind**:

- **case** key — case data only, never administration. A **scope** limits it to **all** cases or a **single**
  case, and a **profile** sets its rights there: `read` acts as a per-case **viewer**, `readwrite` as a per-case
  **editor**. It can never manage membership, create users or keys, or import / replace / delete a case.
- **admin** key — a full administrator, equivalent to a signed-in admin over the whole API.

1. *Create API key*: a **name** (the key's identity: changes appear as `api:<name>` in `updated_by` and the
   activity log), its **kind / scope / profile**, an optional **expiry** and an optional **IP allowlist**
   (IPv4/IPv6 addresses or CIDR ranges; empty = any address).
2. Copy the secret (`aurora_…`). It is shown **once**; the server stores only its SHA-256 hash.
3. Send it on every request:

```http
Authorization: Bearer aurora_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
```

| | |
|---|---|
| `read` case key | On the case(s) it is scoped to: view everything, search, summaries, the Report page, all exports (`.fox`, Excel, PDF, LaTeX) |
| `readwrite` case key | `read` + create / update / delete records, case details, the Report page, row actions (To Timeline, To hosts, Send to MISP, Check VT). An **all-scope** readwrite key may also create cases (it becomes owner); a single-case key may not |
| Never with a **case** key | Manage case membership or ownership; import / replace / delete a case; users; API keys; backups and restore; passwords; MFA |
| **admin** key | Everything a browser-session administrator can do, across every case |
| Management | Change kind / scope / profile, enable/disable, expiry, IP allowlist, **rotate** the secret (the old one stops working at once; name and settings stay), delete. A database restore replaces all keys with those in the snapshot |
| CSRF | Not needed with a Bearer key (no cookies are involved) |
| Errors | Unknown, disabled, expired, rotated or deleted key: `401` with `WWW-Authenticate: Bearer`. Address not in the key's allowlist: `403`. A case the key cannot access: `404` |

### Browser sessions (used by the web UI)

The web UI signs in with a staged, cookie-based session (password, optional MFA, optional forced password
change) and a CSRF token on every non-GET request. Those session endpoints are internal to the UI and are not
part of this documented API — **programs authenticate with an API key**, which needs no cookie or CSRF token.

### Access (per case)

Access to case data is **per case**, not global. On a case you can access, your capability is **viewer** (read)
or **editor** (read + write); the case's **owner** also manages membership. An **admin** has full access to every
case and to administration. A new user can access no case until granted one; any user may create a case or import
a `.fox` and becomes its owner. A case you cannot access is invisible — its routes answer `404`.

| role / key | on a case it can access |
|---|---|
| `viewer` / `read` key | read everything, search, summaries, the Report page, export `.fox`, Excel, PDF and LaTeX |
| `editor` / `readwrite` key | + create / update / delete records, case details and the Report page, row actions |
| `owner` | + manage members, invites and ownership |
| `admin` | + create any user / key, delete / import / replace cases, users, API keys, backups and restore (GUI) |


## Conventions

* JSON in, JSON out (`Content-Type: application/json`). The exceptions are the `.fox` import (raw file body)
  and the export and backup downloads (binary).
* Request bodies are strict: unknown properties are rejected with `422`.
* Case ids in URLs are the numeric `id` from `GET /api/cases`. They are not the human `case_id` like `IR-608`.
* Section keys: `timeline`, `investigated_systems`, `malware`, `compromised_accounts`, `network_indicators`,
  `exfiltration`, `osint`, `systems`, `investigators`, `evidence`, `actions`, `casenotes`.
* A **record** is returned as:

```json
{
  "recid": 4,
  "version": 3,
  "updated_at": 1791358301,
  "updated_by": "alice [api:plaso-importer]",
  "data": { "date_time": "2020-02-21 14:20:37", "event_type": "EventLog", "event_host": "base-file.shieldbase.lan",
            "direction": "<-", "event_source_host": "base-rd-07.shieldbase.lan", "killchain": "Actions on Obj.",
            "event_data": "User SPADERTECH\\sbell.adm RDPed from BASE-RD-07 into BASE-FILE", "notes": "SRC Port 65465",
            "visual": true, "followup": true, "w2ui": {} }
}
```

  `data` is the record exactly as it is written to the `.fox`. `recid`, `version`, `updated_*`,
  `date_added`, `date_updated` and the `*_` twins are server-managed.
  `updated_at` is epoch seconds (UTC).
* **Single-line text:** every record field must be one line. Line breaks (`\n`, `\r`, U+2028, U+2029) are rejected
  with `422` (`"line breaks are not allowed (text must be a single line)"`), because multi-line values break the
  Aurora desktop app. Join lines with `; ` or a space. A `.fox` import joins them for you and reports a warning.
* **Default order:** records are returned in each section's default order (timeline newest first, systems by
  hostname, malware by host then filename, …), listed as `default_order` in
  [data-model.md](data-model.md#default-record-order). The `.fox` and Excel exports use the same order.
  Empty values always come last.
* **Report page:** `executive_summary`, `conclusions` and `lessons_learned` (multi-line) are never written
  to the `.fox`; `context` is the case's `summary` (multi-line here, written to the `.fox` as one line).
* Request size limit: 1 MB. `.fox` import/replace and `/bulk` allow up to `MAX_IMPORT_MB` (25 MB), a restore
  `MAX_RESTORE_MB`.

### Times (UTC)

All `datetime` fields are stored and returned as UTC `YYYY-MM-DD HH:MM:SS`. Input may also be ISO 8601. Values
with a zone are converted:

| you send | stored |
|---|---|
| `2020-02-21 14:20:37` | `2020-02-21 14:20:37` (no zone: taken as UTC) |
| `2020-02-21T14:20:37Z`, `2020-02-21 14:20:37 UTC` | `2020-02-21 14:20:37` |
| `2020-02-21T15:20:37+01:00` | `2020-02-21 14:20:37` |
| `2020-02-21 14:20` | `2020-02-21 14:20:00` |

`date` fields are `YYYY-MM-DD`. Server timestamps (`updated_at`, `ts`, `created_at`, …) are epoch seconds UTC.
`date_added` is epoch **milliseconds**, as in Aurora.


## Errors

| status | meaning | body |
|---|---|---|
| `400` | bad parameter / policy violation | `{"detail": "..."}` |
| `401` | missing/invalid/expired key or session, sign-in not complete | `{"detail": "..."}` |
| `403` | role or key profile does not allow it, key used for administration, address not in the key's allowlist, missing CSRF | `{"detail": "..."}` |
| `404` | case / section / record not found | `{"detail": "..."}` |
| `409` | conflict (see below) | `{"detail": "...", "conflicts" \| "current" \| "references": ...}` |
| `413` | request body too large | `{"detail": "Request body too large"}` |
| `422` | validation failed | see below |
| `429` | too many failed passwords or MFA codes | `{"detail": "..."}` |
| `503` | the database is busy (write lock not obtained within 30 s) | `{"detail": "..."}` |

**Validation (`422`) from the data layer:**

```json
{
  "detail": "Validation failed",
  "errors": [
    {"field": "date_time", "message": "expected YYYY-MM-DD HH:MM:SS (UTC, or with a +HH:MM offset to convert)"},
    {"field": "event_host", "message": "'new-host' is not declared in Systems"},
    {"field": "notes", "message": "line breaks are not allowed (text must be a single line)"}
  ],
  "missing_refs": [{"field": "event_host", "section": "systems", "value": "new-host"}]
}
```

For `/bulk` every error and missing reference also carries the `index` of the failing record. A `422` caused
by a malformed body (wrong JSON types, unknown property) has FastAPI's format: `{"detail": [{"loc": [...], "msg": "...", "type": "..."}]}`.

**Conflicts (`409`)**:

* `version` mismatch: `{"detail": "Record is at version 5, not 4; re-read and retry", "current": <record>}`
* same-field edit (`expected` mode): `{"detail": "...", "conflicts": [{"field", "current", "base", "yours"}], "current": <record>}`
* delete of a still-referenced system/investigator/malware: `{"detail": "...", "references": [{"section", "recid", "field"}]}`


## Concurrency and conflicts

Every write runs in a serialised database transaction. Validation, reference checks and the write are atomic.
To avoid overwriting other people's work, updates use **optimistic locking**. Choose one mode per request:

| mode | send | succeeds when | best for |
|---|---|---|---|
| **version** | `{"changes": {...}, "version": 4}` | the record is still at version 4 | scripts. Simple: on 409, re-read and retry |
| **expected** | `{"changes": {"os": "Win10"}, "expected": {"os": ""}}` | each changed field still has the value you started from (other fields may have changed) | interactive editors (what the web UI uses) |

Deletes accept `?version=N`. Without it the record is deleted regardless of concurrent edits.

To follow changes made by others, poll `GET /api/cases/{id}/revision` (cheap). The `revision` increases on
every change. Re-read what you need when it differs.


## Endpoint reference

`{case}` = numeric case id, `{section}` = section key, `{recid}` = record id.
Auth column (per case unless noted): **any** = anyone with access to the case — its viewer/editor/owner/admin, or an API key with access; **editor** = editor/owner/admin or a `readwrite` key; **admin** = administrator; **session** = browser sign-in only (never an API key). A case you cannot access answers `404`, never 403.

### Users (admin, session)

| method | path | description |
|---|---|---|
| GET | `/api/users[?q=text]` | List users, ordered by username. `q` filters on username or investigator. Each user: role, active, investigator, `mfa_enabled`, `must_change_password`, `ip_allowlist` |
| POST | `/api/users` | `{"username","password","role","investigator","must_change_password":true,"ip_allowlist":[]}` |
| PATCH | `/api/users/{id}` | Any of `{"role","active","password","investigator","must_change_password","ip_allowlist"}`. A password reset or deactivation signs the user out everywhere. An admin cannot set an allowlist that excludes their own current address |
| POST | `/api/users/{id}/reset-mfa` | Remove the user's MFA (they enrol again) and end their sessions |
| DELETE | `/api/users/{id}` | Delete the user and their sessions |

### Cases

| method | path | auth | description |
|---|---|---|---|
| GET | `/api/cases[?q=text]` | any | The cases you can access (an admin, or an all-scope key, sees every case), newest Case ID first in natural order (`IR-609` before `IR-608`, `IR-1000` before `IR-999`): `[{"id","uuid","case_id","client","revision","updated_at","updated_by","owner_id"}]` (plus `owner` username for admins). `q` filters on Case ID or client |
| POST | `/api/cases` | any user; admin key; all-scope `readwrite` key | `{"case_id","client"}` → `{"id"}` (empty case with Aurora's default lookups; **you become its owner**). A `read` key or a single-case key may not create cases |
| POST | `/api/cases/import[?declare_missing=true]` | any user (session) or admin key | Body = raw `.fox` JSON → `{"id","warnings"}`. Importing a `.fox` creates and populates a new case, so **you become its owner**. Strictly validated; `declare_missing` auto-creates missing referenced entries and lookup values. Line breaks in text are joined with a space (listed in `warnings`). A case API key cannot import |
| POST | `/api/cases/{case}/replace[?declare_missing=true]` | owner / admin | Replace all data from a `.fox` (database snapshot written first) |
| POST | `/api/cases/{case}/delete` | owner / admin | `{"confirm": "<case_id>"}` (database snapshot written first; any single-case API keys scoped to this case are deleted with it) |
| GET | `/api/cases/{case}` | any | `{"id","uuid","owner_id","owner","access","can_manage","can_edit","revision","updated_by","updated_at","meta":{case_id,client,start_date,end_date,summary,mispserver,mispeventid,mispapikey:"",vtapikey:"",use_server_misp,use_server_vt,secrets_set:{mispapikey,vtapikey}},"counts":{section: n},"integrations":{...}}`. `uuid` is the case id used for invites; `access` is your level (`admin`/`owner`/`editor`/`viewer`); `can_manage`/`can_edit` are convenience booleans. API keys are write-only: always returned as `""`, `secrets_set` says whether one is stored. `end_date` and `use_server_misp`/`use_server_vt` (default `true`) exist only on this platform, never in the `.fox`; `end_date` may not be before `start_date` |
| PATCH | `/api/cases/{case}` | editor | `{"changes": {...}, "expected"?: {...}}`; without `expected` it overwrites. `summary` may span lines. `mispapikey`/`vtapikey` need no `expected` (set a new key, or `""` to remove it); they are stored encrypted |
| GET | `/api/cases/{case}/revision` | any | `{"revision","updated_by","updated_at"}` |
| GET | `/api/cases/{case}/options` | any | `{"lookups": {event_types: [...], ...}, "refs": {"systems": [...], "investigators": [...], "malware": [...]}}`, the allowed values for enum/ref fields |
| GET | `/api/cases/{case}/export[?locked=true]` | any | `.fox` download (`Content-Disposition`, `X-Case-Revision`). `locked` defaults to `false` so Aurora opens it editable. MISP server and event ID are included; `mispapikey` and `vtapikey` are always written as `""` |
| GET | `/api/cases/{case}/export.xlsx` | any | Excel workbook (spreadsheet of doom): *Cover* (application, logo, case presentation, who exported it and when, case metadata), *Report* (the Report page), then one sheet per section in the default order. UTC date/times as real Excel dates; text never stored as formulas; MISP/VirusTotal keys omitted |
| GET | `/api/cases/{case}/export.pdf` | any | PDF report (A4 landscape): cover, Report page, charts (Visual Timeline / Lateral Movement / Activity Plot), every section as a table |
| GET | `/api/cases/{case}/export.tex` | any | The same report as one self-contained LaTeX file (charts in TikZ/pgfplots); compile with `xelatex`. All case text is escaped |
| GET | `/api/cases/{case}/report` | any | Report page: `{"executive_summary","context","conclusions","lessons_learned","updated_at","updated_by","revision"}` |
| PATCH | `/api/cases/{case}/report` | editor | `{"changes": {...}, "expected"?: {...}}` (field-level merge like case details; `409` with `conflicts` and `current`). Logged as `update_report` |

### Case membership & invitations

Per-case access is managed here. A case **viewer** reads; an **editor** reads and writes; the **owner** also
manages membership and invites; an **admin** can do all of it on any case and may add members directly. These
endpoints are **session only** — a case API key is data-only and cannot manage membership. Non-members get `404`.

| method | path | auth | description |
|---|---|---|---|
| GET | `/api/cases/{case}/members` | owner / admin | `{"members": [{"user_id","username","investigator","permission","is_owner","added_at","added_by"}]}` (owner first) |
| POST | `/api/cases/{case}/members` | admin | `{"user_id","permission":"editor"\|"viewer"}` — add a user directly (owners invite with a code instead; they cannot enumerate users) |
| PATCH | `/api/cases/{case}/members/{user_id}` | owner / admin | `{"permission":"editor"\|"viewer"}` — change a member's permission |
| DELETE | `/api/cases/{case}/members/{user_id}` | owner / admin | Remove a member from the case |
| POST | `/api/cases/{case}/leave` | member (session) | Leave a case you belong to (the owner cannot leave — transfer ownership first) |
| PATCH | `/api/cases/{case}/owner` | owner / admin | `{"user_id"}` — transfer ownership (an owner hands it to a current member; an admin to any active user) |
| GET | `/api/cases/{case}/invites` | owner / admin | `{"invites": [{"id","prefix","permission","max_redeems","redeems_used","expires_at","enabled","expired","created_at","created_by"}]}`; the code itself is never returned |
| POST | `/api/cases/{case}/invites` | owner / admin | `{"permission","max_redeems":1,"expires"?}` → `{"code","uuid","invite":{...}}`. The **code is shown once**; `max_redeems` 0 = unlimited; `expires` is `YYYY-MM-DD` (end of day) or `YYYY-MM-DDTHH:MM[:SS]`, omitted = never. Share `code` + the case `uuid` out of band |
| DELETE | `/api/cases/{case}/invites/{invite_id}` | owner / admin | Revoke an invite (refused with `409` if already used up, expired or revoked) |
| POST | `/api/cases/join` | session | `{"uuid","code"}` → `{"id","permission"}`. Adds you to the case with the permission the invite carries |

### Records

| method | path | auth | description |
|---|---|---|---|
| GET | `/api/cases/{case}/sections/{section}` | any | List. Query: `q` (text in any field), `filter=field:value` (repeatable, exact), `sort` (field or `recid`; omit for the section's default order), `order=asc\|desc` (empty values last either way), `limit` (≤10000), `offset`. → `{"revision","total","records"}`; no parameters = all records in default order |
| GET | `/api/cases/{case}/sections/{section}/{recid}` | any | One record |
| POST | `/api/cases/{case}/sections/{section}[?declare_missing=true]` | editor | `{"data": {...}}` → created record |
| POST | `/api/cases/{case}/sections/{section}/bulk[?declare_missing=true]` | editor | `{"records": [{...}, ...]}` (≤1000), **all or nothing** → `{"created", "records"}` |
| PATCH | `/api/cases/{case}/sections/{section}/{recid}[?declare_missing=true]` | editor | `{"changes": {...}, "version": N}` or `{"changes": {...}, "expected": {...}}` → updated record. Renaming a system/investigator/malware updates all references |
| DELETE | `/api/cases/{case}/sections/{section}/{recid}[?version=N]` | editor | Delete (refused with 409 while still referenced) |
| POST | `/api/cases/{case}/sections/{section}/{recid}/delete` | editor | Same, body `{"version": N}` (used by the web UI) |
| GET | `/api/cases/{case}/sections/{section}/export.csv` | any | The section's records as CSV (RFC 4180, UTF-8; `Content-Disposition`). Editable fields only — no `recid`/`version`/server-managed columns. Formula-trigger cells (`= + - @`, tab, CR) are prefixed with `'` so a spreadsheet will not execute them |
| POST | `/api/cases/{case}/sections/{section}/import.csv[?declare_missing=true]` | editor | Body = raw CSV. Header names the columns (the section's editable fields). Every cell is validated like the API / `.fox` import and the **whole file is rejected** (`400`/`422`) if any value is invalid, unknown/duplicate column appears, or a row's column count is wrong; `≤1000` rows. → `{"created": n}` |

### Row actions & integrations (Aurora's right-click menu)

| method | path | auth | description |
|---|---|---|---|
| GET | `/api/cases/{case}/integrations` | any | `{"enabled", "misp": {"configured","source","server","event_id","missing","note"}, "virustotal": {"configured","source","note"}, "misp_types"}`. `source` is `case`, `server` (the server-wide settings) or `null`; never the keys |
| POST | `/api/cases/{case}/integrations/misp/test` | editor | Server fetches `<MISP>/events/view/<event>` with the saved key → `{"ok","event_info","message"}` |
| POST | `/api/cases/{case}/integrations/virustotal/test` | editor | Checks the saved VirusTotal key → `{"ok","message"}` |
| GET | `/api/cases/{case}/sections/{section}/{recid}/actions` | any | `{"actions": [{"action","label","available","reason"}]}`: what the row menu offers and why an action is unavailable |
| POST | `/api/cases/{case}/sections/{section}/{recid}/to-timeline` | editor | `investigated_systems`, `malware`, `exfiltration` → created timeline record (see mapping below) |
| POST | `/api/cases/{case}/sections/malware/{recid}/to-investigated-systems` | editor | Aurora's *To hosts*: adds the malware's host to Investigated Systems (verdict *Infected*, first compromise = creation date). `409` if the host is already listed |
| GET | `/api/cases/{case}/sections/{section}/{recid}/misp-attributes` | any | `malware`, `network_indicators` → `{"attributes": [{"aurora_field","type","value","comment"}], "misp_types", "misp"}` |
| POST | `/api/cases/{case}/sections/{section}/{recid}/send-to-misp` | editor | `{"attributes"?: [{"type","value","comment"?}]}` (≤10; omit to send all proposed). Values must be among the proposed ones, types from `misp_types`. The server calls `POST <MISP>/attributes/add/<event>` → `{"ok","sent","added","message"}` |
| POST | `/api/cases/{case}/sections/malware/{recid}/check-virustotal` | editor | Requires a hash (MD5/SHA-1/SHA-256) in the record and a VirusTotal key (the case's own or the server-wide one). Stores `vt` = `infected` (≥1 engine), `clean` or `noresult` → `{"verdict","details":{"malicious","suspicious","engines","permalink",...},"record"}`. `429` when the VirusTotal quota is exhausted |

*Duplicate Line* needs no endpoint: read the record and `POST` its fields as a new one (the web UI opens a
pre-filled form).

**To-timeline mapping** (as in Aurora's `controller.js`; the new event always has *Followup* ticked):

| source | Date/Time | Event System | Remote System / ⇄ | Type | Event | Notes |
|---|---|---|---|---|---|---|
| Investigated system | first compromise | hostname | | | summary | |
| Malware | creation date | host | | Malware | `Malware created (<path>). <notes>` | |
| Exfiltration | exfil time | staging system | exfiltrated to / `->` | Exfil | `<filename> exfiltrated.` | context |

API keys with the `readwrite` profile can run every row action. Every action is written to the activity log (`to_timeline`, `to_investigated_systems`, `send_to_misp` with the
values sent, `check_virustotal` with the result). API keys never appear in logs or responses. Integrations need
outbound HTTPS from the container; see [deployment.md](deployment.md#misp-and-virustotal).

### Analysis (read-only, never modify data)

| method | path | auth | description |
|---|---|---|---|
| GET | `/api/cases/{case}/search?q=...[&sections=a,b][&limit=50]` | any | `{"q","count","results":[{"section","recid","matched_fields","data"}]}` |
| GET | `/api/cases/{case}/summary` | any | Incident summary: counts, first/last attacker activity, kill-chain and event-type counts, `activity_by_hour_utc[24]`, lateral-movement `nodes`/`edges`, investigated systems, accounts, exfiltration |
| GET | `/api/cases/{case}/report-data` | any | Snapshot used by the report views (sections + lookups) |
| GET | `/api/cases/{case}/audit[?limit=200][&before_id=N]` | any | Activity log, newest first: `{"id","ts","username","action","section","recid","before","after"}` |

## Examples

```bash
export AURORA=https://air.example.com
H="Authorization: Bearer aurora_..."
J="Content-Type: application/json"

# list cases (the numeric "id" is used in URLs) and create one (readwrite key)
curl -s -H "$H" $AURORA/api/cases
curl -s -H "$H" -H "$J" -X POST $AURORA/api/cases -d '{"case_id": "IR-610", "client": "ACME"}'

# add a timeline event (unknown systems are declared automatically with declare_missing=true)
curl -s -H "$H" -H "$J" -X POST "$AURORA/api/cases/1/sections/timeline?declare_missing=true" \
  -d '{"data": {"date_time": "2020-02-21T15:06:36Z", "event_type": "Exfil", "event_host": "base-file.shieldbase.lan",
                "event_data": "techsupport.7z uploaded", "visual": true}}'

# bulk-load events from a tool (all or nothing)
curl -s -H "$H" -H "$J" -X POST "$AURORA/api/cases/1/sections/timeline/bulk?declare_missing=true" \
  -d '{"records": [{"date_time": "2020-02-21 14:20:37", "event_type": "EventLog", "event_host": "base-file.shieldbase.lan", "event_data": "4624 logon type 10"}]}'

# update safely: read the version, then patch with it (409 if someone changed the record meanwhile)
curl -s -H "$H" $AURORA/api/cases/1/sections/systems/9
curl -s -H "$H" -H "$J" -X PATCH $AURORA/api/cases/1/sections/systems/9 \
  -d '{"changes": {"description": "File server - patient zero"}, "version": 3}'

# query: search everywhere, or filter a section
curl -s -H "$H" "$AURORA/api/cases/1/search?q=spadertech-awsapps"
curl -s -H "$H" "$AURORA/api/cases/1/sections/timeline?filter=event_type:C2&sort=date_time&order=desc&limit=20"

# Report page: executive summary (multi-line text allowed)
curl -s -H "$H" -H "$J" -X PATCH $AURORA/api/cases/1/report \
  -d '{"changes": {"executive_summary": "Ransomware intrusion via VPN.\nContained on day 3."}}'

# exports
curl -s -H "$H" -o IR-610.fox  $AURORA/api/cases/1/export
curl -s -H "$H" -o IR-610.xlsx $AURORA/api/cases/1/export.xlsx
curl -s -H "$H" -o IR-610.pdf  $AURORA/api/cases/1/export.pdf
curl -s -H "$H" -o IR-610.tex  $AURORA/api/cases/1/export.tex
```

A Python client (standard library only) with a small CLI is in [examples/aurora_client.py](examples/aurora_client.py).

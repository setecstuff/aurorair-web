# Data model

_Generated from `app/schema.py` by `tools/gen_docs.py`. Do not edit by hand._

A case is an Aurora `.fox` document (storage format 7). Each **section** is a list of records; every record has a `recid` (unique within its section) and, in this application, a `version` used for optimistic locking.

## Field kinds

| kind | accepted values |
|---|---|
| `text` | single-line text (no line breaks / control characters; TAB and Unicode are allowed) |
| `longtext` | longer single-line text (shown wrapped in a text box; line breaks are rejected as in `text`) |
| `multiline` | free text that may span lines (case summary and Report page only; never a record field) |
| `bool` | true / false |
| `datetime` | UTC `YYYY-MM-DD HH:MM:SS`; ISO 8601 input with `T`, `Z`, `UTC` or `±HH:MM` is converted to UTC |
| `date` | `YYYY-MM-DD` |
| `ip` | IPv4 or IPv6 address (normalised) |
| `port` | 0-65535, stored as a string (Aurora format) |
| `int` | non-negative integer |
| `hash` | hex digest of 32/40/56/64/96/128 characters (MD5, SHA-1, SHA-2) |
| `email` | e-mail address |
| `url` | URL / URI without whitespace (stored as text, never rendered as a link) |
| `enum` | must be a value of the case's lookup list (see `GET /api/cases/{id}/options`) |
| `ref` | must equal the key of an existing record in the referenced section |
| `auto_ms` | set by the server: epoch milliseconds (UTC), plus an ISO twin `<field>_` |
| `readonly` | carried through from Aurora, not editable |

## Relational rules

| referenced section (key field) | referenced from |
|---|---|
| `systems` (`text`) | `timeline.event_host`, `timeline.event_source_host`, `investigated_systems.hostname`, `malware.hostname`, `exfiltration.stagingsystem`, `exfiltration.original`, `exfiltration.exfil_to` |
| `investigators` (`text`) | `timeline.owner`, `investigated_systems.analyst`, `evidence.provider`, `actions.owner`, `casenotes.owner` |
| `malware` (`text`) | `network_indicators.malware` |

* Systems hostnames and investigator short names are unique (case-insensitive).
* Renaming a referenced record updates every reference; deleting one that is still referenced is refused (409).
* `declare_missing=true` on create/update/bulk/import creates missing referenced records (key field only).

## Case details

| field | label | kind | max | notes |
|---|---|---|---|---|
| `case_id` | Case ID | `text` | 100 | required |
| `client` | Client | `text` | 200 |  |
| `start_date` | Engagement start | `date` |  |  |
| `end_date` | Engagement end | `date` |  | platform only (never in the .fox); shown in the Excel, PDF and LaTeX reports |
| `summary` | Summary / context | `multiline` |  |  |
| `mispeventid` | MISP event ID | `text` | 50 |  |
| `use_server_misp` | Use the server-wide MISP | `bool` |  | platform only (never in the .fox), default true |
| `mispserver` | MISP server URL | `url` |  |  |
| `mispapikey` | MISP API key | `text` | 200 | secret, write-only and encrypted at rest: never returned by the API, exported blank in .fox, absent from Excel/PDF/LaTeX |
| `use_server_vt` | Use the server-wide VirusTotal key | `bool` |  | platform only (never in the .fox), default true |
| `vtapikey` | VirusTotal API key | `text` | 200 | secret, write-only and encrypted at rest: never returned by the API, exported blank in .fox, absent from Excel/PDF/LaTeX |

## Single-line text

Every record field, case detail (except the summary) and lookup value must be a single line, because multi-line values break the Aurora desktop grids. The API rejects line breaks (`\n`, `\r`, U+2028, U+2029) with a 422 validation error. A `.fox` import joins line breaks in records with a space and reports it as a warning. The browser keeps wrapping text boxes but ignores Enter and joins pasted lines. The case `summary` (= executive-summary context) may span lines; the `.fox` export writes it as one line.

## Report page

Stored per case, never written to the `.fox` (`GET`/`PATCH /api/cases/{id}/report`); included in the Excel, PDF and LaTeX exports.

| field | label | kind | max |
|---|---|---|---|
| `executive_summary` | Executive summary | `multiline` | 200000 |
| `context` | Context | `multiline` | 100000 |
| `conclusions` | Conclusions | `multiline` | 200000 |
| `lessons_learned` | Lessons learned | `multiline` | 200000 |

`context` is the case's `summary` field.

## Default record order

Records are returned by the API, shown in the UI and written to the `.fox`, Excel, PDF and LaTeX exports in this order. Empty values always come last; equal values keep `recid` order. Text compares case-insensitively with numbers in natural order (`host2` before `host10`), IP addresses numerically (IPv4 before IPv6). `sort`/`order` on `GET .../sections/{section}` override it for one request.

| section | default order |
|---|---|
| `timeline` | Date/Time (`date_time`) newest first |
| `investigated_systems` | Hostname (`hostname`) ascending |
| `malware` | Host (`hostname`) ascending, then Filename (`text`) ascending |
| `compromised_accounts` | Account Domain (`domain`) ascending, then Account Name (`account_name`) ascending |
| `network_indicators` | IP (`ip`) ascending, then Domainname (`domainname`) ascending |
| `exfiltration` | Exfil Time (`exfiltime`) newest first |
| `systems` | Hostname (`text`) ascending |
| `osint` | Short Name (`text`) ascending |
| `investigators` | Short Name (`text`) ascending |
| `evidence` | Date Acquired (`date_acquired`) newest first, then Name (`name`) ascending |
| `actions` | Date added (`date_added`) oldest first |
| `casenotes` | Date added (`date_added`) newest first |

## Lookup lists (defaults)

Enum fields take their allowed values from these per-case lists (imported from the .fox).

* `event_types`: `EventLog`, `File`, `Human`, `Engagement`, `Lateral Movement`, `Exfil`, `Tanium Trace`, `Malware`, `eMail`, `Misc`, `C2`
* `system_types`: `Desktop`, `Server`, `Phone`, `Tablet`, `TV`, `Networking device`, `IoT device`, `Other`, `Attacker Infra`
* `verdicts`: `Infected`, `Accessed`, `Commodity`, `Clean`
* `status`: `Assigned`, `In Progress`, `Completed`, `Closed`, `Rejected`
* `task_types`: `Information request`, `Analysis`, `Deliverable`, `Checkpoint`, `Other`
* `direction`: `<-`, `->`
* `killchain`: `Recon`, `Weaponization`, `Delivery`, `Exploitation`, `Installation`, `C2`, `Actions on Obj.`
* `evidence_types`: `File`, `System Logs`, `Network Logs`, `Triaged System`, `Cloned System`, `Memory Dump`, `External Source`, `Other`

## Sections

### `timeline` (Timeline)

Default order: `date_time` desc. 

| field | label | kind | required | max | allowed / references |
|---|---|---|---|---|---|
| `date_time` | Date/Time | `datetime` |  |  |  |
| `event_type` | Type | `enum` |  |  | lookup `event_types` |
| `event_host` | Event System | `ref` |  |  | → `systems` |
| `direction` | ⇄ | `enum` |  |  | lookup `direction` |
| `event_source_host` | Remote System | `ref` |  |  | → `systems` |
| `killchain` | Killchain | `enum` |  |  | lookup `killchain` |
| `event_data` | Event | `longtext` |  | 20000 |  |
| `notes` | Notes | `longtext` |  | 20000 |  |
| `visual` | Visual? | `bool` |  |  |  |
| `followup` | Followup | `bool` |  |  |  |
| `attribution` | Attribution | `text` |  | 200 |  |
| `owner` | Owner | `ref` |  |  | → `investigators` |

### `investigated_systems` (Investigated Systems)

`date_updated` is refreshed by the server on every change. 
Default order: `hostname` asc. 

| field | label | kind | required | max | allowed / references |
|---|---|---|---|---|---|
| `date_added` | Date added | `auto_ms` |  |  |  |
| `date_updated` | Date updated | `auto_ms` |  |  |  |
| `first_compromise` | First Compromise | `datetime` |  |  |  |
| `hostname` | Hostname | `ref` | yes |  | → `systems` |
| `verdict` | Verdict | `enum` |  |  | lookup `verdicts` |
| `summary` | Summary | `longtext` |  | 20000 |  |
| `analysis_required` | Analysis req? | `bool` |  |  |  |
| `analysis_status` | Analysis status | `enum` |  |  | lookup `status` |
| `analyst` | Analyst | `ref` |  |  | → `investigators` |
| `report_status` | Report Status | `enum` |  |  | lookup `status` |

### `malware` (Malware/Tools)

Key field: `text`. 
Default order: `hostname` asc, then `text` asc. 

| field | label | kind | required | max | allowed / references |
|---|---|---|---|---|---|
| `date_added` | Date added | `auto_ms` |  |  |  |
| `text` | Filename | `text` | yes | 500 |  |
| `path_on_disk` | Path on Disk | `text` |  | 4000 |  |
| `creation_date` | Creation Date | `datetime` |  |  |  |
| `modification_date` | Last modified | `datetime` |  |  |  |
| `hostname` | Host | `ref` |  |  | → `systems` |
| `md5` | Hash | `hash` |  |  |  |
| `vt` | vt | `readonly` |  |  | `infected`, `clean`, `noresult` |
| `attribution` | Attribution | `text` |  | 200 |  |
| `notes` | notes | `longtext` |  | 20000 |  |

### `compromised_accounts` (Compromised Accounts)

Default order: `domain` asc, then `account_name` asc. 

| field | label | kind | required | max | allowed / references |
|---|---|---|---|---|---|
| `date_added` | Date added | `auto_ms` |  |  |  |
| `account_name` | Account Name | `text` | yes | 256 |  |
| `domain` | Account Domain | `text` |  | 256 |  |
| `sid` | SID | `text` |  | 256 |  |
| `context` | Context | `longtext` |  | 20000 |  |
| `last_activity` | Last Activity | `datetime` |  |  |  |
| `privileges` | Privileges | `text` |  | 1000 |  |
| `attribution` | Attribution | `text` |  | 200 |  |

### `network_indicators` (Network Indicators)

Default order: `ip` asc, then `domainname` asc. 

| field | label | kind | required | max | allowed / references |
|---|---|---|---|---|---|
| `date_added` | Date added | `auto_ms` |  |  |  |
| `ip` | IP | `ip` |  |  |  |
| `domainname` | Domainname | `text` |  | 500 |  |
| `port` | Port | `port` |  |  |  |
| `context` | Context | `longtext` |  | 20000 |  |
| `last_activity` | Last activity | `datetime` |  |  |  |
| `malware` | Malware | `ref` |  |  | → `malware` |
| `whois` | Whois | `longtext` |  | 50000 |  |
| `attribution` | Attribution | `text` |  | 200 |  |

### `exfiltration` (Exfiltration)

Default order: `exfiltime` desc. 

| field | label | kind | required | max | allowed / references |
|---|---|---|---|---|---|
| `created` | Created | `datetime` |  |  |  |
| `exfiltime` | Exfil Time | `datetime` |  |  |  |
| `stagingsystem` | Staging System | `ref` |  |  | → `systems` |
| `original` | Original System | `ref` |  |  | → `systems` |
| `exfil_to` | Exfiltrated to | `ref` |  |  | → `systems` |
| `filename` | Filename | `text` |  | 1000 |  |
| `size` | Size | `int` |  |  |  |
| `contents` | Contents | `longtext` |  | 20000 |  |
| `notes` | Context | `longtext` |  | 20000 |  |
| `attribution` | Attribution | `text` |  | 200 |  |

### `systems` (Systems)

Key field: `text` (unique). 
Default order: `text` asc. 

| field | label | kind | required | max | allowed / references |
|---|---|---|---|---|---|
| `text` | Hostname | `text` | yes | 255 |  |
| `ip` | IP | `ip` |  |  |  |
| `system_type` | Type | `enum` |  |  | lookup `system_types` |
| `os` | Operating System | `text` |  | 200 |  |
| `owner` | Owner | `text` |  | 200 |  |
| `description` | Description | `longtext` |  | 20000 |  |
| `pin` | Pin | `bool` |  |  |  |

### `osint` (OSInt)

Default order: `text` asc. 

| field | label | kind | required | max | allowed / references |
|---|---|---|---|---|---|
| `text` | Short Name | `text` |  | 200 |  |
| `url` | URL | `url` |  |  |  |
| `desc` | Description | `longtext` |  | 20000 |  |

### `investigators` (Investigators)

Key field: `text` (unique). 
Default order: `text` asc. 

| field | label | kind | required | max | allowed / references |
|---|---|---|---|---|---|
| `text` | Short Name | `text` | yes | 20 |  |
| `full_name` | Full Name | `text` |  | 200 |  |
| `affiliation` | 🏢 Affiliation | `text` |  | 200 |  |
| `role` | 🙋 Role | `text` |  | 200 |  |
| `contact_email` | 📬 Email | `email` |  |  |  |
| `contact_phone` | 📱 Phone | `text` |  | 60 |  |
| `contact_other` | 📖 Other | `text` |  | 1000 |  |

### `evidence` (Evidence)

Default order: `date_acquired` desc, then `name` asc. 

| field | label | kind | required | max | allowed / references |
|---|---|---|---|---|---|
| `date_acquired` | Date Acquired | `datetime` |  |  |  |
| `type` | Type | `enum` |  |  | lookup `evidence_types` |
| `name` | Name | `text` | yes | 500 |  |
| `description` | Description | `longtext` |  | 20000 |  |
| `size` | Size | `text` |  | 100 |  |
| `hash` | Hash | `text` |  | 500 |  |
| `provider` | Provided by | `ref` |  |  | → `investigators` |
| `location` | Location | `text` |  | 1000 |  |

### `actions` (Action Items)

Default order: `date_added` asc. 

| field | label | kind | required | max | allowed / references |
|---|---|---|---|---|---|
| `date_added` | Date added | `auto_ms` |  |  |  |
| `date_due` | Date Due | `date` |  |  |  |
| `task_type` | Type | `enum` |  |  | lookup `task_types` |
| `task` | Task | `longtext` | yes | 20000 |  |
| `status` | Status | `enum` |  |  | lookup `status` |
| `owner` | Owner | `ref` |  |  | → `investigators` |

### `casenotes` (Case Notes)

Default order: `date_added` desc. 

| field | label | kind | required | max | allowed / references |
|---|---|---|---|---|---|
| `date_added` | Date added | `auto_ms` |  |  |  |
| `note` | Note | `longtext` | yes | 20000 |  |
| `owner` | Owner | `ref` |  |  | → `investigators` |


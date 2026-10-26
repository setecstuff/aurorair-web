# User guide

Aurora IR Web has the sections, fields and reports of Aurora Incident Response, shared by the whole team in the
browser.

## Signing in

1. Username and password.
2. If you use two-factor authentication: the 6-digit code from your authenticator app.
3. If an administrator asked for it: a new password.
4. If two-factor authentication is mandatory and you have none yet: scan the QR code with an authenticator app
   (Microsoft or Google Authenticator, FreeOTP, 1Password, …) and enter the code it shows.

Codes are valid for 30 seconds and only once; if they are refused, check the phone's clock. Lost your phone? Ask
an administrator to *Reset MFA*. Your account may be limited to certain network addresses.

## Access, cases and invitations

There are two kinds of account: **users** and **administrators**. Access to case data is granted **per case**,
not globally:

* A new account can see **no cases** until it is given access to one.
* Any user can **create** a case (**+ New case**) or **import** a `.fox` (**Import .fox**); you become that
  case's **owner**.
* The **owner** has full rights on the case plus management: inviting people, changing their permission,
  removing them, and transferring ownership. Per-case access is either **editor** (view and change) or
  **viewer** (read-only).
* You don't see other users, and they don't see you, unless you share a case. To bring someone onto a case, the
  **owner** (or an admin) creates an **invite code** with a chosen permission and a number of uses, and shares
  it — together with the case's **id (uuid)** — out of band. The invitee uses **Join case** with those two
  values. Editors and viewers cannot create invites (only the owner or an admin can), so no one can raise their
  own access.
* **Administrators** see every case and every owner, can add or remove members directly, change permissions and
  transfer ownership, and manage users, API keys and backups.
* Cases are shown with a unique number, e.g. `12: IR-608 — client`, so two cases may share a Case ID without
  being confused. The number is for display; it is never written into the `.fox` or the exports.

## Layout

* **Top bar**: case selector, **+ New case**, **Import .fox**, **Join case**, **Export .fox**, **Export Excel**,
  **PDF**, **LaTeX**, **Account**, **Sign out**.
* **Sidebar** (**☰** shows or hides it), in Aurora's order:
  * *Investigation*: Timeline, Investigated Systems, Malware/Tools, Compromised Accounts, Network Indicators,
    Exfiltration, OSInt, Systems
  * *Reporting*: Incident Overview, Visual Timeline, Lateral Movement, Activity Plot
  * *Case Management*: Investigators, Evidence, Action Items, Case Notes
  * *Case*: Case Details, Report, Activity Log
  * *Administration* (admins): Cases, Users, API Keys, Backups & Restore
  * *Integrations*: API Explorer; *About*: About & Credits

On a case where your permission is *viewer*, everything is read-only.

## Records

* **+ Add** creates a record; click a row to edit it. **Filter** searches all columns; clicking a column header
  sorts (a third click returns to the default order).
* **Row actions**: right-click a row, or use its **⋯** button:

  | section | actions |
  |---|---|
  | every section | *Duplicate Line* (a pre-filled new record) |
  | Investigated Systems | *To Timeline* |
  | Malware/Tools | *To hosts*, *To Timeline*, *Send to MISP*, *Check VT* |
  | Network Indicators | *Send to MISP* |
  | Exfiltration | *To Timeline* |

  Events created with *To Timeline* have *Followup* ticked. An unavailable action says why (e.g. *Check VT*
  needs a hash and a VirusTotal key, the case's own or the server-wide one). *Send to MISP* lets you choose the indicators and their
  MISP types before sending; *Check VT* sets *vt* to *infected*, *clean* or *noresult*.
* **Default order** per section (also in every export): Timeline, Exfiltration and Evidence newest first; Systems
  and Investigated Systems by hostname; Malware by host then filename; Accounts by domain then name; Network
  Indicators by IP; Action Items oldest first; Case Notes newest first. Empty values go last. The full table is in
  [data-model.md](data-model.md#default-record-order).
* **Times are UTC** (`YYYY-MM-DD HH:MM:SS`). Times pasted with an offset (`2020-02-21T15:20:37+01:00`) are
  converted. **now** inserts the current UTC time.
* **Record text is one line**, so the case stays compatible with the Aurora desktop app: Enter does nothing and
  pasted line breaks become spaces.
* **Related data first**: systems must exist in **Systems**, people in **Investigators**, malware in
  **Malware/Tools**. Typing an unknown name offers **Declare "x"**, which creates it. Renaming updates every
  record that uses it; deleting something still in use is refused.
* New records are pre-filled with your investigator name (analyst, provider, owner), except a timeline event's
  *Owner*.

### CSV import / export

Every record section has **Export CSV** and **Import CSV** next to **+ Add**.

* **Format (standardised):** RFC 4180 — comma-separated, UTF-8 (a byte-order mark is accepted), CRLF line
  endings, and double-quote quoting, so a value containing a comma, a semicolon, a quote or a line break is
  quoted and can never spill into another column. The header row names the columns, which are a section's
  **editable fields only**; server-managed fields (the internal record id, *Date added* / *Date updated*, *vt*)
  are never written or read. Export and import use the same columns, so a file round-trips.
* **Import is validated and all-or-nothing.** Every cell goes through the *same* validation as the API and the
  `.fox` import — field types, length limits, rejection of control characters, and the reference and
  uniqueness checks (e.g. a malware host must exist in **Systems**). In addition the file must be valid UTF-8
  with no NUL bytes, every row must have exactly as many values as the header, and unknown or duplicate columns
  are refused. **If any cell is invalid, nothing is imported** and the first problem is reported; the record cap
  per section still applies. Add `?declare_missing=true` (API) to auto-create referenced systems/people/lookup
  values, as with `.fox` import.
* **No formula/CSV injection.** On export, any cell that could be interpreted as a spreadsheet formula (it
  starts with `=`, `+`, `-`, `@`, a tab or a carriage return) is prefixed with a single quote so opening the
  file in Excel/Sheets cannot execute it; import strips that guard back off. Values are only ever stored as
  text — nothing in a CSV is executed.

## Working together

* Changes by others appear within seconds.
* If someone changes **other fields** of the record you are editing, both edits are kept.
* If someone changes **the same field**, your save stops and shows their value; choose, then save again.
* **Activity Log** lists every change, who made it (programs as `api:<key name>`), when, and the values before
  and after.

## Report

**Case → Report** has four multi-line fields: *executive summary*, *context*, *conclusions* and
*lessons learned*.
- *Context* is the case summary from Case Details; editing it in either place changes the same text.
- All four go into the Excel, PDF and LaTeX exports.
- None of them goes into the `.fox`, except the context, which is written as the case summary on a single line.

## Case details

* Case ID, client, engagement start and **end**, summary, the MISP **event ID**, and optionally the case's own
  MISP server, API key and VirusTotal key.
* *Engagement end* appears on the Excel, PDF and LaTeX covers but is not written to the `.fox` (Aurora has no
  such field); a replace from a `.fox` keeps it.
* **MISP and VirusTotal settings:**
  * *Use the server-wide MISP* and *Use the server-wide VirusTotal key* are on by default: the case uses what an
    administrator configured, and only the event ID is per case.
  * Untick a switch to use the case's own MISP URL **and** API key, or its own VirusTotal key. While a switch is
    on, those fields are greyed out; values stored there are kept for when you switch it off.
  * Below the form, the page shows which settings the case uses.
* The API keys are write-only: once saved, nobody sees them again. They are stored encrypted and never exported,
  so a `.fox` from here opens in Aurora with empty keys (and an empty MISP URL when the case uses the server-wide
  MISP).
* **Test MISP connection** and **Test VirusTotal key** check the saved settings.

## Reports and exports

* **Reports** (live, read-only, printable):
  * Incident Overview;
  * Visual Timeline (events with *Visual?* ticked);
  * Lateral Movement (events naming both an Event System and a Remote System);
  * Activity Plot (events per UTC hour).
* **Export .fox**: opens in the Aurora desktop app (unlocked, keys empty, no Report page except the context as
  the case summary).
* **Export Excel**: a cover sheet (case, exporter, time, metadata), a *Report* sheet, then one sheet per
  section with real UTC dates. Text is never interpreted as a formula.
* **PDF**: cover, the Report page, the three charts and every section.
* **LaTeX**: the same report as a `.tex` file (charts in TikZ); compile with `xelatex`.

While an export is being generated a window shows the progress and further clicks are ignored; *Cancel* stops
waiting for it. Every export is recorded in the Activity Log.

## Administration (admins)

* **Cases**: every case with its number, owner and last change. Admins manage membership and ownership from a
  case's **Case Details** page (owners do the same there for their own cases). A `.fox` import/replace or a
  delete takes a database snapshot first; line breaks in imported records are joined and listed as warnings.
* **Users**: role (*user* or *admin*), active, investigator name, *new password at next sign-in*, IP allowlist
  (one address or CIDR range per line; empty = any), **Reset MFA**, **Reset password**. Per-case rights are not
  set here — they are granted on each case (invite code, or admin add-member).
* **API Keys**: created by admins only. A key is either an **admin** key (full admin-equivalent — treat as a
  total-access secret) or a **case** key limited to case data: profile *read* (viewer) or *readwrite* (editor),
  over **all cases** or a **single case**. Name (shown in the Activity Log), expiry, enabled, IP allowlist.
  * **Rotate secret** issues a new secret and stops the old one. The secret is shown once.
* **MISP & VirusTotal**:
  * The server-wide MISP URL with its API key, and the VirusTotal key, used by every case without its own.
  * The event ID is never server-wide.
  * Keys are write-only, and each setting has a connection test.
* **Backups & Restore**:
  * Snapshots are taken daily and on demand, and can be downloaded.
  * **Restore** replaces the whole database, including users and API keys. See
    [deployment.md](deployment.md#backup--restore).

## Account

**Account** in the top bar: change your password, and set up or remove two-factor authentication (removing is
possible only when it is not mandatory).

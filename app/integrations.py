"""
Record actions and external integrations, mirroring the row menus of the Aurora desktop app
(controller.js / misp.js / virustotal.js):

  * Investigated Systems  -> To Timeline
  * Malware/Tools         -> To Timeline, To hosts (Investigated Systems), Send to MISP, Check VT
  * Network Indicators    -> Send to MISP
  * Exfiltration          -> To Timeline
  (Duplicate Line is done in the browser: it opens a pre-filled "new record" form.)

Unlike the desktop app, MISP and VirusTotal are called by the *server*: the API keys are never sent to a
browser, never exported (.fox / Excel / backups) and never shown again once saved (see cases.public_meta).

Outbound requests use http.client directly: no redirects are followed, responses are size-limited, TLS is
verified, and the connection goes to the IP address that was checked (no DNS-rebinding window). The MISP
URL is entered by case editors, so loopback, link-local (cloud metadata), multicast and reserved addresses
are refused unless the host is explicitly listed in MISP_ALLOWED_HOSTS.
"""
from __future__ import annotations

import http.client
import ipaddress
import json
import re
import socket
import ssl
import time
from typing import Any
from urllib.parse import quote, urlsplit

from . import cases as C
from . import schema as S
from . import server_settings as SS
from .config import settings

VT_HOST = "www.virustotal.com"
MAX_RESPONSE = 4 * 1024 * 1024
MAX_MISP_ATTRIBUTES = 10
MAX_COMMENT = 1500

# Aurora's misp_attribute_types, plus sha1/sha256 which Aurora proposes for long hashes.
MISP_TYPES = ["filename", "domain", "ip-dst", "ip-dst|port", "ip-src", "ip-src|port", "md5", "sha1", "sha256",
              "url", "domain|ip"]
HASH_TYPES = {32: "md5", 40: "sha1", 64: "sha256"}
_EVENT_ID_RE = re.compile(r"^(\d{1,12}|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})$")

ACTION_SECTIONS = {
    "to_timeline": ("investigated_systems", "malware", "exfiltration"),
    "to_investigated_systems": ("malware",),
    "send_to_misp": ("malware", "network_indicators"),
    "check_virustotal": ("malware",),
}
ACTION_LABELS = {"to_timeline": "To Timeline", "to_investigated_systems": "To hosts (Investigated Systems)",
                 "send_to_misp": "Send to MISP", "check_virustotal": "Check VirusTotal"}


class IntegrationError(Exception):
    """An action that cannot be performed. `status` is the HTTP status the API answers with."""
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


# --------------------------------------------------------------------------- #
# Configuration state (never exposes the keys themselves)
# --------------------------------------------------------------------------- #

def _server(srv: dict | None) -> dict:
    return srv if srv is not None else SS.load()


def misp_settings(meta: dict, srv: dict | None = None) -> dict:
    """Where the case's MISP comes from: the server-wide MISP while the case's switch is on, otherwise the case's
    own URL and API key (both needed). The server-wide key is only ever sent to the server-wide URL. The event ID
    always comes from the case."""
    event = str(meta.get("mispeventid") or "").strip()
    missing, note = [], ""
    if S.case_value(meta, "use_server_misp"):
        srv = _server(srv)
        if srv["misp_url"] and srv["misp_apikey"]:
            source, server = "server", srv["misp_url"]
        else:
            source, server = None, ""
            missing.append("server-wide MISP")
            note = "no server-wide MISP is configured: ask an administrator, or untick 'Use the server-wide MISP'"
    else:
        case_url, case_key = (meta.get("mispserver") or "").strip(), bool(meta.get("mispapikey"))
        source, server = "case", case_url
        missing += [label for ok, label in ((case_url, "MISP server URL"), (case_key, "MISP API key")) if not ok]
        if missing:
            note = "this case uses its own MISP, which needs both a URL and an API key"
    if not event:
        missing.append("MISP event ID")
    return {"source": source, "server": server, "event_id": event, "missing": missing, "note": note}


def vt_settings(meta: dict, srv: dict | None = None) -> dict:
    """The server-wide key while the case's switch is on, otherwise the case's own key."""
    if S.case_value(meta, "use_server_vt"):
        if _server(srv)["vt_apikey"]:
            return {"source": "server", "note": ""}
        return {"source": None, "note": "no server-wide VirusTotal key is configured: ask an administrator, "
                                        "or untick 'Use the server-wide VirusTotal key'"}
    if meta.get("vtapikey"):
        return {"source": "case", "note": ""}
    return {"source": None, "note": "this case uses its own VirusTotal key, which is not set"}


def vt_key(meta: dict) -> str:
    """The VirusTotal key for this case's calls; IntegrationError (with the reason) when there is none."""
    srv = SS.load()
    st = vt_settings(meta, srv)
    if st["source"] == "case":
        return C.secret(meta, "vtapikey")
    if st["source"] == "server":
        return SS.secret(srv, "vt_apikey")
    raise IntegrationError(f"No VirusTotal key for this case ({st['note']})")


def status(meta: dict, srv: dict | None = None) -> dict:
    srv = _server(srv)
    enabled = settings.integrations_enabled
    m, v = misp_settings(meta, srv), vt_settings(meta, srv)
    return {
        "enabled": enabled,
        "misp": {"configured": enabled and not m["missing"], **m},
        "virustotal": {"configured": enabled and v["source"] is not None, **v},
    }


def adopt_server_misp(meta: dict) -> str | None:
    """.fox import: a MISP server URL equal to the server-wide one means "use the server-wide MISP" (exports leave
    the URL empty for such cases). Any other URL stays the case's own MISP (switch off; it still needs a key)."""
    url = (meta.get("mispserver") or "").strip().rstrip("/")
    server = SS.load()["misp_url"].rstrip("/")
    if url and server and url.lower() == server.lower():
        meta["mispserver"] = ""
        meta["use_server_misp"] = True
        return "The MISP server URL is the server-wide MISP: the case uses the server-wide MISP settings"
    if url:
        return ("The case uses its own MISP server from the file; add its MISP API key in Case Details, or tick "
                "'Use the server-wide MISP'")
    return None


def hash_type(value: str) -> str | None:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-fA-F]+", value or ""):
        return None
    return HASH_TYPES.get(len(value))


def available_actions(section: str, data: dict, meta: dict) -> list[dict]:
    """Which row actions apply to a record, and why one is unavailable (shown as a tooltip in the UI)."""
    st = status(meta)
    out = []
    for action, sections in ACTION_SECTIONS.items():
        if section not in sections:
            continue
        reason = ""
        if action == "to_investigated_systems" and not data.get("hostname"):
            reason = "Set the Host of this malware first"
        elif action == "send_to_misp":
            if not st["enabled"]:
                reason = "Integrations are disabled on this server"
            elif not st["misp"]["configured"]:
                reason = _missing_text(st["misp"])
            elif not misp_proposals(section, data):
                reason = "This record has no value that can be sent to MISP"
        elif action == "check_virustotal":
            if not st["enabled"]:
                reason = "Integrations are disabled on this server"
            elif not st["virustotal"]["configured"]:
                reason = f"No VirusTotal key for this case ({st['virustotal']['note']})"
            elif not data.get("md5"):
                reason = "Enter the file hash first"
            elif not hash_type(data.get("md5")):
                reason = "The hash must be an MD5, SHA-1 or SHA-256 (32/40/64 hex characters)"
        out.append({"action": action, "label": ACTION_LABELS[action], "available": not reason, "reason": reason})
    return out


def _require_action(action: str, section: str):
    if section not in ACTION_SECTIONS[action]:
        names = ", ".join(S.SECTIONS[s].label for s in ACTION_SECTIONS[action])
        raise IntegrationError(f"'{ACTION_LABELS[action]}' is only available for: {names}")


# --------------------------------------------------------------------------- #
# Record -> record actions (same field mapping as Aurora's controller.js)
# --------------------------------------------------------------------------- #

def _full_path(path: str, filename: str) -> str:
    path, filename = path or "", filename or ""
    if not path:
        return filename
    if filename and path.lower().rstrip("\\/").endswith(("\\" + filename.lower(), "/" + filename.lower())):
        return path.rstrip("\\/")          # the path already names the file
    if path.endswith(("\\", "/")):
        return path + filename
    sep = "/" if "/" in path and "\\" not in path else "\\"
    return path + sep + filename


def _lookup(meta: dict, key: str, wanted: str) -> str:
    """The lookup entry matching `wanted` (case-insensitive), or "" when the case has no such entry."""
    for t in C.lookup_texts(meta, key):
        if isinstance(t, str) and t.lower() == wanted.lower():
            return t
    return ""


def timeline_values(section: str, data: dict, meta: dict) -> dict:
    _require_action("to_timeline", section)
    if section == "investigated_systems":
        vals = {"event_host": data.get("hostname", ""), "event_data": data.get("summary", ""),
                "date_time": data.get("first_compromise", ""), "followup": True}
    elif section == "malware":
        summary = f"Malware created ({_full_path(data.get('path_on_disk'), data.get('text'))})."
        if data.get("notes"):
            summary += " " + data["notes"]
        vals = {"event_host": data.get("hostname", ""), "event_type": _lookup(meta, "event_types", "Malware"),
                "event_data": summary, "date_time": data.get("creation_date", ""), "followup": True,
                "attribution": data.get("attribution", "")}
    else:  # exfiltration: staging system -> destination
        filename = data.get("filename") or "Data"
        vals = {"event_host": data.get("stagingsystem", ""), "event_source_host": data.get("exfil_to", ""),
                "direction": _lookup(meta, "direction", "->") if data.get("exfil_to") else "",
                "event_type": _lookup(meta, "event_types", "Exfil"), "event_data": f"{filename} exfiltrated.",
                "notes": data.get("notes", ""), "date_time": data.get("exfiltime", ""), "followup": True,
                "attribution": data.get("attribution", "")}
    return {k: v for k, v in vals.items() if v not in ("", None)}


def to_timeline(conn, case_pk: int, section: str, recid: int, user: str) -> dict:
    """Must run inside write_tx."""
    _require_action("to_timeline", section)
    meta = C.get_meta(conn, case_pk)
    src = C.get_record(conn, case_pk, section, recid)
    created = C.create_record(conn, case_pk, "timeline", timeline_values(section, src["data"], meta), user)
    C._audit(conn, case_pk, user, "to_timeline", section, recid, after={"timeline_recid": created["recid"]})
    return created


def to_investigated_systems(conn, case_pk: int, section: str, recid: int, user: str) -> dict:
    """Malware -> Investigated Systems ("To hosts" in Aurora). Must run inside write_tx."""
    _require_action("to_investigated_systems", section)
    meta = C.get_meta(conn, case_pk)
    data = C.get_record(conn, case_pk, section, recid)["data"]
    host = data.get("hostname")
    if not host:
        raise IntegrationError("Set the Host of this malware first")
    existing = conn.execute("SELECT recid FROM records WHERE case_pk=? AND section='investigated_systems' "
                            "AND lower(JSON_UNQUOTE(JSON_EXTRACT(data, '$.hostname'))) = lower(?)",
                            (case_pk, host)).fetchone()
    if existing:
        raise IntegrationError(f"{host} is already in Investigated Systems (#{existing[0]}); "
                               "it can't be added twice", 409)
    summary = f"Malware created ({_full_path(data.get('path_on_disk'), data.get('text'))})."
    if data.get("notes"):
        summary += " " + data["notes"]
    vals = {"hostname": host, "summary": summary, "first_compromise": data.get("creation_date", ""),
            "verdict": _lookup(meta, "verdicts", "Infected")}
    created = C.create_record(conn, case_pk, "investigated_systems",
                              {k: v for k, v in vals.items() if v}, user)
    C._audit(conn, case_pk, user, "to_investigated_systems", section, recid,
             after={"investigated_systems_recid": created["recid"]})
    return created


# --------------------------------------------------------------------------- #
# Outbound HTTPS
# --------------------------------------------------------------------------- #

def _ssl_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context(cafile=settings.integrations_ca_file or None)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


def _blocked(ip: ipaddress._BaseAddress, allow_private: bool = True) -> bool:
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    # Always refused: loopback, link-local (incl. the 169.254.169.254 cloud-metadata address), multicast,
    # unspecified, reserved. Private RFC1918 / unique-local only when MISP_ALLOW_PRIVATE is off.
    if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified or ip.is_reserved:
        return True
    return not allow_private and ip.is_private


def _resolve(host: str, port: int, guard: bool, allow_private: bool) -> None:
    """Pre-connection safety check only: refuse a host that currently resolves to a blocked address. The
    connection itself re-resolves the hostname (DNS may legitimately move the MISP server to a new IP), so this
    is a check, not a pin. `allow_private` is the caller's decision for *this* URL: private ranges are allowed
    for the admin's server-wide MISP (MISP_ALLOW_PRIVATE), but never for an editor-supplied case MISP URL."""
    if not guard:
        return
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError):
        raise IntegrationError(f"Cannot resolve {host}", 502)
    addrs = [ipaddress.ip_address(i[4][0].split("%")[0]) for i in infos]
    bad = [a for a in addrs if _blocked(a, allow_private)]
    if bad:
        always = (bad[0].is_loopback or bad[0].is_link_local or bad[0].is_multicast or bad[0].is_unspecified
                  or bad[0].is_reserved)
        if always:
            kind, how = "loopback / link-local / cloud-metadata / reserved", "allow a host with MISP_ALLOWED_HOSTS."
        elif settings.misp_allow_private:
            # Private ranges are allowed globally, so this is an editor-supplied case URL: the only escape hatch
            # is an explicit allowlist entry (MISP_ALLOW_PRIVATE does not extend to case-controlled URLs).
            kind = "a private address"
            how = "add the host to MISP_ALLOWED_HOSTS (a case's own MISP URL may not use private ranges)."
        else:
            kind = "a private address"
            how = "allow private ranges with MISP_ALLOW_PRIVATE=true, or a single host with MISP_ALLOWED_HOSTS."
        raise IntegrationError(f"{host} resolves to {bad[0]} ({kind}), which is not allowed for integrations. "
                               f"An administrator can {how}", 400)


def _request(method: str, url: str, headers: dict, body: Any = None, guard: bool = True,
             verify: bool = True, allow_private: bool | None = None) -> tuple[int, Any]:
    if not settings.integrations_enabled:
        raise IntegrationError("Integrations are disabled on this server (INTEGRATIONS_ENABLED=false)", 403)
    u = urlsplit(url)
    if u.scheme not in ("https", "http") or not u.hostname:
        raise IntegrationError("Invalid URL")
    host = u.hostname
    port = u.port or (443 if u.scheme == "https" else 80)
    if allow_private is None:
        allow_private = settings.misp_allow_private
    _resolve(host, port, guard, allow_private)   # pre-connection check; the connection below re-resolves by hostname
    path = (u.path or "/") + (f"?{u.query}" if u.query else "")
    t = settings.integrations_timeout
    if u.scheme == "https":
        ctx = _ssl_context()
        if not verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        conn = http.client.HTTPSConnection(host, port=port, timeout=t, context=ctx)
    else:
        conn = http.client.HTTPConnection(host, port=port, timeout=t)
    data = None if body is None else json.dumps(body).encode("utf-8")
    hdrs = {"Accept": "application/json", "User-Agent": "aurora-ir-web", **headers}
    if data is not None:
        hdrs["Content-Type"] = "application/json"
    try:
        conn.request(method, path, body=data, headers=hdrs)
        resp = conn.getresponse()
        raw = resp.read(MAX_RESPONSE + 1)
    except ssl.SSLError as e:
        raise IntegrationError(f"TLS error talking to {host}: {e.reason or e}", 502)
    except socket.timeout:
        raise IntegrationError(f"{host} did not answer within {t} s", 504)
    except OSError as e:
        raise IntegrationError(f"Cannot connect to {host}: {e.strerror or e}", 502)
    finally:
        conn.close()
    if len(raw) > MAX_RESPONSE:
        raise IntegrationError(f"Response from {host} is too large", 502)
    try:
        parsed = json.loads(raw.decode("utf-8")) if raw else None
    except (UnicodeDecodeError, ValueError):
        parsed = None
    return resp.status, parsed


def _err_text(body: Any) -> str:
    """A short, plain error message from an upstream JSON body (never echoes our own key)."""
    if isinstance(body, dict):
        parts = []
        for k in ("message", "name", "error"):
            v = body.get(k)
            if isinstance(v, str):
                parts.append(v)
            elif isinstance(v, dict) and isinstance(v.get("message"), str):
                parts.append(v["message"])
        errs = body.get("errors")
        if isinstance(errs, (dict, list, str)):
            parts.append(json.dumps(errs, ensure_ascii=False) if not isinstance(errs, str) else errs)
        return " ".join(parts)[:500]
    return ""


# --------------------------------------------------------------------------- #
# VirusTotal (API v3; Aurora used the retired v2 file/report endpoint)
# --------------------------------------------------------------------------- #

def vt_lookup(apikey: str, file_hash: str) -> dict:
    """Verdict as Aurora stores it in the `vt` column: infected | clean | noresult."""
    if not apikey:
        raise IntegrationError("Add a VirusTotal API key in Case Details first")
    if not hash_type(file_hash):
        raise IntegrationError("The hash must be an MD5, SHA-1 or SHA-256 (32/40/64 hex characters)")
    code, body = _request("GET", f"https://{VT_HOST}/api/v3/files/{file_hash.lower()}",
                          {"x-apikey": apikey}, guard=False)
    if code == 404:
        return {"verdict": "noresult", "message": "VirusTotal does not know this file"}
    if code == 401:
        raise IntegrationError("VirusTotal rejected the API key", 400)
    if code == 429:
        raise IntegrationError("VirusTotal quota exceeded; try again later or use another API key", 429)
    if code != 200 or not isinstance(body, dict):
        raise IntegrationError(f"VirusTotal error (HTTP {code}) {_err_text(body)}".strip(), 502)
    attrs = (body.get("data") or {}).get("attributes") or {}
    stats = attrs.get("last_analysis_stats") or {}
    num = lambda k: stats.get(k) if isinstance(stats.get(k), int) else 0
    malicious, suspicious = num("malicious"), num("suspicious")
    total = sum(v for v in stats.values() if isinstance(v, int))
    if not stats:
        verdict = "noresult"
    else:
        verdict = "infected" if malicious > 0 else "clean"
    sha256 = attrs.get("sha256") if isinstance(attrs.get("sha256"), str) else ""
    return {"verdict": verdict, "malicious": malicious, "suspicious": suspicious, "engines": total,
            "name": attrs.get("meaningful_name") if isinstance(attrs.get("meaningful_name"), str) else "",
            "permalink": f"https://www.virustotal.com/gui/file/{sha256}" if re.fullmatch(r"[0-9a-f]{64}", sha256)
            else "",
            "message": f"{malicious}/{total} engines flag it as malicious" if stats else "No analysis available"}


def vt_test(apikey: str) -> dict:
    # Same idea as Aurora's "Test connection": look up a well-known hash (EICAR test file).
    vt_lookup(apikey, "44d88612fea8a8f36de82e1278abb02f")
    return {"ok": True, "message": "VirusTotal connected, API key accepted"}


def check_virustotal(case_pk: int, section: str, recid: int, user: str) -> dict:
    """Read the hash, ask VirusTotal (outside any DB lock), then store the verdict in `vt`."""
    from .db import cases_db, read_tx, write_tx
    _require_action("check_virustotal", section)
    with cases_db() as conn, read_tx(conn):
        meta = C.get_meta(conn, case_pk)
        rec = C.get_record(conn, case_pk, section, recid)
    file_hash = rec["data"].get("md5") or ""
    if not file_hash:
        raise IntegrationError("Enter the file hash first")
    result = vt_lookup(vt_key(meta), file_hash)
    with cases_db() as conn, write_tx(conn):
        updated = C.set_system_field(conn, case_pk, section, recid, "vt", result["verdict"], user,
                                     only_if={"md5": file_hash}, action="check_virustotal",
                                     note={"hash": file_hash, "result": result["message"]})
    return {"verdict": result["verdict"], "details": result, "record": updated}


# --------------------------------------------------------------------------- #
# MISP
# --------------------------------------------------------------------------- #

def misp_proposals(section: str, data: dict) -> list[dict]:
    """Attributes Aurora proposes in its "Add to MISP" popup for a record."""
    out = []

    def add(aurora_field, mtype, value, comment):
        if value not in ("", None) and not any(p["value"] == str(value) for p in out):
            out.append({"aurora_field": aurora_field, "type": mtype, "value": str(value),
                        "comment": (comment or "")[:MAX_COMMENT]})

    if section == "malware":
        notes = data.get("notes", "")
        add("Filename", "filename", data.get("text"), notes)
        if data.get("path_on_disk"):
            add("Fullpath", "filename", _full_path(data.get("path_on_disk"), data.get("text")), notes)
        ht = hash_type(data.get("md5", ""))
        if ht:
            add("Hash", ht, data.get("md5").lower(), notes)
    elif section == "network_indicators":
        ip, dom, port, notes = data.get("ip"), data.get("domainname"), data.get("port"), data.get("context", "")
        add("Domain Name", "domain", dom, notes)
        add("IP", "ip-dst", ip, notes)
        if ip and dom:
            add("Domain IP", "domain|ip", f"{dom}|{ip}", notes)
        if ip and port not in ("", None):
            add("IP Port", "ip-dst|port", f"{ip}|{port}", notes)
    return out


def _misp_conf(meta: dict) -> tuple[str, str, str, bool]:
    srv = SS.load()
    st = status(meta, srv)
    if not st["enabled"]:
        raise IntegrationError("Integrations are disabled on this server", 403)
    m = st["misp"]
    if not m["configured"]:
        raise IntegrationError(_missing_text(m))
    if m["source"] == "server":                      # the server-wide key goes to the server-wide URL only
        server, key, case_supplied = srv["misp_url"].rstrip("/"), SS.secret(srv, "misp_apikey"), False
    else:
        server, key, case_supplied = meta["mispserver"].rstrip("/"), C.secret(meta, "mispapikey"), True
    event = m["event_id"]
    if not _EVENT_ID_RE.match(event):
        raise IntegrationError("The MISP event ID must be a number or a UUID")
    why = SS.check_misp_url(server)
    if why:
        raise IntegrationError("The MISP server URL " + why)
    return server, key, event, case_supplied


def _missing_text(m: dict) -> str:
    text = "MISP is not ready: missing " + ", ".join(m["missing"])
    return f"{text} ({m['note']})" if m.get("note") else text


def _misp_call(meta: dict, method: str, path: str, body: Any = None) -> tuple[int, Any, str]:
    server, key, event, case_supplied = _misp_conf(meta)
    code, resp = _misp_http(server, key, method, path.replace("{event}", quote(event, safe="")), body,
                            case_supplied=case_supplied)
    if code == 404:
        raise IntegrationError(f"MISP event {event} not found", 404)
    return code, resp, event


def _misp_http(server: str, key: str, method: str, path: str, body: Any = None,
               case_supplied: bool = False) -> tuple[int, Any]:
    host = (urlsplit(server).hostname or "").lower()
    allowed = settings.misp_allowed_hosts
    if allowed and host not in allowed:
        raise IntegrationError(f"{host} is not in MISP_ALLOWED_HOSTS", 400)
    # MISP_ALLOW_PRIVATE is the admin's trust in their own server-wide MISP; it does NOT extend to a case's own
    # MISP URL, which an editor controls. An editor-supplied URL may reach a private range only when the admin
    # has explicitly allowlisted the host (MISP_ALLOWED_HOSTS), which also turns the guard off below. (CWE-918.)
    allow_private = settings.misp_allow_private and not case_supplied
    code, resp = _request(method, server + path, {"Authorization": key}, body, guard=not allowed,
                          verify=settings.misp_verify_tls, allow_private=allow_private)
    if code in (401, 403):
        raise IntegrationError(f"MISP refused the request (HTTP {code}). Check the API key. {_err_text(resp)}"
                               .strip(), 400)
    return code, resp


def misp_server_test(srv: dict) -> dict:
    """Administration -> Integrations: check the server-wide MISP URL and key (no event: that is per case)."""
    if not settings.integrations_enabled:
        raise IntegrationError("Integrations are disabled on this server", 403)
    if not (srv["misp_url"] and srv["misp_apikey"]):
        raise IntegrationError("Set the server-wide MISP URL and API key and save first")
    why = SS.check_misp_url(srv["misp_url"])
    if why:
        raise IntegrationError("The MISP server URL " + why)
    code, resp = _misp_http(srv["misp_url"].rstrip("/"), SS.secret(srv, "misp_apikey"), "GET", "/servers/getVersion")
    if code != 200 or not isinstance(resp, dict) or not isinstance(resp.get("version"), str):
        raise IntegrationError(f"Unexpected answer from MISP (HTTP {code}). Is MISP running there?", 502)
    return {"ok": True, "message": f"MISP {resp['version']} connected, API key accepted"}


def misp_test(meta: dict) -> dict:
    code, resp, event = _misp_call(meta, "GET", "/events/view/{event}")
    if code != 200 or not isinstance(resp, dict) or not isinstance(resp.get("Event"), dict):
        raise IntegrationError(f"Unexpected answer from MISP (HTTP {code}). Is MISP running there?", 502)
    info = resp["Event"].get("info")
    return {"ok": True, "event_id": event, "event_info": info if isinstance(info, str) else "",
            "message": f"MISP connected. You'll be sending to the event '{info}'"}


def _clean_attributes(section: str, data: dict, attributes: list | None) -> list[dict]:
    proposals = misp_proposals(section, data)
    if not proposals:
        raise IntegrationError("This record has no value that can be sent to MISP")
    if attributes is None:
        return [{"type": p["type"], "value": p["value"], "comment": p["comment"]} for p in proposals]
    if not isinstance(attributes, list) or not attributes:
        raise IntegrationError("Select at least one attribute")
    if len(attributes) > MAX_MISP_ATTRIBUTES:
        raise IntegrationError(f"At most {MAX_MISP_ATTRIBUTES} attributes per request")
    allowed = {p["value"] for p in proposals}
    out = []
    for i, a in enumerate(attributes):
        if not isinstance(a, dict) or set(a) - {"type", "value", "comment"}:
            raise IntegrationError(f"attribute {i}: expected an object with type, value and comment")
        if a.get("value") not in allowed:
            raise IntegrationError(f"attribute {i}: value must be one of the values proposed for this record")
        if a.get("type") not in MISP_TYPES:
            raise IntegrationError(f"attribute {i}: type must be one of {', '.join(MISP_TYPES)}")
        comment = a.get("comment", "")
        if not isinstance(comment, str) or len(comment) > MAX_COMMENT or re.search(r"[\x00-\x08\x0b\x0c\x0e-\x1f]",
                                                                                  comment):
            raise IntegrationError(f"attribute {i}: comment must be text of at most {MAX_COMMENT} characters")
        out.append({"type": a["type"], "value": a["value"], "comment": comment})
    return out


def send_to_misp(case_pk: int, section: str, recid: int, attributes: list | None, user: str) -> dict:
    from .db import cases_db, read_tx, write_tx
    _require_action("send_to_misp", section)
    with cases_db() as conn, read_tx(conn):
        meta = C.get_meta(conn, case_pk)
        data = C.get_record(conn, case_pk, section, recid)["data"]
    attrs = _clean_attributes(section, data, attributes)
    _misp_conf(meta)
    code, resp, event = _misp_call(meta, "POST", "/attributes/add/{event}", attrs)
    if code not in (200, 201) or not isinstance(resp, dict):
        raise IntegrationError(f"MISP did not accept the attributes (HTTP {code}). {_err_text(resp)}".strip(), 502)
    added = resp.get("Attribute")
    n_added = len(added) if isinstance(added, list) else (1 if isinstance(added, dict) else 0)
    problems = _err_text({"errors": resp["errors"]}) if resp.get("errors") else ""
    with cases_db() as conn, write_tx(conn):
        C._audit(conn, case_pk, user, "send_to_misp", section, recid,
                 after={"event_id": event, "added": n_added,
                        "attributes": [{"type": a["type"], "value": a["value"]} for a in attrs]})
    msg = f"Added {n_added} attribute{'s' if n_added != 1 else ''} to MISP event {event}."
    if problems:
        msg += f" MISP reported: {problems}"
    return {"ok": n_added > 0, "event_id": event, "sent": len(attrs), "added": n_added, "message": msg,
            "time": int(time.time())}

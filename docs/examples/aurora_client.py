#!/usr/bin/env python3
"""
Minimal Aurora IR Web API client (Python 3 standard library only) + CLI.

    export AURORA_URL=https://air.example.com  AURORA_KEY=aurora_...
    python3 aurora_client.py cases
    python3 aurora_client.py summary 1
    python3 aurora_client.py search 1 spadertech
    python3 aurora_client.py export 1 IR-608.fox
    python3 aurora_client.py import-timeline-csv 1 events.csv      # columns = timeline field names

The CSV import uses the atomic bulk endpoint with declare_missing=true, so unknown hosts are added to
Systems automatically and either every row is imported or none is.
"""
import csv
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request


class AuroraError(Exception):
    def __init__(self, status, body):
        super().__init__(f"HTTP {status}: {body}")
        self.status, self.body = status, body


class Aurora:
    def __init__(self, base_url: str, token: str, timeout: float = 60):
        self.base = base_url.rstrip("/")
        self.token = token
        self.timeout = timeout

    def _req(self, method, path, body=None, params=None, raw=False):
        url = self.base + path + ("?" + urllib.parse.urlencode(params, doseq=True) if params else "")
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method, headers={
            "Authorization": f"Bearer {self.token}", "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                payload = r.read()
                return payload if raw else json.loads(payload or b"null")
        except urllib.error.HTTPError as e:
            text = e.read().decode("utf-8", "replace")
            try:
                text = json.loads(text)
            except ValueError:
                pass
            raise AuroraError(e.code, text) from None

    # --- reading
    def cases(self):
        return self._req("GET", "/api/cases")

    def case(self, case):
        return self._req("GET", f"/api/cases/{case}")

    def records(self, case, section, **params):
        """params: q, filter=["field:value", ...], sort, order, limit, offset"""
        return self._req("GET", f"/api/cases/{case}/sections/{section}", params=params)

    def record(self, case, section, recid):
        return self._req("GET", f"/api/cases/{case}/sections/{section}/{recid}")

    def search(self, case, q, limit=50):
        return self._req("GET", f"/api/cases/{case}/search", params={"q": q, "limit": limit})

    def summary(self, case):
        return self._req("GET", f"/api/cases/{case}/summary")

    def export_fox(self, case) -> bytes:
        return self._req("GET", f"/api/cases/{case}/export", raw=True)

    # --- writing
    def create(self, case, section, data, declare_missing=False):
        return self._req("POST", f"/api/cases/{case}/sections/{section}", {"data": data},
                         {"declare_missing": "true"} if declare_missing else None)

    def bulk(self, case, section, records, declare_missing=False):
        return self._req("POST", f"/api/cases/{case}/sections/{section}/bulk", {"records": records},
                         {"declare_missing": "true"} if declare_missing else None)

    def update(self, case, section, recid, changes, version):
        return self._req("PATCH", f"/api/cases/{case}/sections/{section}/{recid}",
                         {"changes": changes, "version": version})

    def update_with_retry(self, case, section, recid, change_fn, attempts=5):
        """Read-modify-write that retries on concurrent modification (HTTP 409)."""
        for _ in range(attempts):
            rec = self.record(case, section, recid)
            try:
                return self.update(case, section, recid, change_fn(rec["data"]), rec["version"])
            except AuroraError as e:
                if e.status != 409:
                    raise
        raise RuntimeError("record keeps changing; giving up")

    def delete(self, case, section, recid, version=None):
        return self._req("DELETE", f"/api/cases/{case}/sections/{section}/{recid}",
                         params={"version": version} if version is not None else None)


def _client():
    url, token = os.environ.get("AURORA_URL"), os.environ.get("AURORA_KEY")
    if not url or not token:
        sys.exit("set AURORA_URL and AURORA_KEY")
    return Aurora(url, token)


def main(argv):
    if not argv:
        sys.exit(__doc__)
    a, cmd = _client(), argv[0]
    try:
        if cmd == "cases":
            for c in a.cases():
                print(f"{c['id']:>4}  {c['case_id']:<20} {c['client']}")
        elif cmd == "summary":
            print(json.dumps(a.summary(int(argv[1])), indent=2, ensure_ascii=False))
        elif cmd == "search":
            for h in a.search(int(argv[1]), argv[2])["results"]:
                print(f"{h['section']:<22} #{h['recid']:<5} {', '.join(h['matched_fields'])}")
        elif cmd == "export":
            data = a.export_fox(int(argv[1]))
            with open(argv[2], "wb") as fh:
                fh.write(data)
            print(f"wrote {argv[2]} ({len(data)} bytes)")
        elif cmd == "import-timeline-csv":
            with open(argv[2], newline="", encoding="utf-8-sig") as fh:
                rows = [{k: v for k, v in r.items() if v not in (None, "")} for r in csv.DictReader(fh)]
            for r in rows:
                for b in ("visual", "followup"):
                    if b in r:
                        r[b] = r[b].strip().lower() in ("1", "true", "yes", "x")
            res = a.bulk(int(argv[1]), "timeline", rows, declare_missing=True)
            print(f"imported {res['created']} timeline events")
        else:
            sys.exit(f"unknown command {cmd}\n{__doc__}")
    except AuroraError as e:
        print(json.dumps(e.body, indent=2) if isinstance(e.body, dict) else e, file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main(sys.argv[1:])

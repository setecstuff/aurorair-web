#!/usr/bin/env python3
"""
Query the public OSV database (https://osv.dev) for vulnerabilities in the hash-pinned Python dependencies.
Self-contained (stdlib only, no third-party action/binary). Exits non-zero if any advisory is found.

Usage: python .github/scripts/osv_check.py requirements.lock
"""
import json
import re
import sys
import urllib.request

LINE = re.compile(r"^([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)==([^\s\\;]+)")


def parse(path):
    pkgs = {}
    for line in open(path, encoding="utf-8"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = LINE.match(line)
        if m:
            pkgs[m.group(1)] = m.group(2)
    return pkgs


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "requirements.lock"
    pkgs = parse(path)
    if not pkgs:
        print(f"no pinned packages found in {path}")
        return 1
    names = sorted(pkgs)
    queries = [{"package": {"name": n, "ecosystem": "PyPI"}, "version": pkgs[n]} for n in names]
    req = urllib.request.Request(
        "https://api.osv.dev/v1/querybatch",
        data=json.dumps({"queries": queries}).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    res = json.loads(urllib.request.urlopen(req, timeout=120).read())
    hits = []
    for n, r in zip(names, res.get("results", [])):
        ids = [v["id"] for v in r.get("vulns", [])]
        if ids:
            hits.append((n, pkgs[n], ids))
    print(f"OSV scan: {len(names)} PyPI packages from {path}")
    if not hits:
        print("No known vulnerabilities.")
        return 0
    print(f"\n{len(hits)} vulnerable package(s):")
    for n, v, ids in hits:
        print(f"  {n}=={v}: {', '.join(ids)}  (https://osv.dev/{ids[0]})")
    return 1


if __name__ == "__main__":
    sys.exit(main())

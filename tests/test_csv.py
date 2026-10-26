"""
CSV import / export: round-trip fidelity, column rules, strict validation (the whole file is rejected if any
cell is invalid), formula-injection neutralisation, and reference integrity.
"""
import pytest
from fastapi.testclient import TestClient

from tests.test_app import login
from app.main import app


@pytest.fixture(scope="module")
def admin():
    with TestClient(app) as c:
        yield login(c)


def mkcase(admin, cid):
    r = admin.post("/api/cases", json={"case_id": cid, "client": "c"})
    assert r.status_code == 200, r.text
    return r.json()["id"]


def add(admin, case, section, data):
    r = admin.post(f"/api/cases/{case}/sections/{section}", json={"data": data})
    assert r.status_code == 200, r.text


def rows(admin, case, section):
    return admin.get(f"/api/cases/{case}/sections/{section}").json()["records"]


def imp(admin, case, section, text, q=""):
    return admin.post(f"/api/cases/{case}/sections/{section}/import.csv{q}", content=text)


# --------------------------------------------------------------------------- #

def test_roundtrip_and_columns(admin):
    a = mkcase(admin, "CSV-A")
    add(admin, a, "casenotes", {"note": "first note"})
    add(admin, a, "casenotes", {"note": "second, with a comma"})      # must survive via quoting
    r = admin.get(f"/api/cases/{a}/sections/casenotes/export.csv")
    assert r.status_code == 200 and "text/csv" in r.headers["content-type"]
    text = r.text
    header = text.splitlines()[0]
    assert header == "note,owner"                                     # editable fields only
    assert "date_added" not in text and "recid" not in text           # no server-managed columns
    # re-import into a fresh case: same data
    b = mkcase(admin, "CSV-B")
    assert imp(admin, b, "casenotes", text).json()["created"] == 2
    notes = sorted(x["data"]["note"] for x in rows(admin, b, "casenotes"))
    assert notes == ["first note", "second, with a comma"]


def test_formula_injection_is_neutralised(admin):
    a = mkcase(admin, "CSV-INJ")
    add(admin, a, "casenotes", {"note": "=cmd|' /C calc'!A0"})
    text = admin.get(f"/api/cases/{a}/sections/casenotes/export.csv").text
    # the dangerous cell is prefixed with a single quote so a spreadsheet will not execute it
    assert "'=cmd" in text and "\n=cmd" not in text
    # importing strips the guard back off: stored value is the original text (and it is only ever text)
    b = mkcase(admin, "CSV-INJ2")
    imp(admin, b, "casenotes", text)
    assert rows(admin, b, "casenotes")[0]["data"]["note"] == "=cmd|' /C calc'!A0"


def test_delimiters_and_quotes_roundtrip(admin):
    a = mkcase(admin, "CSV-DELIM")
    tricky = 'has, comma; semicolon "quote" and = sign'
    add(admin, a, "casenotes", {"note": tricky})
    text = admin.get(f"/api/cases/{a}/sections/casenotes/export.csv").text
    b = mkcase(admin, "CSV-DELIM2")
    assert imp(admin, b, "casenotes", text).json()["created"] == 1
    assert rows(admin, b, "casenotes")[0]["data"]["note"] == tricky


def test_rejects_unknown_and_duplicate_columns(admin):
    a = mkcase(admin, "CSV-COL")
    assert imp(admin, a, "casenotes", "note,bogus\r\nx,y\r\n").status_code in (400, 422)
    assert imp(admin, a, "casenotes", "note,note\r\na,b\r\n").status_code in (400, 422)
    # server-managed columns are not importable either
    assert imp(admin, a, "casenotes", "note,date_added\r\nx,123\r\n").status_code in (400, 422)
    assert rows(admin, a, "casenotes") == []                          # nothing written


def test_rejects_wrong_column_count(admin):
    a = mkcase(admin, "CSV-COUNT")
    assert imp(admin, a, "casenotes", "note,owner\r\njust-one\r\n").status_code in (400, 422)
    assert rows(admin, a, "casenotes") == []


def test_rejects_invalid_values_and_is_all_or_nothing(admin):
    a = mkcase(admin, "CSV-VAL")
    # invalid port / ip are refused by the normal field validation
    assert imp(admin, a, "network_indicators", "ip,port\r\n10.0.0.1,99999999\r\n").status_code in (400, 422)
    assert imp(admin, a, "network_indicators", "ip,port\r\nnot-an-ip,443\r\n").status_code in (400, 422)
    # a required field left empty is refused
    assert imp(admin, a, "casenotes", 'note\r\n""\r\n').status_code in (400, 422)
    # all-or-nothing: a valid row followed by an invalid one imports NOTHING
    assert imp(admin, a, "network_indicators", "ip,port\r\n10.0.0.1,443\r\n10.0.0.2,notaport\r\n").status_code in (400, 422)
    assert rows(admin, a, "network_indicators") == []


def test_rejects_non_utf8_and_nul(admin):
    a = mkcase(admin, "CSV-BIN")
    assert imp(admin, a, "casenotes", "note\r\nbefore\x00after\r\n").status_code in (400, 422)
    assert admin.post(f"/api/cases/{a}/sections/casenotes/import.csv", content=b"\xff\xfe\x00bad").status_code in (400, 422)
    assert rows(admin, a, "casenotes") == []


def test_empty_upload_rejected(admin):
    a = mkcase(admin, "CSV-EMPTY")
    assert admin.post(f"/api/cases/{a}/sections/casenotes/import.csv", content=b"").status_code == 400
    assert imp(admin, a, "casenotes", "note\r\n").status_code in (400, 422)   # header only, no data rows


def test_reference_integrity_and_declare_missing(admin):
    a = mkcase(admin, "CSV-REF")
    # network_indicators.malware is a reference; an unknown one is refused by default
    assert imp(admin, a, "network_indicators", "ip,malware\r\n10.0.0.9,Emotet\r\n").status_code in (400, 422)
    assert rows(admin, a, "network_indicators") == []
    # ...but declare_missing auto-creates the referenced record, like the .fox import
    assert imp(admin, a, "network_indicators", "ip,malware\r\n10.0.0.9,Emotet\r\n", "?declare_missing=true").json()["created"] == 1
    assert any(m["data"]["text"] == "Emotet" for m in rows(admin, a, "malware"))


def test_section_must_exist(admin):
    a = mkcase(admin, "CSV-SEC")
    assert admin.get(f"/api/cases/{a}/sections/nope/export.csv").status_code == 404
    assert imp(admin, a, "nope", "x\r\n1\r\n").status_code == 404


# ------------------------------------------------------------------ hostile input

def test_rejects_too_many_rows(admin):
    a = mkcase(admin, "CSV-MANY")
    big = "note\r\n" + "".join(f"row{i}\r\n" for i in range(1001))     # over the 1000 bulk cap
    assert imp(admin, a, "casenotes", big).status_code in (400, 422)
    assert rows(admin, a, "casenotes") == []                          # nothing written


def test_rejects_embedded_newline_in_single_line_field(admin):
    a = mkcase(admin, "CSV-NL")
    # a quoted field carrying a real newline parses as one value; a single-line field must refuse it
    assert imp(admin, a, "systems", 'text\r\n"a\nb"\r\n').status_code in (400, 422)
    assert rows(admin, a, "systems") == []


def test_rejects_malformed_quotes(admin):
    a = mkcase(admin, "CSV-Q")
    # an unbalanced quote makes the parse swallow following columns/rows -> wrong column count / parse error
    r = imp(admin, a, "systems", 'text,os\r\n"unterminated,field\r\nmore,data\r\n')
    assert r.status_code in (400, 422)


def test_semicolon_delimited_is_rejected_not_misimported(admin):
    a = mkcase(admin, "CSV-SEMI")
    # we standardise on comma; a ;-delimited file becomes one unknown column and is refused (never silently mangled)
    assert imp(admin, a, "casenotes", "note;owner\r\nhello;bob\r\n").status_code in (400, 422)
    assert rows(admin, a, "casenotes") == []


def test_recid_and_auto_columns_not_importable(admin):
    a = mkcase(admin, "CSV-RECID")
    for col in ("recid", "date_added", "version"):
        assert imp(admin, a, "casenotes", f"note,{col}\r\nx,1\r\n").status_code in (400, 422)
    assert rows(admin, a, "casenotes") == []


def test_formula_guard_covers_all_prefixes_and_roundtrips(admin):
    a = mkcase(admin, "CSV-FML")
    dangerous = ["=1+1", "+1", "-1+1", "@SUM(1)", "\tTAB"]
    for i, v in enumerate(dangerous):
        add(admin, a, "casenotes", {"note": v})
    text = admin.get(f"/api/cases/{a}/sections/casenotes/export.csv").text
    # every dangerous value is quote-guarded in the export: no data line begins with a formula trigger
    for line in text.splitlines()[1:]:
        assert not line[:1] in ("=", "+", "-", "@", "\t"), line
    # import restores the originals exactly (guard stripped), stored only as text
    b = mkcase(admin, "CSV-FML2")
    imp(admin, b, "casenotes", text)
    assert sorted(x["data"]["note"] for x in rows(admin, b, "casenotes")) == sorted(dangerous)


def test_lf_only_and_bom_are_accepted(admin):
    a = mkcase(admin, "CSV-LF")
    assert imp(admin, a, "casenotes", "note\nunix-lf\n").json()["created"] == 1   # bare LF
    b = mkcase(admin, "CSV-BOM")
    assert imp(admin, b, "casenotes", "﻿note\r\nwith-bom\r\n").json()["created"] == 1  # UTF-8 BOM


def test_empty_cells_respect_required(admin):
    a = mkcase(admin, "CSV-REQ")
    # systems.text is the required key field; an empty value must be refused
    assert imp(admin, a, "systems", 'text,os\r\n"",linux\r\n').status_code in (400, 422)
    # an optional field left blank is fine
    assert imp(admin, a, "systems", "text,os\r\nhost-1,\r\n").json()["created"] == 1

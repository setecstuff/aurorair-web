"""
Case reports: PDF and LaTeX, built from the same consistent snapshot as the .fox and Excel exports.

Content (both formats): cover (application, logo, case presentation, who exported it and when, case metadata),
the Report page (executive summary, context, conclusions, lessons learned), the charts of the three Aurora reports
(Visual Timeline, Lateral Movement, Activity Plot) and every section as a table, in the default order.

Safety: case text is attacker-controlled.
* PDF: ReportLab paragraphs understand a markup language (<img src=...>, <a href=...>, <font>...). Every value is
  XML-escaped, so case data can never load local files or inject links/markup.
* LaTeX: every special character is escaped (\\ { } $ & # ^ _ % ~), so text such as \\input{/etc/passwd} or
  \\write18 is printed literally and never executed when the .tex is compiled.
"""
from __future__ import annotations

import io
import json
import math
import os
from datetime import datetime, timezone
from xml.sax.saxutils import escape as xml_escape

from . import cases as C
from . import schema as S
from .db import read_tx
from .security import LOGO_PNG

APP_NAME = "Aurora IR Web"
SECTION_ORDER = ["timeline", "investigated_systems", "malware", "compromised_accounts", "network_indicators",
                 "exfiltration", "osint", "systems", "investigators", "evidence", "actions", "casenotes"]

# Aurora's event-type colours (same as the web reports)
EVENT_COLORS = {
    "EventLog": "#32cd32", "File": "#ffd700", "Human": "#db7093", "Engagement": "#87cefa",
    "Lateral Movement": "#20b2aa", "Exfil": "#dda0dd", "Tanium Trace": "#db7093", "Malware": "#b22222",
    "eMail": "#1e90ff", "Misc": "#e9967a", "C2": "#9e9e9e",
}
DEFAULT_COLOR = "#cccccc"
SYSTEM_COLORS = {
    "Desktop": "#5f9ea0", "Server": "#ff7f50", "Phone": "#dc143c", "Tablet": "#8a2be2", "TV": "#b8860b",
    "Networking device": "#00008b", "IoT device": "#9932cc", "Other": "#696969", "Attacker Infra": "#000000",
}


# --------------------------------------------------------------------------- #
# Snapshot
# --------------------------------------------------------------------------- #

def collect(conn, case_pk: int, exported_by: str) -> dict:
    """Everything an export needs, read in one consistent snapshot."""
    with read_tx(conn):
        doc, rev = C.build_fox(conn, case_pk)
        row = C.get_case_row(conn, case_pk)
        report = C.get_report(conn, case_pk)
        end_date = json.loads(row["meta"]).get("end_date", "")          # platform only, not in the .fox
    errs = C.integrity_errors(doc)
    if errs:
        raise RuntimeError("export failed integrity check: " + "; ".join(errs))
    return {"doc": doc, "revision": rev, "report": report, "end_date": end_date, "exported_by": exported_by,
            "exported_at": datetime.now(timezone.utc).replace(microsecond=0),
            "case_updated_at": row["updated_at"], "case_updated_by": row["updated_by"]}


def metadata_rows(data: dict) -> list[tuple[str, str]]:
    d = data["doc"]
    upd = datetime.fromtimestamp(data["case_updated_at"], tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    return [("Case ID", d.get("case_id", "")), ("Client", d.get("client", "")),
            ("Engagement start", d.get("start_date", "") or "—"), ("Engagement end", data.get("end_date") or "—"),
            ("Case revision", str(data["revision"])),
            ("Last change", f"{upd} by {data['case_updated_by']}"),
            ("Exported by", data["exported_by"]),
            ("Exported at", data["exported_at"].strftime("%Y-%m-%d %H:%M:%S UTC")),
            ("Time zone", "All date/time values are UTC")]


def section_counts(data: dict) -> list[tuple[str, int]]:
    return [(S.SECTIONS[k].label, len(data["doc"].get(k, []))) for k in SECTION_ORDER]


def report_parts(data: dict) -> list[tuple[str, str]]:
    r = data["report"]
    return [("Executive summary", r.get("executive_summary", "")), ("Context", r.get("context", "")),
            ("Conclusions", r.get("conclusions", "")), ("Lessons learned", r.get("lessons_learned", ""))]


def _systems(doc) -> dict:
    return {s.get("text"): s for s in doc.get("systems", [])}


def visual_events(doc) -> list[dict]:
    return sorted((e for e in doc.get("timeline", []) if e.get("visual") is True and e.get("date_time")),
                  key=lambda e: e["date_time"])


def lateral_graph(doc) -> tuple[list[str], list[dict]]:
    """Aurora's Lateral Movement rules: visual events naming both hosts; '->' = event host to remote."""
    nodes, edges = [], []
    for e in sorted(doc.get("timeline", []), key=lambda e: e.get("date_time") or ""):
        a, b = e.get("event_host"), e.get("event_source_host")
        if not a or not b or e.get("visual") is not True:
            continue
        src, dst = (a, b) if e.get("direction") == "->" else (b, a)
        for h in (src, dst):
            if h not in nodes:
                nodes.append(h)
        edges.append({"from": src, "to": dst, "type": e.get("event_type", ""), "time": e.get("date_time", "")})
    return nodes, edges


def activity_by_hour(doc) -> list[int]:
    hours = [0] * 24
    for e in doc.get("timeline", []):
        if e.get("event_type") != "Engagement" and e.get("date_time"):
            hours[int(e["date_time"][11:13])] += 1
    return hours


def _cell(f: S.Field, v) -> str:
    if v is None or v == "":
        return ""
    if f.kind == "bool":
        return "✓" if v is True else ""
    if f.kind == "auto_ms" and isinstance(v, (int, float)) and not isinstance(v, bool):
        return datetime.fromtimestamp(v / 1000, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    return str(v)


def table_fields(sec: S.Section) -> list[S.Field]:
    return [f for f in sec.fields if f.in_table]


def _weight(f: S.Field) -> float:
    """Relative column width from the grid definition (px, or % of a ~900 px table)."""
    w = f.width or ""
    return float(w[:-2]) if w.endswith("px") else (float(w[:-1]) * 9 if w.endswith("%") else 120.0)


def _header(f: S.Field) -> str:
    """Column title without the emoji some grid labels carry (PDF/LaTeX fonts have no emoji glyphs)."""
    import unicodedata
    label = "".join(ch for ch in f.label if unicodedata.category(ch) != "So" and ord(ch) not in (0xFE0F, 0x200D)).strip()
    if not label:                                   # e.g. the timeline's "⇄" column
        label = {"direction": "Direction"}.get(f.name, f.name.replace("_", " ").capitalize())
    return f"{label} (UTC)" if f.kind in ("datetime", "auto_ms") else label


# --------------------------------------------------------------------------- #
# Charts (PNG, for the PDF)
# --------------------------------------------------------------------------- #

def _plt():
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 8})
    return plt


def _png(fig) -> bytes:
    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=160, bbox_inches="tight")
    _plt().close(fig)
    return buf.getvalue()


def chart_visual_timeline(doc) -> bytes | None:
    evs = visual_events(doc)
    if not evs:
        return None
    plt = _plt()
    import matplotlib.dates as mdates
    types = list(dict.fromkeys(e.get("event_type") or "—" for e in evs))
    fig, ax = plt.subplots(figsize=(10, 0.5 + 0.45 * len(types)))
    for i, t in enumerate(types):
        xs = [datetime.strptime(e["date_time"], "%Y-%m-%d %H:%M:%S") for e in evs if (e.get("event_type") or "—") == t]
        ax.scatter(xs, [i] * len(xs), s=42, color=EVENT_COLORS.get(t, DEFAULT_COLOR), edgecolors="#333333",
                   linewidths=0.5, zorder=3)
    ax.set_yticks(range(len(types)), types)
    ax.set_ylim(-0.7, len(types) - 0.3)
    from datetime import timedelta
    times = [datetime.strptime(e["date_time"], "%Y-%m-%d %H:%M:%S") for e in evs]
    lo, hi = min(times), max(times)
    pad = max((hi - lo) * 0.05, timedelta(hours=2))
    ax.set_xlim(lo - pad, hi + pad)
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%Y-%m-%d\n%H:%M"))
    ax.grid(axis="x", color="#dddddd", zorder=0)
    ax.set_xlabel("UTC")
    ax.spines[["top", "right"]].set_visible(False)
    return _png(fig)


def _circle_layout(n: int) -> list[tuple[float, float]]:
    if n == 1:
        return [(0.0, 0.0)]
    if n == 2:
        return [(-0.8, 0.0), (0.8, 0.0)]
    return [(math.cos(2 * math.pi * i / n - math.pi / 2), math.sin(2 * math.pi * i / n - math.pi / 2)) for i in range(n)]


def chart_lateral(doc) -> bytes | None:
    nodes, edges = lateral_graph(doc)
    if not edges:
        return None
    plt = _plt()
    systems = _systems(doc)
    pos = dict(zip(nodes, _circle_layout(len(nodes))))
    fig, ax = plt.subplots(figsize=(9, 5.2 if len(nodes) > 2 else 3.2))
    seen: dict = {}
    for e in edges:
        k = tuple(sorted((e["from"], e["to"])))
        n = seen.get(k, 0)
        seen[k] = n + 1
        rad = 0.12 + 0.1 * n
        ax.annotate("", xy=pos[e["to"]], xytext=pos[e["from"]],
                    arrowprops=dict(arrowstyle="-|>", color=EVENT_COLORS.get(e["type"], DEFAULT_COLOR), lw=1.8,
                                    shrinkA=14, shrinkB=14, connectionstyle=f"arc3,rad={rad}"))
    for h in nodes:
        x, y = pos[h]
        st = (systems.get(h) or {}).get("system_type") or "Other"
        ax.scatter([x], [y], s=380, color=SYSTEM_COLORS.get(st, "#696969"), zorder=3, edgecolors="white", linewidths=1.5)
        ip = (systems.get(h) or {}).get("ip") or "N/A"
        ax.text(x, y - 0.17, f"{h}\n{ip}", ha="center", va="top", fontsize=7, zorder=4)
    ax.set_xlim(-1.5, 1.5)
    ax.set_ylim(-1.45, 1.3) if len(nodes) > 2 else ax.set_ylim(-0.6, 0.45)
    ax.axis("off")
    used = list(dict.fromkeys(e["type"] for e in edges))
    from matplotlib.lines import Line2D
    ax.legend([Line2D([0], [0], color=EVENT_COLORS.get(t, DEFAULT_COLOR), lw=2) for t in used], used,
              loc="lower right", fontsize=7, frameon=False)
    return _png(fig)


def chart_activity(doc) -> bytes | None:
    hours = activity_by_hour(doc)
    if not any(hours):
        return None
    plt = _plt()
    fig, ax = plt.subplots(figsize=(10, 3))
    ax.bar(range(24), hours, color="#2f6fae", width=0.75, zorder=3)
    ax.set_xticks(range(24), [f"{h:02d}" for h in range(24)])
    ax.set_xlabel("Hour of day (UTC)")
    ax.set_ylabel("Events")
    from matplotlib.ticker import MaxNLocator
    ax.yaxis.set_major_locator(MaxNLocator(integer=True))
    ax.grid(axis="y", color="#dddddd", zorder=0)
    ax.spines[["top", "right"]].set_visible(False)
    return _png(fig)


# --------------------------------------------------------------------------- #
# PDF (ReportLab)
# --------------------------------------------------------------------------- #

def _fonts() -> tuple[str, str]:
    """DejaVu Sans (ships with matplotlib) covers far more Unicode than the PDF base fonts."""
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    try:
        import matplotlib
        d = os.path.join(os.path.dirname(matplotlib.__file__), "mpl-data", "fonts", "ttf")
        if "DejaVu" not in pdfmetrics.getRegisteredFontNames():
            pdfmetrics.registerFont(TTFont("DejaVu", os.path.join(d, "DejaVuSans.ttf")))
            pdfmetrics.registerFont(TTFont("DejaVu-Bold", os.path.join(d, "DejaVuSans-Bold.ttf")))
        return "DejaVu", "DejaVu-Bold"
    except Exception:
        return "Helvetica", "Helvetica-Bold"


def _p(text: str) -> str:
    """Escape case text for a ReportLab Paragraph; keep line breaks."""
    return xml_escape(str(text)).replace("\n", "<br/>")


def build_pdf(data: dict) -> bytes:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import (Image, KeepTogether, LongTable, PageBreak, Paragraph, SimpleDocTemplate, Spacer,
                                    Table, TableStyle)

    font, bold = _fonts()
    st = {
        "title": ParagraphStyle("t", fontName=bold, fontSize=24, leading=30, textColor=colors.HexColor("#14304f")),
        "h1": ParagraphStyle("h1", fontName=bold, fontSize=16, leading=20, spaceBefore=4, spaceAfter=8,
                             textColor=colors.HexColor("#14304f"), keepWithNext=1),
        "h2": ParagraphStyle("h2", fontName=bold, fontSize=12, leading=15, spaceBefore=10, spaceAfter=4, keepWithNext=1),
        "body": ParagraphStyle("b", fontName=font, fontSize=9.5, leading=13),
        "muted": ParagraphStyle("m", fontName=font, fontSize=8.5, leading=11, textColor=colors.HexColor("#5b6675")),
        "cell": ParagraphStyle("c", fontName=font, fontSize=6.8, leading=8.4),
        "hcell": ParagraphStyle("hc", fontName=bold, fontSize=6.8, leading=8.4, textColor=colors.white),
    }
    doc = data["doc"]
    page = landscape(A4)
    buf = io.BytesIO()
    title = f"{doc.get('case_id', '')} - incident report"

    def decorate(canvas, d):
        canvas.saveState()
        canvas.setFont(font, 7.5)
        canvas.setFillColor(colors.HexColor("#5b6675"))
        canvas.drawString(12 * mm, 8 * mm, f"{APP_NAME} · {doc.get('case_id', '')} · revision {data['revision']} · "
                                           f"exported {data['exported_at'].strftime('%Y-%m-%d %H:%M UTC')} by {data['exported_by']}")
        canvas.drawRightString(page[0] - 12 * mm, 8 * mm, f"Page {d.page}")
        canvas.restoreState()

    pdf = SimpleDocTemplate(buf, pagesize=page, leftMargin=12 * mm, rightMargin=12 * mm, topMargin=12 * mm,
                            bottomMargin=14 * mm, title=title, author=data["exported_by"], creator=APP_NAME)
    width = page[0] - 24 * mm
    story: list = []
    # ReportLab cannot split a table row across pages: a cell taller than a page (a record field holds up to
    # 20000 characters) would abort the whole export. Such cells are shortened here; the Excel and .fox exports
    # keep the full text.
    max_cell_h = page[1] - 26 * mm - 60

    def fit_cell(text: str, w: float):
        para = Paragraph(_p(text), st["cell"])
        if len(text) < 200 or para.wrap(w, 1e9)[1] <= max_cell_h:
            return para

        def cut(n: int):
            return Paragraph(_p(f"{text[:n]} … [truncated, {len(text) - n} more characters: see the Excel "
                                f"export]"), st["cell"])
        lo, hi = 0, len(text)
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if cut(mid).wrap(w, 1e9)[1] <= max_cell_h:
                lo = mid
            else:
                hi = mid - 1
        return cut(lo)

    # Cover
    if LOGO_PNG.exists():
        story += [Image(str(LOGO_PNG), width=28 * mm, height=28 * mm, hAlign="LEFT"), Spacer(1, 6 * mm)]
    story += [Paragraph(_p(APP_NAME), st["muted"]), Paragraph(_p(f"Incident report — {doc.get('case_id', '')}"), st["title"]),
              Spacer(1, 2 * mm), Paragraph(_p(doc.get("client", "")), st["h2"]), Spacer(1, 6 * mm)]
    meta = Table([[Paragraph(_p(k), st["body"]), Paragraph(_p(v), st["body"])] for k, v in metadata_rows(data)],
                 colWidths=[45 * mm, width - 45 * mm], hAlign="LEFT")
    meta.setStyle(TableStyle([("LINEBELOW", (0, 0), (-1, -1), 0.25, colors.HexColor("#d5dbe3")),
                              ("FONTNAME", (0, 0), (0, -1), bold), ("VALIGN", (0, 0), (-1, -1), "TOP")]))
    cnt = section_counts(data)
    half = (len(cnt) + 1) // 2
    rows_c = []
    for i in range(half):
        row = [Paragraph(_p(cnt[i][0]), st["muted"]), Paragraph(str(cnt[i][1]), st["muted"])]
        if i + half < len(cnt):
            row += [Paragraph(_p(cnt[i + half][0]), st["muted"]), Paragraph(str(cnt[i + half][1]), st["muted"])]
        rows_c.append(row)
    counts = Table(rows_c, colWidths=[55 * mm, 18 * mm, 55 * mm, 18 * mm], hAlign="LEFT")
    story += [meta, Spacer(1, 6 * mm), Paragraph("Records per section", st["h2"]), counts, PageBreak()]

    # Report page (executive summary, context, conclusions, lessons learned)
    story.append(Paragraph("Report", st["h1"]))
    for label, text in report_parts(data):
        story += [Paragraph(_p(label), st["h2"]),
                  Paragraph(_p(text) if text.strip() else "<i>Not written yet.</i>", st["body"])]
    story.append(PageBreak())

    # Reports
    story.append(Paragraph("Charts", st["h1"]))
    for label, png, note in (
            ("Visual Timeline", chart_visual_timeline(doc), "Timeline events with Visual? ticked, coloured by event type (UTC)."),
            ("Lateral Movement", chart_lateral(doc), "Systems linked by visual events naming both hosts; arrows follow the direction."),
            ("Activity Plot", chart_activity(doc), "Timeline events per UTC hour of the day; Engagement events excluded.")):
        block = [Paragraph(label, st["h2"]), Paragraph(_p(note), st["muted"]), Spacer(1, 2 * mm)]
        if png:
            from reportlab.lib.utils import ImageReader
            iw, ih = ImageReader(io.BytesIO(png)).getSize()
            w = min(width, 250 * mm)
            h = w * ih / iw
            if h > 120 * mm:
                w, h = w * 120 * mm / h, 120 * mm
            block.append(Image(io.BytesIO(png), width=w, height=h, hAlign="LEFT"))
        else:
            block.append(Paragraph("<i>No events to show.</i>", st["muted"]))
        story.append(KeepTogether(block))
    story.append(PageBreak())

    # Sections
    for key in SECTION_ORDER:
        sec = S.SECTIONS[key]
        fields = table_fields(sec)
        recs = doc.get(key, [])
        story += [Paragraph(_p(f"{sec.label} ({len(recs)})"), st["h1"])]
        if not recs:
            story += [Paragraph("<i>No records.</i>", st["muted"]), Spacer(1, 6 * mm)]
            continue
        weights = [max(_weight(f), 7.5 * len(max(_header(f).split(), key=len)) + 10) for f in fields]
        tot = sum(weights)
        col_w = [width * w / tot for w in weights]
        rows = [[Paragraph(_p(_header(f)), st["hcell"]) for f in fields]]
        rows += [[fit_cell(_cell(f, r.get(f.name)), w - 6) for f, w in zip(fields, col_w)] for r in recs]
        t = LongTable(rows, colWidths=col_w, repeatRows=1)
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f3a5f")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f3f6fa")]),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#c9d1dc")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"), ("TOPPADDING", (0, 0), (-1, -1), 2),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2), ("LEFTPADDING", (0, 0), (-1, -1), 3),
            ("RIGHTPADDING", (0, 0), (-1, -1), 3)]))
        story += [t, Spacer(1, 8 * mm)]
    pdf.build(story, onFirstPage=decorate, onLaterPages=decorate)
    return buf.getvalue()


# --------------------------------------------------------------------------- #
# LaTeX (compile with xelatex)
# --------------------------------------------------------------------------- #

_TEX = {"\\": r"\textbackslash{}", "{": r"\{", "}": r"\}", "$": r"\$", "&": r"\&", "#": r"\#", "^": r"\^{}",
        "_": r"\_", "%": r"\%", "~": r"\textasciitilde{}", "<": r"\textless{}", ">": r"\textgreater{}",
        "|": r"\textbar{}", '"': r"\textquotedbl{}", "[": "{[}", "]": "{]}"}


def tex(text) -> str:
    """Escape any text for LaTeX: no command, group or math can be formed from case data."""
    out = []
    for ch in str(text):
        if ch in _TEX:
            out.append(_TEX[ch])
        elif ch == "\n":
            out.append(r"\newline{}")
        elif ord(ch) < 32 or ch == "\x7f":
            out.append(" ")
        else:
            out.append(ch)
    return "".join(out)


def _tex_par(text: str) -> str:
    """Multi-line text: blank lines become paragraphs, single line breaks become \\newline."""
    paras = [p.strip("\n") for p in str(text).replace("\r\n", "\n").split("\n\n")]
    return "\n\n".join(tex(p) for p in paras if p.strip()) or r"\emph{Not written yet.}"


def _tex_color(hexcol: str) -> str:
    h = hexcol.lstrip("#")
    return f"{int(h[0:2], 16)},{int(h[2:4], 16)},{int(h[4:6], 16)}"


_LOGO_TIKZ = r"""\begin{tikzpicture}[x=0.9mm,y=-0.9mm]
  \fill[logobg,rounded corners=6.3mm] (0,0) rectangle (32,32);
  \draw[line width=3.96mm,line cap=round,color=logohandle] (19.8,19.8) -- (25.6,25.6);
  \fill[logoring] (13.5,13.5) circle (8.6);
  \fill[logolens] (13.5,13.5) circle (6.0);
  \draw[white,line width=1.5mm,line cap=round] (9.4,12.4) arc[start angle=196,end angle=250,radius=4.6];
\end{tikzpicture}"""


def build_latex(data: dict) -> bytes:
    doc = data["doc"]
    L: list[str] = []
    a = L.append
    a("% " + tex(f"{APP_NAME} - incident report {doc.get('case_id', '')}"))
    a("% Compile with:  xelatex report.tex. Packages: fontspec, geometry, longtable, booktabs,")
    a("% xcolor, tikz, pgfplots (pgfplots dateplot library), array, hyperref - all part of TeX Live.")
    a(r"\documentclass[10pt]{article}")
    a(r"\usepackage[a4paper,landscape,margin=12mm,bottom=16mm]{geometry}")
    a(r"\usepackage{fontspec}")
    a(r"\usepackage{longtable,booktabs,array}")
    a(r"\usepackage[table]{xcolor}")
    a(r"\usepackage{tikz}")
    a(r"\usepackage{pgfplots}")
    a(r"\usepgfplotslibrary{dateplot}")
    a(r"\pgfplotsset{compat=1.16}")
    a(r"\usepackage{fancyhdr}")
    a(r"\usepackage[hidelinks,pdfusetitle]{hyperref}")
    a(r"\definecolor{logobg}{HTML}{14304F}\definecolor{logohandle}{HTML}{E8B04A}")
    a(r"\definecolor{logoring}{HTML}{EAF2FB}\definecolor{logolens}{HTML}{1F4F80}\definecolor{head}{HTML}{1F3A5F}")
    ev_names = {t: f"ev{chr(97 + i)}" for i, t in enumerate(EVENT_COLORS)}
    sy_names = {t: f"sy{chr(97 + i)}" for i, t in enumerate(SYSTEM_COLORS)}
    for t, c in EVENT_COLORS.items():
        a(rf"\definecolor{{{ev_names[t]}}}{{RGB}}{{{_tex_color(c)}}}")
    for t, c in SYSTEM_COLORS.items():
        a(rf"\definecolor{{{sy_names[t]}}}{{RGB}}{{{_tex_color(c)}}}")
    a(r"\definecolor{evdefault}{RGB}{204,204,204}\definecolor{sydefault}{RGB}{105,105,105}")
    a(r"\setlength{\parindent}{0pt}\setlength{\parskip}{4pt}\renewcommand{\arraystretch}{1.15}")
    a(r"\pagestyle{fancy}\fancyhf{}\renewcommand{\headrulewidth}{0pt}")
    a(r"\fancyfoot[L]{\footnotesize\color{gray}" + tex(
        f"{APP_NAME} · {doc.get('case_id', '')} · revision {data['revision']} · exported "
        f"{data['exported_at'].strftime('%Y-%m-%d %H:%M UTC')} by {data['exported_by']}") + "}")
    a(r"\fancyfoot[R]{\footnotesize\color{gray}Page \thepage}")
    a(r"\title{" + tex(f"Incident report — {doc.get('case_id', '')}") + "}")
    a(r"\author{" + tex(data["exported_by"]) + "}")
    a(r"\date{" + tex(data["exported_at"].strftime("%Y-%m-%d %H:%M UTC")) + "}")
    a(r"\begin{document}")

    ev = lambda t: ev_names.get(t, "evdefault")
    sy = lambda t: sy_names.get(t, "sydefault")

    # Cover
    a(r"\thispagestyle{fancy}")
    a(_LOGO_TIKZ)
    a(r"\par\vspace{4mm}{\color{gray}" + tex(APP_NAME) + r"}\par")
    a(r"{\Huge\bfseries\color{logobg} " + tex(f"Incident report — {doc.get('case_id', '')}") + r"}\par\vspace{2mm}")
    a(r"{\Large " + tex(doc.get("client", "")) + r"}\par\vspace{6mm}")
    a(r"\begin{tabular}{@{}>{\bfseries}p{45mm}p{200mm}@{}}")
    for k, v in metadata_rows(data):
        a(tex(k) + " & " + tex(v) + r" \\")
    a(r"\end{tabular}\par\vspace{6mm}")
    a(r"{\bfseries Records per section}\par\begin{tabular}{@{}p{60mm}r@{}}")
    for k, n in section_counts(data):
        a(tex(k) + f" & {n} " + r"\\")
    a(r"\end{tabular}\newpage")

    # Report page (executive summary, context, conclusions, lessons learned)
    a(r"\section*{Report}")
    for label, text in report_parts(data):
        a(r"\subsection*{" + tex(label) + "}")
        a(_tex_par(text))
    a(r"\newpage")

    # Reports
    a(r"\section*{Charts}")
    a(r"\subsection*{Visual Timeline}")
    evs = visual_events(doc)
    if evs:
        types = list(dict.fromkeys(e.get("event_type") or "—" for e in evs))
        from datetime import timedelta
        times = [datetime.strptime(e["date_time"], "%Y-%m-%d %H:%M:%S") for e in evs]
        pad = max((max(times) - min(times)) * 0.05, timedelta(hours=2))
        lo_tex, hi_tex = ((min(times) - pad).strftime("%Y-%m-%d %H:%M"), (max(times) + pad).strftime("%Y-%m-%d %H:%M"))
        a(r"\begin{tikzpicture}\begin{axis}[date coordinates in=x, width=250mm, height=" +
          f"{max(40, 12 * len(types) + 25)}mm" + r", xticklabel={\year-\month-\day\\\hour:\minute}, "
          r"xticklabel style={align=center,font=\scriptsize}, ytick={" + ",".join(str(i) for i in range(len(types))) +
          r"}, yticklabels={" + ",".join("{" + tex(t) + "}" for t in types) + r"}, ymin=-0.7, ymax=" +
          f"{len(types) - 0.3}" + r", xlabel={UTC}, grid=major, grid style={gray!25}, max space between ticks=60, "
          + f"xmin={{{lo_tex}}}, xmax={{{hi_tex}}}" + "]")
        for i, t in enumerate(types):
            pts = " ".join(f"({e['date_time'][:16]},{i})" for e in evs if (e.get("event_type") or "—") == t)
            a(rf"\addplot[only marks, mark=*, mark size=2.6pt, draw=black!60, fill={ev(t)}] coordinates {{{pts}}};")
        a(r"\end{axis}\end{tikzpicture}")
    else:
        a(r"\emph{No events to show.}")
    a(r"\subsection*{Lateral Movement}")
    nodes, edges = lateral_graph(doc)
    if edges:
        systems = _systems(doc)
        pos = dict(zip(nodes, _circle_layout(len(nodes))))
        a(r"\begin{tikzpicture}[x=80mm,y=55mm]")
        for i, h in enumerate(nodes):
            x, y = pos[h]
            stype = (systems.get(h) or {}).get("system_type") or "Other"
            ip = (systems.get(h) or {}).get("ip") or "N/A"
            a(rf"\node[circle, minimum size=7mm, fill={sy(stype)}, draw=white] (n{i}) at ({x:.3f},{-y:.3f}) {{}};")
            a(rf"\node[below=1mm, align=center, font=\scriptsize] at (n{i}.south) {{{tex(h)}\\{tex(ip)}}};")
        seen: dict = {}
        for e in edges:
            k = tuple(sorted((e["from"], e["to"])))
            n = seen.get(k, 0)
            seen[k] = n + 1
            a(rf"\draw[-latex, line width=1.2pt, color={ev(e['type'])}] (n{nodes.index(e['from'])}) to[bend left={12 + 10 * n}] (n{nodes.index(e['to'])});")
        a(r"\end{tikzpicture}")
        a(r"\par\footnotesize " + ", ".join(rf"\textcolor{{{ev(t)}}}{{\rule{{6mm}}{{1.5pt}}}} {tex(t)}"
                                             for t in dict.fromkeys(e["type"] for e in edges)) + r"\normalsize")
    else:
        a(r"\emph{No events to show.}")
    a(r"\subsection*{Activity Plot}")
    hours = activity_by_hour(doc)
    if any(hours):
        a(r"\begin{tikzpicture}\begin{axis}[ybar, bar width=5mm, width=250mm, height=70mm, xtick={0,...,23}, "
          r"xlabel={Hour of day (UTC)}, ylabel={Events}, ymin=0, grid=major, grid style={gray!25}, "
          + f"ytick distance={max(1, -(-max(hours) // 6))}, " +
          r"xticklabel style={font=\scriptsize}]")
        a(r"\addplot[fill=logolens, draw=none] coordinates {" + " ".join(f"({h},{n})" for h, n in enumerate(hours)) + "};")
        a(r"\end{axis}\end{tikzpicture}")
    else:
        a(r"\emph{No events to show.}")
    a(r"\newpage")

    # Sections
    a(r"\scriptsize")
    for key in SECTION_ORDER:
        sec = S.SECTIONS[key]
        fields = table_fields(sec)
        recs = doc.get(key, [])
        a(r"\section*{" + tex(f"{sec.label} ({len(recs)})") + "}")
        if not recs:
            a(r"\emph{No records.}")
            continue
        weights = [max(_weight(f), 7.5 * len(max(_header(f).split(), key=len)) + 10) for f in fields]
        tot = sum(weights)
        usable = 262.0 - 4.6 * len(fields)          # text width minus the column padding (2 x \tabcolsep)
        spec = "".join(f">{{\\raggedright\\arraybackslash}}p{{{max(6.0, usable * w / tot):.1f}mm}}" for w in weights)
        a(r"\rowcolors{2}{white}{gray!8}")
        a(r"\begin{longtable}{@{}" + spec + "@{}}")
        head = " & ".join(r"\color{white}\bfseries " + tex(_header(f)) for f in fields) + r" \\"
        a(r"\rowcolor{head}" + head + r" \endfirsthead")
        a(r"\rowcolor{head}" + head + r" \endhead")
        for r in recs:
            a(" & ".join(tex("yes" if f.kind == "bool" and r.get(f.name) is True else _cell(f, r.get(f.name)))
                         for f in fields) + r" \\")
        a(r"\end{longtable}")
    a(r"\end{document}")
    return ("\n".join(L) + "\n").encode("utf-8")

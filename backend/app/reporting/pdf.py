"""PDF rendering of incident reports.

Deliberately a small, dependency-light Markdown subset renderer rather than a
full converter: headings, paragraphs, bullets, blockquotes and tables are what
the report generator actually emits, and anything more would be unused code
carrying a maintenance cost.

If ReportLab is unavailable the caller gets a clear error and Markdown export
continues to work, rather than the PDF button silently producing nothing.
"""

from __future__ import annotations

import io
import re
from typing import Any

from app.core.errors import SentinelError


class PDFUnavailable(SentinelError):
    code = "PDF_UNAVAILABLE"
    status_code = 503
    message = "PDF rendering is unavailable in this deployment. Markdown export is unaffected."


def _escape(text: str) -> str:
    """Escape for ReportLab's mini-HTML, then restore bold and code spans."""
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    text = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", text)
    text = re.sub(r"`(.+?)`", r'<font face="Courier">\1</font>', text)
    text = re.sub(r"(?<!\*)\*(?!\*)(.+?)(?<!\*)\*(?!\*)", r"<i>\1</i>", text)
    return text


def _is_table_separator(line: str) -> bool:
    stripped = line.strip()
    return bool(stripped) and set(stripped) <= set("|-: ")


def render_pdf(markdown: str, *, title: str = "Incident Report") -> bytes:
    try:
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_LEFT
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import mm
        from reportlab.platypus import (
            PageBreak,
            Paragraph,
            SimpleDocTemplate,
            Spacer,
            Table,
            TableStyle,
        )
    except ImportError as exc:  # pragma: no cover - environment dependent
        raise PDFUnavailable() from exc

    buffer = io.BytesIO()
    document = SimpleDocTemplate(
        buffer, pagesize=A4,
        leftMargin=18 * mm, rightMargin=18 * mm, topMargin=18 * mm, bottomMargin=18 * mm,
        title=title, author="SENTINEL-X",
    )

    base = getSampleStyleSheet()
    styles = {
        "h1": ParagraphStyle("h1", parent=base["Heading1"], fontSize=18, spaceAfter=10,
                             textColor=colors.HexColor("#0f172a")),
        "h2": ParagraphStyle("h2", parent=base["Heading2"], fontSize=13, spaceBefore=14,
                             spaceAfter=6, textColor=colors.HexColor("#1e293b")),
        "h3": ParagraphStyle("h3", parent=base["Heading3"], fontSize=11, spaceBefore=10,
                             spaceAfter=4, textColor=colors.HexColor("#334155")),
        "body": ParagraphStyle("body", parent=base["BodyText"], fontSize=8.5, leading=12,
                               alignment=TA_LEFT),
        "bullet": ParagraphStyle("bullet", parent=base["BodyText"], fontSize=8.5, leading=12,
                                 leftIndent=10, bulletIndent=2),
        "quote": ParagraphStyle("quote", parent=base["BodyText"], fontSize=8.5, leading=12,
                                leftIndent=10, textColor=colors.HexColor("#475569"),
                                backColor=colors.HexColor("#f1f5f9"), borderPadding=5),
        "cell": ParagraphStyle("cell", parent=base["BodyText"], fontSize=7, leading=9),
        "cellhead": ParagraphStyle("cellhead", parent=base["BodyText"], fontSize=7, leading=9,
                                   textColor=colors.white),
    }

    story: list[Any] = []
    lines = markdown.splitlines()
    index = 0

    while index < len(lines):
        line = lines[index]
        stripped = line.strip()

        if not stripped:
            index += 1
            continue

        if stripped.startswith("|") and index + 1 < len(lines) and _is_table_separator(lines[index + 1]):
            rows: list[list[str]] = []
            while index < len(lines) and lines[index].strip().startswith("|"):
                if not _is_table_separator(lines[index]):
                    cells = [c.strip() for c in lines[index].strip().strip("|").split("|")]
                    rows.append(cells)
                index += 1
            if rows:
                story.append(_build_table(rows, styles, Table, TableStyle, colors, Paragraph, document))
                story.append(Spacer(1, 6))
            continue

        if stripped.startswith("---") and set(stripped) <= {"-"}:
            story.append(Spacer(1, 8))
            index += 1
            continue

        if stripped.startswith("### "):
            story.append(Paragraph(_escape(stripped[4:]), styles["h3"]))
        elif stripped.startswith("## "):
            story.append(PageBreak())
            story.append(Paragraph(_escape(stripped[3:]), styles["h2"]))
        elif stripped.startswith("# "):
            story.append(Paragraph(_escape(stripped[2:]), styles["h1"]))
        elif stripped.startswith("> "):
            story.append(Paragraph(_escape(stripped[2:]), styles["quote"]))
            story.append(Spacer(1, 4))
        elif stripped.startswith(("- ", "* ")):
            story.append(Paragraph(_escape(stripped[2:]), styles["bullet"], bulletText="•"))
        elif re.match(r"^\d+\.\s", stripped):
            number, _, rest = stripped.partition(". ")
            story.append(Paragraph(_escape(rest), styles["bullet"], bulletText=f"{number}."))
        else:
            story.append(Paragraph(_escape(stripped), styles["body"]))
        index += 1

    if not story:
        story.append(Paragraph("Empty report.", styles["body"]))

    document.build(story)
    return buffer.getvalue()


def _build_table(rows, styles, Table, TableStyle, colors, Paragraph, document):
    """Lay out a Markdown table, wrapping cells and fitting the page width."""
    column_count = max(len(r) for r in rows)
    normalised = [r + [""] * (column_count - len(r)) for r in rows]

    data = [[Paragraph(_escape(c), styles["cellhead"]) for c in normalised[0]]]
    for row in normalised[1:]:
        data.append([Paragraph(_escape(c), styles["cell"]) for c in row])

    available = document.width
    widths = [available / column_count] * column_count

    table = Table(data, colWidths=widths, repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5e1")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
        ("LEFTPADDING", (0, 0), (-1, -1), 3),
        ("RIGHTPADDING", (0, 0), (-1, -1), 3),
        ("TOPPADDING", (0, 0), (-1, -1), 2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
    ]))
    return table

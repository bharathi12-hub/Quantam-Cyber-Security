"""
Report exporters: JSON, CSV, SARIF 2.1.0, Markdown, and PDF.

Each takes the scan metadata, its findings (list of dicts), and the posture
summary, and returns bytes ready to stream to the client.
"""
from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone

from ..detection.rules import RULES_BY_ID

_SARIF_LEVEL = {"Critical": "error", "High": "error", "Medium": "warning", "Low": "note"}
_FIELDS = [
    "severity", "quantum_threat", "algorithm", "family", "language",
    "file", "line", "column", "cwe", "confidence",
    "pqc_primary", "pqc_standard", "migration_difficulty", "name",
]


class ExporterUnavailable(RuntimeError):
    """An export format's optional dependency is not installed."""

    def __init__(self, fmt: str, package: str) -> None:
        super().__init__(
            f"The {fmt.upper()} exporter needs the '{package}' package, which is not "
            f"installed. Install it with: pip install {package}"
        )
        self.fmt = fmt
        self.package = package


def to_json(scan: dict, findings: list[dict], summary: dict) -> bytes:
    doc = {
        "tool": {"name": "QuantumShield", "version": "0.2.0"},
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scan": scan,
        "summary": summary,
        "findings": findings,
    }
    return json.dumps(doc, indent=2, default=str).encode("utf-8")


def to_csv(scan: dict, findings: list[dict], summary: dict) -> bytes:
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=_FIELDS, extrasaction="ignore")
    writer.writeheader()
    for f in findings:
        writer.writerow(f)
    return buf.getvalue().encode("utf-8")


def to_sarif(scan: dict, findings: list[dict], summary: dict) -> bytes:
    rule_ids = sorted({f["rule_id"] for f in findings if f.get("rule_id")})
    rules = []
    for rid in rule_ids:
        r = RULES_BY_ID.get(rid)
        if not r:
            continue
        rules.append({
            "id": r.id,
            "name": r.name,
            "shortDescription": {"text": r.name},
            "fullDescription": {"text": r.description},
            "helpUri": "https://csrc.nist.gov/projects/post-quantum-cryptography",
            "properties": {
                "security-severity": {"Critical": "9.5", "High": "8.0", "Medium": "5.0", "Low": "3.0"}.get(r.severity, "3.0"),
                "cwe": r.cwe,
                "quantum_threat": r.quantum_threat,
            },
        })

    results = []
    for f in findings:
        results.append({
            "ruleId": f.get("rule_id"),
            "level": _SARIF_LEVEL.get(f.get("severity", "Low"), "note"),
            "message": {"text": f"{f.get('algorithm')}: {f.get('name')}. "
                                f"Migrate to {f.get('pqc_primary')} ({f.get('pqc_standard')})."},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.get("file", "")},
                    "region": {"startLine": max(1, f.get("line", 1)), "startColumn": max(1, f.get("column", 1))},
                }
            }],
            "properties": {
                "severity": f.get("severity"),
                "quantum_threat": f.get("quantum_threat"),
                "pqc_recommendation": f.get("pqc_primary"),
            },
        })

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "QuantumShield",
                "version": "0.2.0",
                "informationUri": "https://example.com/quantumshield",
                "rules": rules,
            }},
            "results": results,
        }],
    }
    return json.dumps(sarif, indent=2).encode("utf-8")


def to_markdown(scan: dict, findings: list[dict], summary: dict) -> bytes:
    sev = summary.get("by_severity", {})
    lines = [
        "# QuantumShield Cryptographic Assessment Report",
        "",
        f"_Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}_",
        "",
        "## Executive Summary",
        "",
        f"- **Risk score:** {summary.get('risk_score')}/100 (grade {summary.get('grade')}, "
        f"threat level {summary.get('threat_level')})",
        f"- **Total findings:** {summary.get('total_findings')}",
        f"- **Quantum-vulnerable:** {summary.get('quantum_vulnerable')} "
        f"({summary.get('quantum_vulnerable_pct')}%)",
        f"- **Quantum readiness:** {summary.get('quantum_readiness')}/100 · "
        f"**Compliance:** {summary.get('compliance_score')}/100",
        f"- Severity: {sev.get('Critical',0)} critical, {sev.get('High',0)} high, "
        f"{sev.get('Medium',0)} medium, {sev.get('Low',0)} low",
        "",
        "## Findings",
        "",
        "| Severity | Algorithm | Location | Quantum | Migrate to |",
        "|---|---|---|---|---|",
    ]
    for f in findings:
        lines.append(
            f"| {f.get('severity')} | {f.get('algorithm')} | "
            f"`{f.get('file')}:{f.get('line')}` | {f.get('quantum_threat')} | "
            f"{f.get('pqc_primary')} |"
        )
    return "\n".join(lines).encode("utf-8")


def to_pdf(scan: dict, findings: list[dict], summary: dict) -> bytes:
    # reportlab is the one heavyweight dependency here, so it is imported lazily
    # and its absence is surfaced as a clear 503 rather than an opaque 500.
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import mm
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        )
    except ImportError as exc:
        raise ExporterUnavailable("pdf", "reportlab") from exc

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, topMargin=18 * mm, bottomMargin=18 * mm)
    styles = getSampleStyleSheet()
    brand = ParagraphStyle("brand", parent=styles["Title"], textColor=colors.HexColor("#4f46e5"))
    elems = []

    elems.append(Paragraph("QuantumShield", brand))
    elems.append(Paragraph("Cryptographic Assessment — Executive Report", styles["Heading2"]))
    elems.append(Paragraph(datetime.now(timezone.utc).strftime("Generated %Y-%m-%d %H:%M UTC"),
                           styles["Normal"]))
    elems.append(Spacer(1, 8 * mm))

    sev = summary.get("by_severity", {})
    kpi = [
        ["Risk score", f"{summary.get('risk_score')}/100 ({summary.get('grade')})"],
        ["Threat level", str(summary.get("threat_level"))],
        ["Total findings", str(summary.get("total_findings"))],
        ["Quantum-vulnerable", f"{summary.get('quantum_vulnerable')} ({summary.get('quantum_vulnerable_pct')}%)"],
        ["Quantum readiness", f"{summary.get('quantum_readiness')}/100"],
        ["Compliance score", f"{summary.get('compliance_score')}/100"],
        ["Severity mix", f"{sev.get('Critical',0)}C / {sev.get('High',0)}H / "
                         f"{sev.get('Medium',0)}M / {sev.get('Low',0)}L"],
    ]
    t = Table(kpi, colWidths=[55 * mm, 110 * mm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#eef2ff")),
        ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#312e81")),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#c7d2fe")),
        ("PADDING", (0, 0), (-1, -1), 6),
    ]))
    elems.append(t)
    elems.append(Spacer(1, 8 * mm))

    elems.append(Paragraph("Priority Findings", styles["Heading3"]))
    rank = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    top = sorted(findings, key=lambda f: (rank.get(f.get("severity"), 9),
                                          0 if f.get("quantum_threat") == "shor" else 1))[:20]
    data = [["Severity", "Algorithm", "Location", "Migrate to"]]
    for f in top:
        data.append([f.get("severity"), f.get("algorithm"),
                     f"{f.get('file')}:{f.get('line')}", f.get("pqc_primary")])
    ft = Table(data, colWidths=[22 * mm, 33 * mm, 70 * mm, 40 * mm])
    ft.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#4f46e5")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#e2e8f0")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
        ("PADDING", (0, 0), (-1, -1), 4),
    ]))
    elems.append(ft)
    elems.append(Spacer(1, 6 * mm))
    elems.append(Paragraph(
        "Recommended migration targets: ML-KEM-768 (FIPS 203) for key establishment, "
        "ML-DSA-65 (FIPS 204) for signatures, SLH-DSA (FIPS 205) for long-lived roots of "
        "trust, AES-256-GCM for symmetric encryption.", styles["Normal"]))

    doc.build(elems)
    return buf.getvalue()


EXPORTERS = {
    "json": (to_json, "application/json", "json"),
    "csv": (to_csv, "text/csv", "csv"),
    "sarif": (to_sarif, "application/sarif+json", "sarif"),
    "md": (to_markdown, "text/markdown", "md"),
    "pdf": (to_pdf, "application/pdf", "pdf"),
}

"""Report export endpoints (JSON / CSV / SARIF / Markdown / PDF)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..core.reporting import exporters
from ..database import get_db
from ..models import Finding, Scan

router = APIRouter(prefix="/reports", tags=["reports"])


def _finding_dict(f: Finding) -> dict:
    return {
        "rule_id": f.rule_id, "name": f.name, "algorithm": f.algorithm, "family": f.family,
        "quantum_threat": f.quantum_threat, "severity": f.severity, "confidence": f.confidence,
        "language": f.language, "file": f.file, "line": f.line, "column": f.column,
        "cwe": f.cwe, "pqc_primary": f.pqc_primary, "pqc_standard": f.pqc_standard,
        "migration_difficulty": f.migration_difficulty,
    }


@router.get("/scan/{scan_id}")
def export_scan(
    scan_id: int,
    format: str = Query("json", pattern="^(json|csv|sarif|md|pdf)$"),
    db: Session = Depends(get_db),
) -> Response:
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    findings = [
        _finding_dict(f)
        for f in db.scalars(select(Finding).where(Finding.scan_id == scan_id).order_by(Finding.id))
    ]
    scan_meta = {
        "id": scan.id, "project_id": scan.project_id, "source_ref": scan.source_ref,
        "files_scanned": scan.files_scanned, "lines_scanned": scan.lines_scanned,
        "total_findings": scan.total_findings, "risk_score": scan.risk_score,
        "grade": scan.grade, "completed_at": scan.completed_at,
    }

    fn, media_type, ext = exporters.EXPORTERS[format]
    try:
        content = fn(scan_meta, findings, scan.summary or {})
    except exporters.ExporterUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    return Response(
        content=content,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="quantumshield-scan-{scan_id}.{ext}"'},
    )

"""Executive dashboard aggregation across the latest scan of each project."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..core.risk import scoring
from ..database import get_db
from ..models import Finding, Project, Scan
from ..schemas import DashboardOut
from ..services import certificate_service

router = APIRouter(tags=["dashboard"])

_SEVERITY_RANK = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}


def _finding_to_dict(f: Finding) -> dict:
    return {
        "severity": f.severity,
        "quantum_threat": f.quantum_threat,
        "family": f.family,
        "algorithm": f.algorithm,
        "language": f.language,
        "pqc_primary": f.pqc_primary,
        "confidence": f.confidence,
    }


@router.get("/dashboard", response_model=DashboardOut)
def dashboard(db: Session = Depends(get_db)) -> DashboardOut:
    # Latest scan id per project
    latest_ids = [
        row[0]
        for row in db.execute(
            select(func.max(Scan.id)).group_by(Scan.project_id)
        ).all()
    ]

    findings: list[Finding] = []
    if latest_ids:
        findings = list(db.scalars(select(Finding).where(Finding.scan_id.in_(latest_ids))))

    posture = scoring.score([_finding_to_dict(f) for f in findings]) if findings else scoring.empty_summary()

    projects_count = db.scalar(select(func.count()).select_from(Project)) or 0
    scans_count = db.scalar(select(func.count()).select_from(Scan)) or 0

    recent_scans = list(db.scalars(select(Scan).order_by(Scan.id.desc()).limit(8)))

    # Top findings: most severe, Shor-broken first, from the latest scans.
    top = sorted(
        findings,
        key=lambda f: (
            _SEVERITY_RANK.get(f.severity, 9),
            0 if f.quantum_threat == "shor" else 1,
            f.file,
            f.line,
        ),
    )[:12]

    return DashboardOut(
        projects=projects_count,
        scans=scans_count,
        posture=posture,
        recent_scans=recent_scans,
        top_findings=top,
        certificates=certificate_service.summary(db),
    )

"""PQC migration roadmap endpoints."""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..core.migration import planner
from ..database import get_db
from ..models import Finding, Scan

router = APIRouter(prefix="/migration", tags=["migration"])


def _latest_scan_id(db: Session) -> Optional[int]:
    scan = db.scalar(select(Scan).order_by(Scan.id.desc()))
    return scan.id if scan else None


@router.get("/plan")
def plan(scan_id: Optional[int] = None, db: Session = Depends(get_db)) -> dict:
    sid = scan_id if scan_id is not None else _latest_scan_id(db)
    if sid is None:
        raise HTTPException(status_code=404, detail="No scans available")
    if db.get(Scan, sid) is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    findings = [
        {
            "rule_id": f.rule_id,
            "severity": f.severity,
            "quantum_threat": f.quantum_threat,
            "file": f.file,
            "pqc_primary": f.pqc_primary,
        }
        for f in db.scalars(select(Finding).where(Finding.scan_id == sid))
    ]
    result = planner.generate_plan(findings)
    result["scan_id"] = sid
    return result

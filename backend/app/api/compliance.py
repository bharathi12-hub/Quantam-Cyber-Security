"""Compliance posture endpoints."""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..core.compliance import engine
from ..database import get_db
from ..models import Finding, Scan

router = APIRouter(prefix="/compliance", tags=["compliance"])


@router.get("/plan")
def compliance_plan(scan_id: Optional[int] = None, db: Session = Depends(get_db)) -> dict:
    if scan_id is None:
        scan = db.scalar(select(Scan).order_by(Scan.id.desc()))
        scan_id = scan.id if scan else None
    if scan_id is None:
        raise HTTPException(status_code=404, detail="No scans available")
    if db.get(Scan, scan_id) is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    findings = [
        {"rule_id": f.rule_id, "severity": f.severity, "quantum_threat": f.quantum_threat}
        for f in db.scalars(select(Finding).where(Finding.scan_id == scan_id))
    ]
    result = engine.compute(findings)
    result["scan_id"] = scan_id
    return result

"""Dependency & SBOM analysis endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import DependencyReport
from ..schemas import DependencyAnalyzeRequest, DependencyReportOut
from ..services import dependency_service

router = APIRouter(prefix="/dependencies", tags=["dependencies"])


@router.get("", response_model=list[DependencyReportOut])
def list_reports(db: Session = Depends(get_db)) -> list[DependencyReport]:
    return list(db.scalars(select(DependencyReport).order_by(DependencyReport.id.desc())))


@router.get("/{report_id}", response_model=DependencyReportOut)
def get_report(report_id: int, db: Session = Depends(get_db)) -> DependencyReport:
    rec = db.get(DependencyReport, report_id)
    if rec is None:
        raise HTTPException(status_code=404, detail="Dependency report not found")
    return rec


@router.get("/{report_id}/sbom")
def download_sbom(report_id: int, db: Session = Depends(get_db)) -> Response:
    rec = db.get(DependencyReport, report_id)
    if rec is None:
        raise HTTPException(status_code=404, detail="Dependency report not found")
    import json

    sbom = rec.report.get("sbom", {})
    return Response(
        content=json.dumps(sbom, indent=2),
        media_type="application/vnd.cyclonedx+json",
        headers={"Content-Disposition": f'attachment; filename="sbom-{report_id}.cdx.json"'},
    )


@router.post("/analyze", response_model=DependencyReportOut, status_code=status.HTTP_201_CREATED)
def analyze(payload: DependencyAnalyzeRequest, db: Session = Depends(get_db)) -> DependencyReport:
    files = {f.path: f.content for f in payload.files}
    if not files:
        raise HTTPException(status_code=400, detail="No manifest files provided")
    return dependency_service.analyze_and_store(db, files, payload.label, payload.project_id)


@router.post("/demo", response_model=DependencyReportOut, status_code=status.HTTP_201_CREATED)
def demo(db: Session = Depends(get_db)) -> DependencyReport:
    rec = dependency_service.seed_demo(db)
    if rec is None:
        rec = db.scalar(select(DependencyReport).order_by(DependencyReport.id.desc()))
    if rec is None:
        raise HTTPException(status_code=400, detail="No sample manifests available")
    return rec


@router.delete("/{report_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_report(report_id: int, db: Session = Depends(get_db)) -> None:
    rec = db.get(DependencyReport, report_id)
    if rec is None:
        raise HTTPException(status_code=404, detail="Dependency report not found")
    db.delete(rec)
    db.commit()

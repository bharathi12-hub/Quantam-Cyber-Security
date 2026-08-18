"""Scan endpoints: trigger scans, list/retrieve them, and query findings."""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, UploadFile, status
from sqlalchemy import case, func, select
from sqlalchemy.orm import Session

from ..config import settings
from ..database import get_db
from ..models import Finding, Scan
from ..schemas import (
    InlineScanRequest,
    MultiFileScanRequest,
    PagedFindings,
    PathScanRequest,
    RepoScanRequest,
    ScanOut,
    ScanSummaryOut,
)
from ..services import scan_service

router = APIRouter(prefix="/scans", tags=["scans"])

# Severity ordering used for "most severe first" sorts.
_SEVERITY_RANK = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
_SEVERITY_CASE = case(
    {"Critical": 0, "High": 1, "Medium": 2, "Low": 3},
    value=Finding.severity,
    else_=4,
)


def _handle(exc: scan_service.ScanError):
    raise HTTPException(status_code=400, detail=str(exc))


# ---------------------------------------------------------------- trigger scans
@router.post("/inline", response_model=ScanOut, status_code=status.HTTP_201_CREATED)
def scan_inline(payload: InlineScanRequest, db: Session = Depends(get_db)) -> Scan:
    try:
        return scan_service.run_inline_scan(
            db, payload.filename, payload.content, payload.project_id, payload.project_name
        )
    except scan_service.ScanError as exc:
        _handle(exc)


@router.post("/path", response_model=ScanOut, status_code=status.HTTP_201_CREATED)
def scan_path_endpoint(payload: PathScanRequest, db: Session = Depends(get_db)) -> Scan:
    try:
        return scan_service.run_path_scan(
            db, payload.path, payload.project_id, payload.project_name
        )
    except scan_service.ScanError as exc:
        _handle(exc)


@router.post("/files", response_model=ScanOut, status_code=status.HTTP_201_CREATED)
def scan_files(payload: MultiFileScanRequest, db: Session = Depends(get_db)) -> Scan:
    files = {f.path: f.content for f in payload.files}
    try:
        return scan_service.run_multifile_scan(
            db, files, payload.project_id, payload.project_name
        )
    except scan_service.ScanError as exc:
        _handle(exc)


@router.post("/upload", response_model=ScanOut, status_code=status.HTTP_201_CREATED)
async def scan_upload(
    files: list[UploadFile],
    project_name: Optional[str] = None,
    db: Session = Depends(get_db),
) -> Scan:
    blobs: dict[str, str] = {}
    for uf in files:
        raw = await uf.read()
        blobs[uf.filename or "unnamed"] = raw.decode("utf-8", errors="replace")
    try:
        return scan_service.run_multifile_scan(db, blobs, None, project_name)
    except scan_service.ScanError as exc:
        _handle(exc)


@router.post("/repository", response_model=ScanOut, status_code=status.HTTP_201_CREATED)
def scan_repository(payload: RepoScanRequest, db: Session = Depends(get_db)) -> Scan:
    """Clone a public Git repository (shallow) and scan it for crypto risk."""
    try:
        return scan_service.run_repository_scan(
            db, payload.url, payload.branch, None, payload.project_name
        )
    except scan_service.ScanError as exc:
        _handle(exc)


@router.post("/demo", response_model=ScanOut, status_code=status.HTTP_201_CREATED)
def scan_demo(db: Session = Depends(get_db)) -> Scan:
    """Convenience: scan the bundled intentionally-vulnerable sample application."""
    try:
        return scan_service.run_path_scan(
            db, settings.samples_path, None, "Demo - Vulnerable App"
        )
    except scan_service.ScanError as exc:
        _handle(exc)


# ------------------------------------------------------------------- read scans
@router.get("", response_model=list[ScanSummaryOut])
def list_scans(
    project_id: Optional[int] = None,
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
) -> list[Scan]:
    stmt = select(Scan).order_by(Scan.id.desc()).limit(limit)
    if project_id is not None:
        stmt = select(Scan).where(Scan.project_id == project_id).order_by(Scan.id.desc()).limit(limit)
    return list(db.scalars(stmt))


@router.get("/{scan_id}", response_model=ScanOut)
def get_scan(scan_id: int, db: Session = Depends(get_db)) -> Scan:
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.get("/{scan_id}/findings", response_model=PagedFindings)
def scan_findings(
    scan_id: int,
    severity: Optional[str] = None,
    quantum_threat: Optional[str] = None,
    language: Optional[str] = None,
    family: Optional[str] = None,
    search: Optional[str] = None,
    sort_by: str = Query("severity", pattern="^(severity|line|file|algorithm|language|family)$"),
    sort_dir: str = Query("asc", pattern="^(asc|desc)$"),
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=200),
    db: Session = Depends(get_db),
) -> PagedFindings:
    if db.get(Scan, scan_id) is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    conditions = [Finding.scan_id == scan_id]
    if severity:
        conditions.append(Finding.severity == severity)
    if quantum_threat:
        conditions.append(Finding.quantum_threat == quantum_threat)
    if language:
        conditions.append(Finding.language == language)
    if family:
        conditions.append(Finding.family == family)
    if search:
        like = f"%{search}%"
        conditions.append(
            Finding.file.ilike(like)
            | Finding.algorithm.ilike(like)
            | Finding.snippet.ilike(like)
            | Finding.name.ilike(like)
        )

    total = db.scalar(select(func.count()).select_from(Finding).where(*conditions)) or 0

    if sort_by == "severity":
        order_col = _SEVERITY_CASE
    else:
        order_col = getattr(Finding, sort_by)
    order_col = order_col.desc() if sort_dir == "desc" else order_col.asc()

    stmt = (
        select(Finding)
        .where(*conditions)
        .order_by(order_col, Finding.id.asc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    )
    items = list(db.scalars(stmt))

    return PagedFindings(total=total, page=page, page_size=page_size, items=items)

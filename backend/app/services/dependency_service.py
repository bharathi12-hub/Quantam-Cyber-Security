"""Dependency analysis orchestration: analyze, persist, seed demo manifests."""
from __future__ import annotations

import os
from typing import Dict, Optional

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..config import settings
from ..core.deps import analyzer
from ..models import DependencyReport


def analyze_and_store(
    db: Session, files: Dict[str, str], label: Optional[str] = None, project_id: Optional[int] = None
) -> DependencyReport:
    report = analyzer.analyze(files)
    record = DependencyReport(
        project_id=project_id,
        label=label or (report["manifests"][0] if report["manifests"] else "manifest"),
        manifests=report["manifests"],
        total_packages=report["total_packages"],
        flagged=report["flagged"],
        risk_score=report["risk_score"],
        grade=report["grade"],
        report=report,
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return record


def _read_manifest_dir(path: str) -> Dict[str, str]:
    files: Dict[str, str] = {}
    if not os.path.isdir(path):
        return files
    for name in os.listdir(path):
        full = os.path.join(path, name)
        if os.path.isfile(full) and analyzer.detect_manifest(full):
            with open(full, "r", encoding="utf-8", errors="replace") as fh:
                files[name] = fh.read()
    return files


def seed_demo(db: Session) -> Optional[DependencyReport]:
    existing = db.scalar(select(func.count()).select_from(DependencyReport)) or 0
    if existing:
        return None
    files = _read_manifest_dir(settings.dep_samples_path)
    if not files:
        return None
    return analyze_and_store(db, files, label="Demo - Application Dependencies")


def summary(db: Session) -> dict:
    latest = db.scalar(select(DependencyReport).order_by(DependencyReport.id.desc()))
    if latest is None:
        return {"total_packages": 0, "flagged": 0, "risk_score": 0, "grade": "A"}
    return {
        "total_packages": latest.total_packages,
        "flagged": latest.flagged,
        "risk_score": latest.risk_score,
        "grade": latest.grade,
    }

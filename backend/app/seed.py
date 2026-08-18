"""
Seed script: ensure the database has demo data on first run.

Usage (from the backend/ directory):
    python -m app.seed

Idempotent: if a scan already exists it does nothing. Scans the bundled
intentionally-vulnerable sample application so the dashboard has real findings.
"""
from __future__ import annotations

import os

from sqlalchemy import func, select

from .config import settings
from .database import SessionLocal, init_db
from .models import Scan
from .services import certificate_service, dependency_service, scan_service


def seed() -> None:
    init_db()
    db = SessionLocal()
    try:
        existing = db.scalar(select(func.count()).select_from(Scan)) or 0
        if existing:
            print(f"[seed] {existing} scan(s) already present - skipping scan seed.")
        elif not os.path.isdir(settings.samples_path):
            print(f"[seed] Samples directory not found: {settings.samples_path}")
        else:
            scan = scan_service.run_path_scan(
                db, settings.samples_path, project_id=None, project_name="Demo - Vulnerable App"
            )
            print(
                f"[seed] Created demo scan #{scan.id}: "
                f"{scan.files_scanned} files, {scan.total_findings} findings, "
                f"risk {scan.risk_score}/{scan.grade}."
            )

        added = certificate_service.seed_demo_certificates(db)
        if added:
            print(f"[seed] Analyzed {added} demo certificate(s).")
        else:
            print("[seed] Certificates already present - skipping cert seed.")

        dep = dependency_service.seed_demo(db)
        if dep:
            print(f"[seed] Analyzed dependencies: {dep.total_packages} packages, "
                  f"{dep.flagged} flagged, risk {dep.risk_score}/{dep.grade}.")
        else:
            print("[seed] Dependency report already present - skipping dep seed.")
    finally:
        db.close()


if __name__ == "__main__":
    seed()

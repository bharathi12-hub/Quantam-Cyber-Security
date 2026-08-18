"""Certificate analysis orchestration: analyze, persist, seed demo certs."""
from __future__ import annotations

from typing import Optional

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..core.certs import analyzer, samples
from ..models import Certificate


def analyze_and_store(
    db: Session, pem: bytes, label: Optional[str] = None, project_id: Optional[int] = None
) -> Certificate:
    report = analyzer.analyze(pem)  # raises analyzer.CertificateError on bad input
    cert = Certificate(
        project_id=project_id,
        label=label or report["subject"],
        subject=report["subject"],
        issuer=report["issuer"],
        serial=report["serial"],
        public_key_algorithm=report["public_key_algorithm"],
        key_size=report["key_size"],
        curve=report["curve"] or "",
        hash_algorithm=report["hash_algorithm"],
        signature_algorithm=report["signature_algorithm"],
        not_before=report["not_before"],
        not_after=report["not_after"],
        days_to_expiry=report["days_to_expiry"],
        is_expired=report["is_expired"],
        expiring_soon=report["expiring_soon"],
        is_self_signed=report["is_self_signed"],
        is_ca=report["is_ca"],
        quantum_vulnerable=report["quantum_vulnerable"],
        pqc_ready=report["pqc_ready"],
        pqc_recommendation=report["pqc_recommendation"],
        risk_score=report["risk_score"],
        grade=report["grade"],
        fingerprint_sha256=report["fingerprint_sha256"],
        report=report,
    )
    db.add(cert)
    db.commit()
    db.refresh(cert)
    return cert


def seed_demo_certificates(db: Session) -> int:
    """Generate + analyze the demo certificate set if none exist. Returns count added."""
    existing = db.scalar(select(func.count()).select_from(Certificate)) or 0
    if existing:
        return 0
    added = 0
    for label, pem in samples.generate():
        analyze_and_store(db, pem, label=label, project_id=None)
        added += 1
    return added


def summary(db: Session) -> dict:
    total = db.scalar(select(func.count()).select_from(Certificate)) or 0
    expired = db.scalar(
        select(func.count()).select_from(Certificate).where(Certificate.is_expired.is_(True))
    ) or 0
    quantum = db.scalar(
        select(func.count()).select_from(Certificate).where(Certificate.quantum_vulnerable.is_(True))
    ) or 0
    expiring = db.scalar(
        select(func.count()).select_from(Certificate).where(Certificate.expiring_soon.is_(True))
    ) or 0
    return {
        "total": total,
        "expired": expired,
        "quantum_vulnerable": quantum,
        "expiring_soon": expiring,
        "pqc_ready": (db.scalar(select(func.count()).select_from(Certificate).where(Certificate.pqc_ready.is_(True))) or 0),
    }

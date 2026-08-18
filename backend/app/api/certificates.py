"""Certificate analysis endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, UploadFile, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..core.certs import analyzer
from ..database import get_db
from ..models import Certificate
from ..schemas import CertAnalyzeRequest, CertificateOut
from ..services import certificate_service

router = APIRouter(prefix="/certificates", tags=["certificates"])


@router.get("", response_model=list[CertificateOut])
def list_certificates(db: Session = Depends(get_db)) -> list[Certificate]:
    return list(db.scalars(select(Certificate).order_by(Certificate.risk_score.desc(), Certificate.id.desc())))


@router.get("/summary")
def certificate_summary(db: Session = Depends(get_db)) -> dict:
    return certificate_service.summary(db)


@router.get("/{cert_id}", response_model=CertificateOut)
def get_certificate(cert_id: int, db: Session = Depends(get_db)) -> Certificate:
    cert = db.get(Certificate, cert_id)
    if cert is None:
        raise HTTPException(status_code=404, detail="Certificate not found")
    return cert


@router.post("/analyze", response_model=CertificateOut, status_code=status.HTTP_201_CREATED)
def analyze_certificate(payload: CertAnalyzeRequest, db: Session = Depends(get_db)) -> Certificate:
    try:
        return certificate_service.analyze_and_store(
            db, payload.pem.encode("utf-8", errors="ignore"), payload.label, payload.project_id
        )
    except analyzer.CertificateError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/upload", response_model=list[CertificateOut], status_code=status.HTTP_201_CREATED)
async def upload_certificates(files: list[UploadFile], db: Session = Depends(get_db)) -> list[Certificate]:
    out: list[Certificate] = []
    errors: list[str] = []
    for uf in files:
        raw = await uf.read()
        try:
            out.append(certificate_service.analyze_and_store(db, raw, uf.filename))
        except analyzer.CertificateError as exc:
            errors.append(f"{uf.filename}: {exc}")
    if not out and errors:
        raise HTTPException(status_code=400, detail="; ".join(errors))
    return out


@router.post("/demo", response_model=list[CertificateOut], status_code=status.HTTP_201_CREATED)
def seed_demo(db: Session = Depends(get_db)) -> list[Certificate]:
    certificate_service.seed_demo_certificates(db)
    return list(db.scalars(select(Certificate).order_by(Certificate.risk_score.desc())))


@router.delete("/{cert_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_certificate(cert_id: int, db: Session = Depends(get_db)) -> None:
    cert = db.get(Certificate, cert_id)
    if cert is None:
        raise HTTPException(status_code=404, detail="Certificate not found")
    db.delete(cert)
    db.commit()

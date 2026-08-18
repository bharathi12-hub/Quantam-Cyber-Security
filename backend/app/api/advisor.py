"""AI Security Advisor endpoints (deterministic, knowledge-based)."""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..core.advisor import assistant
from ..core.risk import scoring
from ..database import get_db
from ..models import Finding, Scan

router = APIRouter(prefix="/advisor", tags=["advisor"])


class AskRequest(BaseModel):
    question: str
    scan_id: Optional[int] = None


class SummarizeRequest(BaseModel):
    scan_id: Optional[int] = None


def _summary_for(db: Session, scan_id: Optional[int]) -> tuple[dict, str]:
    if scan_id is not None:
        scan = db.get(Scan, scan_id)
        if scan is None:
            raise HTTPException(status_code=404, detail="Scan not found")
        return scan.summary or scoring.empty_summary(), f"scan #{scan.id}"
    latest = db.scalar(select(Scan).order_by(Scan.id.desc()))
    if latest is None:
        return scoring.empty_summary(), "your codebase"
    return latest.summary or scoring.empty_summary(), f"scan #{latest.id}"


@router.post("/ask")
def ask(payload: AskRequest, db: Session = Depends(get_db)) -> dict:
    summary, _ = _summary_for(db, payload.scan_id)
    return assistant.answer(payload.question, summary)


@router.post("/summarize")
def summarize(payload: SummarizeRequest, db: Session = Depends(get_db)) -> dict:
    summary, label = _summary_for(db, payload.scan_id)
    return assistant.summarize(summary, label)


@router.get("/explain/{rule_id}")
def explain(rule_id: str, language: Optional[str] = None) -> dict:
    try:
        return assistant.explain_rule(rule_id.upper(), language)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Unknown rule '{rule_id}'")


@router.get("/finding/{finding_id}")
def explain_finding(finding_id: int, db: Session = Depends(get_db)) -> dict:
    finding = db.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    data = {
        "rule_id": finding.rule_id,
        "language": finding.language,
        "file": finding.file,
        "line": finding.line,
        "snippet": finding.snippet,
    }
    try:
        return assistant.explain_finding(data)
    except KeyError:
        raise HTTPException(status_code=404, detail="No advisor entry for this finding")

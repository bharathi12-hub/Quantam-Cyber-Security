"""Metadata endpoints: health, PQC catalog, ruleset & language reference."""
from __future__ import annotations

from fastapi import APIRouter

from ..config import settings
from ..core.detection.languages import SUPPORTED_LANGUAGES
from ..core.detection.rules import all_rules
from ..core.pqc.recommendations import catalog

router = APIRouter(tags=["meta"])


@router.get("/health")
def health() -> dict:
    return {
        "status": "ok",
        "app": settings.app_name,
        "version": settings.app_version,
        "tagline": settings.tagline,
    }


@router.get("/meta/algorithms")
def algorithms() -> dict:
    """The post-quantum / hardened-classical target catalog."""
    return {"algorithms": catalog()}


@router.get("/meta/rules")
def rules() -> dict:
    """The detection ruleset (reference view for the UI)."""
    out = []
    for r in all_rules():
        out.append(
            {
                "id": r.id,
                "name": r.name,
                "algorithm": r.algorithm,
                "family": r.family,
                "quantum_threat": r.quantum_threat,
                "severity": r.severity,
                "cwe": r.cwe,
                "description": r.description,
                "remediation": r.remediation,
                "languages": list(r.languages),
                "confidence": r.confidence,
            }
        )
    return {"count": len(out), "rules": out}


@router.get("/meta/languages")
def languages() -> dict:
    return {"languages": SUPPORTED_LANGUAGES}

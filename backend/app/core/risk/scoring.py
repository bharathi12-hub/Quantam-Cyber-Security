"""
Risk scoring and aggregation.

Turns a flat list of findings into an executive risk posture: a 0-100 risk
score (higher = worse), a letter grade, and breakdowns by severity, quantum
threat, algorithm family, language, and recommended PQC target.
"""
from __future__ import annotations

import math
from collections import Counter
from typing import Dict, Iterable, List

from ..detection.engine import Finding
from ..detection.rules import CLASSICAL, GROVER, SHOR

# Base weight per severity level.
SEVERITY_WEIGHT = {"Critical": 10.0, "High": 6.0, "Medium": 3.0, "Low": 1.0}

# Multiplier reflecting how a quantum adversary changes the picture.
QUANTUM_FACTOR = {SHOR: 1.5, GROVER: 1.1, CLASSICAL: 1.0}

# Saturation constant for the risk curve (larger => more findings needed to saturate).
_SATURATION_K = 25.0


def _grade(score: float) -> str:
    if score < 20:
        return "A"
    if score < 40:
        return "B"
    if score < 60:
        return "C"
    if score < 80:
        return "D"
    return "F"


def _threat_level(score: float) -> str:
    if score >= 80:
        return "Critical"
    if score >= 60:
        return "High"
    if score >= 40:
        return "Elevated"
    if score >= 20:
        return "Guarded"
    return "Low"


def _as_iter(findings: Iterable) -> List[dict]:
    out = []
    for f in findings:
        out.append(f.to_dict() if isinstance(f, Finding) else dict(f))
    return out


def score(findings: Iterable) -> Dict:
    """Compute the aggregate risk posture for a set of findings."""
    items = _as_iter(findings)

    weighted = 0.0
    by_severity: Counter = Counter()
    by_threat: Counter = Counter()
    by_family: Counter = Counter()
    by_algorithm: Counter = Counter()
    by_language: Counter = Counter()
    by_target: Counter = Counter()

    for f in items:
        sev = f.get("severity", "Low")
        threat = f.get("quantum_threat", CLASSICAL)
        weighted += SEVERITY_WEIGHT.get(sev, 1.0) * QUANTUM_FACTOR.get(threat, 1.0)

        by_severity[sev] += 1
        by_threat[threat] += 1
        by_family[f.get("family", "Other")] += 1
        by_algorithm[f.get("algorithm", "Unknown")] += 1
        by_language[f.get("language", "Unknown")] += 1
        if f.get("pqc_primary"):
            by_target[f["pqc_primary"]] += 1

    risk_score = round(100.0 * (1.0 - math.exp(-weighted / _SATURATION_K)))

    shor = by_threat.get(SHOR, 0)
    grover = by_threat.get(GROVER, 0)
    classical = by_threat.get(CLASSICAL, 0)
    total = len(items)

    crit = by_severity.get("Critical", 0)
    high = by_severity.get("High", 0)
    med = by_severity.get("Medium", 0)
    low = by_severity.get("Low", 0)

    # --- Derived enterprise scores (deterministic, from the real breakdowns) ---
    # Quantum readiness: 100 = fully quantum-safe. Falls as Shor/Grover exposure rises.
    quantum_readiness = 100 - min(100, round(100 * (shor + 0.4 * grover) / total)) if total else 100
    # Migration effort index: Shor migrations are the heaviest (new primitives).
    migration_effort = (
        round(100 * (shor * 3 + grover * 1 + classical * 1.5) / (total * 3)) if total else 0
    )
    # Compliance score vs a quantum-safe baseline (penalize by severity).
    compliance_score = max(0, 100 - (crit * 8 + high * 4 + med * 2 + low * 1))
    # Detection confidence: share of high-confidence findings.
    high_conf = sum(1 for f in items if f.get("confidence", "High") == "High")
    confidence = round(100 * high_conf / total) if total else 100

    return {
        "risk_score": risk_score,
        "grade": _grade(risk_score),
        "total_findings": total,
        "quantum_vulnerable": shor,  # Shor-broken: the headline number
        "quantum_weakened": grover,
        "classically_weak": classical,
        "quantum_vulnerable_pct": round(100 * shor / total) if total else 0,
        "quantum_readiness": quantum_readiness,
        "migration_effort": migration_effort,
        "compliance_score": compliance_score,
        "confidence": confidence,
        "threat_level": _threat_level(risk_score),
        "by_severity": {"Critical": crit, "High": high, "Medium": med, "Low": low},
        "by_quantum_threat": {
            "shor": shor,
            "grover": grover,
            "classical": classical,
        },
        "by_family": dict(by_family.most_common()),
        "by_algorithm": dict(by_algorithm.most_common()),
        "by_language": dict(by_language.most_common()),
        "recommended_targets": dict(by_target.most_common()),
    }


def empty_summary() -> Dict:
    """Posture for a project/scan with no findings."""
    return {
        "risk_score": 0,
        "grade": "A",
        "total_findings": 0,
        "quantum_vulnerable": 0,
        "quantum_weakened": 0,
        "classically_weak": 0,
        "quantum_vulnerable_pct": 0,
        "quantum_readiness": 100,
        "migration_effort": 0,
        "compliance_score": 100,
        "confidence": 100,
        "threat_level": "Low",
        "by_severity": {"Critical": 0, "High": 0, "Medium": 0, "Low": 0},
        "by_quantum_threat": {"shor": 0, "grover": 0, "classical": 0},
        "by_family": {},
        "by_algorithm": {},
        "by_language": {},
        "recommended_targets": {},
    }

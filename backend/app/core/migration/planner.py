"""
PQC Migration Planner.

Turns a set of findings into a phased, actionable migration roadmap: which
issues to fix in what order, the target algorithms, estimated engineering
effort, projected risk reduction, a sequential timeline, and a rollback strategy
per phase. Fully deterministic - derived from the real findings.
"""
from __future__ import annotations

import math
from collections import defaultdict
from typing import Dict, Iterable, List

from ..detection.rules import CLASSICAL, GROVER, RULES_BY_ID, SHOR
from ..risk.scoring import QUANTUM_FACTOR, SEVERITY_WEIGHT

# Phase definition: which migration categories belong to each phase, in order.
PHASES = [
    {
        "id": 1,
        "name": "Immediate Remediation",
        "goal": "Eliminate classically-broken cryptography — low effort, high impact.",
        "categories": {"hash-broken", "cipher-broken", "rng-weak", "iv-static",
                       "password-hash", "auth-weak", "secret"},
        "complexity": "Low",
        "compatibility": 95,
        "rollback": "Low risk — swap primitives behind existing interfaces; feature-flag "
        "and revert per component. No wire-format change.",
    },
    {
        "id": 2,
        "name": "Quantum-Safe Key Establishment",
        "goal": "Replace RSA/ECDH key exchange with ML-KEM — first, to defeat "
        "'harvest now, decrypt later'.",
        "categories": {"pk-encryption", "key-exchange"},
        "complexity": "High",
        "compatibility": 70,
        "rollback": "Deploy hybrid (classical + ML-KEM) so peers negotiate down to classical "
        "if needed; roll back by disabling the PQC group. Keep dual stacks during cutover.",
    },
    {
        "id": 3,
        "name": "Quantum-Safe Signatures",
        "goal": "Migrate RSA/ECDSA/EdDSA signatures and certificates to ML-DSA / SLH-DSA.",
        "categories": {"signature"},
        "complexity": "High",
        "compatibility": 65,
        "rollback": "Issue hybrid/dual certificates; verifiers accept either during transition. "
        "Roll back by re-pinning the classical chain.",
    },
    {
        "id": 4,
        "name": "Symmetric & Protocol Hardening",
        "goal": "Raise symmetric margins against Grover (AES-256) and enforce TLS 1.3.",
        "categories": {"cipher-grover", "protocol-weak"},
        "complexity": "Low",
        "compatibility": 90,
        "rollback": "Configuration-only; revert cipher/protocol settings instantly.",
    },
]

# Person-days per finding, by category (before economies of scale).
_EFFORT = {
    "secret": 0.5, "rng-weak": 0.5, "hash-broken": 0.5, "iv-static": 0.5,
    "cipher-grover": 0.5, "password-hash": 1.0, "auth-weak": 1.0, "cipher-broken": 1.0,
    "protocol-weak": 1.0, "pk-encryption": 3.0, "key-exchange": 3.0, "signature": 3.0,
}
_TEAM = 2  # engineers working in parallel
_WORKWEEK = 5  # working days/week


def _category(rule_id: str) -> str | None:
    rule = RULES_BY_ID.get(rule_id)
    return rule.pqc_category if rule else None


def _weight(f: dict) -> float:
    return SEVERITY_WEIGHT.get(f.get("severity", "Low"), 1.0) * QUANTUM_FACTOR.get(
        f.get("quantum_threat", CLASSICAL), 1.0
    )


def _effort_days(cat_counts: Dict[str, int]) -> float:
    total = 0.0
    for cat, n in cat_counts.items():
        base = _EFFORT.get(cat, 1.0)
        total += base * (n ** 0.8)  # diminishing returns at scale
    return round(total * 2) / 2  # nearest 0.5


def generate_plan(findings: Iterable[dict]) -> dict:
    items = list(findings)
    total_weight = sum(_weight(f) for f in items) or 1.0

    # Bucket findings into phases by category.
    phase_findings: Dict[int, List[dict]] = defaultdict(list)
    cat_to_phase = {cat: ph["id"] for ph in PHASES for cat in ph["categories"]}
    for f in items:
        cat = _category(f.get("rule_id", ""))
        pid = cat_to_phase.get(cat)
        if pid:
            phase_findings[pid].append({**f, "_category": cat})

    phases_out = []
    cumulative_days = 0.0
    remaining_weight = total_weight

    for ph in PHASES:
        fs = phase_findings.get(ph["id"], [])
        if not fs:
            continue
        cat_counts: Dict[str, int] = defaultdict(int)
        targets: Dict[str, int] = defaultdict(int)
        files: set = set()
        phase_weight = 0.0
        for f in fs:
            cat_counts[f["_category"]] += 1
            if f.get("pqc_primary"):
                targets[f["pqc_primary"]] += 1
            files.add(f.get("file"))
            phase_weight += _weight(f)

        effort = _effort_days(cat_counts)
        duration_weeks = max(1, math.ceil(effort / (_TEAM * _WORKWEEK)))
        start_week = int(cumulative_days / (_TEAM * _WORKWEEK)) + 1
        cumulative_days += effort
        end_week = start_week + duration_weeks - 1
        risk_reduction = round(100 * phase_weight / total_weight)

        # per-target breakdown
        breakdown = [
            {"target": t, "count": c} for t, c in sorted(targets.items(), key=lambda x: -x[1])
        ]

        phases_out.append({
            "id": ph["id"],
            "name": ph["name"],
            "goal": ph["goal"],
            "complexity": ph["complexity"],
            "compatibility_score": ph["compatibility"],
            "rollback": ph["rollback"],
            "findings": len(fs),
            "affected_files": len(files),
            "effort_days": effort,
            "duration_weeks": duration_weeks,
            "start_week": start_week,
            "end_week": end_week,
            "risk_reduction": risk_reduction,
            "targets": breakdown,
        })

    total_effort = round(cumulative_days * 2) / 2
    total_weeks = phases_out[-1]["end_week"] if phases_out else 0
    total_risk_reduction = sum(p["risk_reduction"] for p in phases_out)

    return {
        "phases": phases_out,
        "total_findings": len(items),
        "total_effort_days": total_effort,
        "estimated_weeks": total_weeks,
        "team_size": _TEAM,
        "total_risk_reduction": min(100, total_risk_reduction),
        "priority_note": "Key establishment (Phase 2) is scheduled early despite its cost: "
        "encrypted data captured today can be decrypted once quantum computers mature "
        "('harvest now, decrypt later').",
    }

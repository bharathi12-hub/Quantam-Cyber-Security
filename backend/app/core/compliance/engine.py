"""Compute per-framework compliance posture from findings."""
from __future__ import annotations

from collections import defaultdict
from typing import Dict, Iterable, List

from ..detection.rules import RULES_BY_ID
from . import mapping

_SEV_RANK = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}


def _worst(a: str, b: str) -> str:
    return a if _SEV_RANK.get(a, 9) <= _SEV_RANK.get(b, 9) else b


# How much of a single control a finding of each severity consumes. A Critical
# finding fails its control outright; lighter severities degrade it.
_CONTROL_PENALTY = {"Critical": 1.0, "High": 0.75, "Medium": 0.4, "Low": 0.15}

# Score thresholds for the reported status.
_PASS_AT = 80
_PARTIAL_AT = 50


def _status(score: int, touched: bool) -> str:
    if not touched or score >= _PASS_AT:
        return "Pass"
    if score >= _PARTIAL_AT:
        return "Partial"
    return "Fail"


def compute(findings: Iterable[dict]) -> dict:
    items = list(findings)

    # (framework, control_id) -> {title, count, worst_severity}
    controls: Dict[tuple, dict] = {}
    # framework -> aggregate
    fw_findings: Dict[str, int] = defaultdict(int)
    fw_worst: Dict[str, str] = {}
    fw_touched: Dict[str, set] = defaultdict(set)

    for f in items:
        rule = RULES_BY_ID.get(f.get("rule_id", ""))
        category = rule.pqc_category if rule else None
        threat = f.get("quantum_threat", "classical")
        severity = f.get("severity", "Low")

        for framework, cid, title in mapping.controls_for(category, threat):
            key = (framework, cid)
            entry = controls.setdefault(key, {"title": title, "count": 0, "severity": severity})
            entry["count"] += 1
            entry["severity"] = _worst(entry["severity"], severity)

            fw_findings[framework] += 1
            fw_worst[framework] = _worst(fw_worst.get(framework, "Low"), severity)
            fw_touched[framework].add(cid)

    frameworks: List[dict] = []
    passed = partial = failed = 0
    for name in mapping.FRAMEWORKS:
        touched = name in fw_findings

        # Posture is the share of this framework's controls left intact. Each
        # impacted control is degraded by its own worst severity, so the score
        # is bounded and comparable across codebases of any size — unlike a raw
        # weighted sum, which saturated to 0 after only three Critical findings.
        universe = mapping.all_controls(name)
        impacted = {
            cid: data["severity"]
            for (fw, cid), data in controls.items()
            if fw == name
        }
        if universe:
            penalty = sum(_CONTROL_PENALTY.get(sev, 0.15) for sev in impacted.values())
            score = max(0, min(100, round(100 * (1 - penalty / len(universe)))))
        else:
            score = 100

        status = _status(score, touched)
        if status == "Pass":
            passed += 1
        elif status == "Partial":
            partial += 1
        else:
            failed += 1

        ctrl_list = [
            {"id": cid, "title": data["title"], "findings": data["count"], "severity": data["severity"]}
            for (fw, cid), data in controls.items()
            if fw == name
        ]
        ctrl_list.sort(key=lambda c: (_SEV_RANK.get(c["severity"], 9), -c["findings"]))

        frameworks.append({
            "name": name,
            "status": status,
            "score": score if touched else 100,
            "findings": fw_findings.get(name, 0),
            "controls_impacted": len(fw_touched.get(name, set())),
            "controls": ctrl_list,
        })

    return {
        "total_findings": len(items),
        "frameworks": frameworks,
        "overall": {"passed": passed, "partial": partial, "failed": failed},
    }

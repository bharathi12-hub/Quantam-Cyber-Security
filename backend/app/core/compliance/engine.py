"""Compute per-framework compliance posture from findings."""
from __future__ import annotations

from collections import defaultdict
from typing import Dict, Iterable, List

from ..detection.rules import RULES_BY_ID
from ..risk.scoring import SEVERITY_WEIGHT
from . import mapping

_SEV_RANK = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}


def _worst(a: str, b: str) -> str:
    return a if _SEV_RANK.get(a, 9) <= _SEV_RANK.get(b, 9) else b


def _status(worst_sev: str | None) -> str:
    if worst_sev in ("Critical", "High"):
        return "Fail"
    if worst_sev in ("Medium", "Low"):
        return "Partial"
    return "Pass"


def compute(findings: Iterable[dict]) -> dict:
    items = list(findings)

    # (framework, control_id) -> {title, count, worst_severity}
    controls: Dict[tuple, dict] = {}
    # framework -> aggregate
    fw_findings: Dict[str, int] = defaultdict(int)
    fw_weight: Dict[str, float] = defaultdict(float)
    fw_worst: Dict[str, str] = {}
    fw_touched: Dict[str, set] = defaultdict(set)

    for f in items:
        rule = RULES_BY_ID.get(f.get("rule_id", ""))
        category = rule.pqc_category if rule else None
        threat = f.get("quantum_threat", "classical")
        severity = f.get("severity", "Low")
        weight = SEVERITY_WEIGHT.get(severity, 1.0)

        for framework, cid, title in mapping.controls_for(category, threat):
            key = (framework, cid)
            entry = controls.setdefault(key, {"title": title, "count": 0, "severity": severity})
            entry["count"] += 1
            entry["severity"] = _worst(entry["severity"], severity)

            fw_findings[framework] += 1
            fw_weight[framework] += weight
            fw_worst[framework] = _worst(fw_worst.get(framework, "Low"), severity)
            fw_touched[framework].add(cid)

    frameworks: List[dict] = []
    passed = partial = failed = 0
    for name in mapping.FRAMEWORKS:
        touched = name in fw_findings
        worst = fw_worst.get(name) if touched else None
        status = _status(worst)
        if status == "Pass":
            passed += 1
        elif status == "Partial":
            partial += 1
        else:
            failed += 1

        weighted = fw_weight.get(name, 0.0)
        score = max(0, round(100 - min(100, weighted * 4)))

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

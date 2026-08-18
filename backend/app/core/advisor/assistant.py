"""
The AI Security Advisor engine.

Deterministic reasoning over the detection ruleset, PQC catalog, and concept
knowledge base. Explains findings/algorithms, generates secure replacement code,
summarizes scans, and answers natural-language-ish questions - all offline.
"""
from __future__ import annotations

from typing import Optional

from ..detection.rules import RULES_BY_ID
from ..pqc.recommendations import recommend
from . import knowledge as kb

# concept term -> migration category (to attach secure code to concept answers)
_CONCEPT_CATEGORY = {
    "rsa": "pk-encryption",
    "ecdsa": "signature",
    "ecdh": "key-exchange",
    "md5": "hash-broken",
    "sha1": "hash-broken",
    "des": "cipher-broken",
    "rc4": "cipher-broken",
}


def _references(rule=None, rec=None) -> list[str]:
    refs = []
    if rule is not None and rule.cwe:
        refs.append(rule.cwe)
    if rec is not None:
        refs.append(f"{rec.primary.standard} - {rec.primary.name}")
    refs.append("NIST PQC: FIPS 203 / 204 / 205")
    return refs


def explain_rule(rule_id: str, language: Optional[str] = None) -> dict:
    rule = RULES_BY_ID.get(rule_id)
    if rule is None:
        raise KeyError(rule_id)
    rec = recommend(rule.pqc_category)
    concept_key = kb.resolve_concept(rule.algorithm) or kb.resolve_concept(rule_id.lower())
    concept = kb.CONCEPTS.get(concept_key) if concept_key else None

    return {
        "rule_id": rule.id,
        "algorithm": rule.algorithm,
        "family": rule.family,
        "severity": rule.severity,
        "quantum_threat": rule.quantum_threat,
        "explanation": concept["body"] if concept else rule.description,
        "why_vulnerable": rule.description,
        "migration": rec.guidance if rec else rule.remediation,
        "target": f"{rec.primary.name} ({rec.primary.standard})" if rec else None,
        "migration_difficulty": rec.migration_difficulty if rec else None,
        "secure_code": kb.secure_code(rule.pqc_category, language),
        "references": _references(rule, rec),
    }


def explain_finding(finding: dict) -> dict:
    """`finding` is a Finding.to_dict()/ORM-derived dict."""
    out = explain_rule(finding["rule_id"], finding.get("language"))
    out.update(
        {
            "file": finding.get("file"),
            "line": finding.get("line"),
            "snippet": finding.get("snippet"),
            "language": finding.get("language"),
        }
    )
    return out


def summarize(summary: dict, project_label: str = "your codebase") -> dict:
    total = summary.get("total_findings", 0)
    if total == 0:
        md = (f"## Executive Summary\n\nNo cryptographic findings were detected in "
              f"{project_label}. Posture grade **A** - continue monitoring as the code evolves.")
        return {"kind": "summary", "answer": md, "references": ["NIST PQC: FIPS 203 / 204 / 205"]}

    sev = summary.get("by_severity", {})
    targets = list(summary.get("recommended_targets", {}).items())[:3]
    algos = list(summary.get("by_algorithm", {}).items())[:3]

    lines = [
        "## Executive Summary",
        "",
        f"QuantumShield analyzed **{project_label}** and identified **{total} cryptographic "
        f"findings**. The overall risk score is **{summary.get('risk_score')}/100 "
        f"(grade {summary.get('grade')})**, threat level **{summary.get('threat_level')}**.",
        "",
        f"- **{summary.get('quantum_vulnerable', 0)}** findings are **quantum-vulnerable** "
        f"(broken by Shor's algorithm) - {summary.get('quantum_vulnerable_pct', 0)}% of the total.",
        f"- Severity: **{sev.get('Critical', 0)} critical**, {sev.get('High', 0)} high, "
        f"{sev.get('Medium', 0)} medium, {sev.get('Low', 0)} low.",
        f"- **Quantum readiness: {summary.get('quantum_readiness', 0)}/100** · "
        f"Compliance: {summary.get('compliance_score', 0)}/100 · "
        f"Migration effort index: {summary.get('migration_effort', 0)}/100.",
    ]
    if algos:
        lines += ["", "### Most common weak algorithms",
                  *[f"- **{name}** x{count}" for name, count in algos]]
    if targets:
        lines += ["", "### Priority migration targets",
                  *[f"- Adopt **{name}** ({count} finding(s))" for name, count in targets]]
    lines += [
        "",
        "### Recommended next steps",
        "1. Remediate critical/quantum-vulnerable public-key crypto first "
        "(key-exchange before signatures - 'harvest now, decrypt later').",
        "2. Deploy PQC in **hybrid mode** (classical + ML-KEM/ML-DSA) to preserve interoperability.",
        "3. Replace classically-broken primitives (MD5/SHA-1/DES/RC4) immediately - these are low effort.",
        "4. Add QuantumShield to CI to prevent regressions.",
    ]
    return {"kind": "summary", "answer": "\n".join(lines),
            "references": ["NIST FIPS 203 / 204 / 205", "CNSA 2.0"]}


def _detect_concept(q: str) -> Optional[str]:
    ql = q.lower()
    # check multi-word synonyms first (longest match wins)
    for syn in sorted(kb._SYNONYMS, key=len, reverse=True):
        if syn in ql:
            return kb._SYNONYMS[syn]
    for key in kb.CONCEPTS:
        if key in ql:
            return key
    return None


def _concept_answer(concept_key: str, language: Optional[str] = None) -> dict:
    c = kb.CONCEPTS[concept_key]
    category = _CONCEPT_CATEGORY.get(concept_key)
    code = kb.secure_code(category, language) if category else None
    md = [f"## {c['title']}", "", c["body"], "", f"**Migrate to:** {c['migrate_to']}"]
    if code:
        md += ["", "### Secure replacement", "```", code, "```"]
    return {"kind": "concept", "concept": concept_key, "answer": "\n".join(md),
            "references": ["NIST PQC: FIPS 203 / 204 / 205"], "secure_code": code}


def answer(question: str, summary: Optional[dict] = None, language: Optional[str] = None) -> dict:
    """Route a free-text question to a deterministic, knowledge-based answer."""
    q = (question or "").strip()
    ql = q.lower()
    if not q:
        return {"kind": "help", "answer": _help_text(), "references": []}

    concept = _detect_concept(ql)

    # Migration / remediation intent
    if any(w in ql for w in ("migrat", "replace", "remediat", "fix", "how do i", "how to")):
        if concept:
            return _concept_answer(concept, language)
        return {"kind": "guidance", "answer": _migration_guidance(summary),
                "references": ["NIST FIPS 203 / 204 / 205"]}

    # Summary / posture intent
    if any(w in ql for w in ("summar", "overview", "posture", "report", "how bad", "risk")):
        if summary:
            return summarize(summary)

    # Priorities / worst issues
    if any(w in ql for w in ("critical", "priorit", "worst", "urgent", "top ")):
        return {"kind": "priorities", "answer": _priorities(summary),
                "references": ["NIST FIPS 203 / 204 / 205"]}

    # Concept explanation
    if concept:
        return _concept_answer(concept, language)

    return {"kind": "help", "answer": _help_text(summary), "references": []}


def _migration_guidance(summary: Optional[dict]) -> str:
    base = [
        "## Migration Guidance",
        "",
        "A pragmatic quantum-safe migration follows four phases:",
        "",
        "1. **Discover** - inventory every cryptographic asset (QuantumShield's scanners do this).",
        "2. **Prioritize** - rank by data lifetime and exposure. Key-exchange for long-lived "
        "secrets first (harvest-now-decrypt-later), then signatures, then symmetric hardening.",
        "3. **Deploy hybrid** - run classical + PQC together (X25519+ML-KEM-768, and ML-DSA "
        "certificates) so a break of either component is survivable and interoperability holds.",
        "4. **Cut over** - once the ecosystem supports it, move to pure PQC and retire legacy crypto.",
        "",
        "**Targets:** ML-KEM-768 (FIPS 203) for key establishment, ML-DSA-65 (FIPS 204) for "
        "signatures, SLH-DSA (FIPS 205) for long-lived roots of trust, AES-256-GCM for symmetric.",
    ]
    if summary and summary.get("recommended_targets"):
        base += ["", "### Your top targets"]
        for name, count in list(summary["recommended_targets"].items())[:4]:
            base.append(f"- **{name}** - {count} finding(s)")
    return "\n".join(base)


def _priorities(summary: Optional[dict]) -> str:
    if not summary or not summary.get("total_findings"):
        return "No scan data is available yet. Run a scan to see prioritized findings."
    sev = summary.get("by_severity", {})
    lines = [
        "## Priority Findings",
        "",
        f"- **{sev.get('Critical', 0)} critical** and **{summary.get('quantum_vulnerable', 0)} "
        f"quantum-vulnerable** findings should be addressed first.",
        f"- Threat level: **{summary.get('threat_level')}** (risk {summary.get('risk_score')}/100).",
        "",
        "Start with public-key cryptography (RSA/ECDSA/ECDH) - it is both the highest severity "
        "and the only category *broken outright* by quantum computers. Classically-broken "
        "primitives (MD5/SHA-1/DES/RC4) are quick wins you can fix immediately.",
    ]
    if summary.get("by_algorithm"):
        lines += ["", "### Weak algorithms detected"]
        for name, count in list(summary["by_algorithm"].items())[:5]:
            lines.append(f"- {name} x{count}")
    return "\n".join(lines)


def _help_text(summary: Optional[dict] = None) -> str:
    lines = [
        "## QuantumShield Security Advisor",
        "",
        "I can help you understand and act on your cryptographic risk. Try asking:",
        "",
        "- *\"Summarize my scan\"* - an executive overview of your posture.",
        "- *\"What is RSA / ML-KEM / Shor's algorithm?\"* - explain an algorithm or standard.",
        "- *\"How do I migrate ECDSA?\"* - concrete migration steps and secure code.",
        "- *\"What are my critical findings?\"* - prioritized remediation.",
    ]
    if summary and summary.get("total_findings"):
        lines += ["", f"_Current posture: {summary['total_findings']} findings, risk "
                  f"{summary.get('risk_score')}/100 ({summary.get('grade')}), "
                  f"{summary.get('quantum_vulnerable', 0)} quantum-vulnerable._"]
    return "\n".join(lines)

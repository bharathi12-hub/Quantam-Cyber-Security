"""
The static crypto-detection engine.

Walks source trees (or in-memory file contents), applies the compiled ruleset
line by line, and emits structured findings with exact file+line locations,
quantum-threat classification, and a resolved PQC migration recommendation.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Dict, Iterable, List, Optional, Tuple

from ..pqc.recommendations import recommend
from . import languages as lang
from .rules import Rule, all_rules


@dataclass
class Finding:
    rule_id: str
    name: str
    algorithm: str
    family: str
    quantum_threat: str
    severity: str
    confidence: str
    language: str
    file: str
    line: int
    column: int
    snippet: str
    cwe: str
    description: str
    remediation: str
    pqc_primary: Optional[str] = None
    pqc_standard: Optional[str] = None
    migration_difficulty: Optional[str] = None
    pqc_guidance: Optional[str] = None
    analysis: str = "regex"  # "regex" | "ast"
    dataflow: str = ""  # optional data-flow trace for taint findings

    def to_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class ScanResult:
    findings: List[Finding] = field(default_factory=list)
    files_scanned: int = 0
    files_with_findings: int = 0
    lines_scanned: int = 0
    language_breakdown: Dict[str, int] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "findings": [f.to_dict() for f in self.findings],
            "files_scanned": self.files_scanned,
            "files_with_findings": self.files_with_findings,
            "lines_scanned": self.lines_scanned,
            "language_breakdown": self.language_breakdown,
            "errors": self.errors,
        }


@lru_cache(maxsize=512)
def _compiled(rule_id: str) -> Tuple[re.Pattern, ...]:
    """Compile (and cache) the patterns for a rule."""
    rule = next(r for r in all_rules() if r.id == rule_id)
    flags = 0 if rule.case_sensitive else re.IGNORECASE
    return tuple(re.compile(p, flags) for p in rule.patterns)


def _rules_for_language(language: str) -> List[Rule]:
    out = []
    for rule in all_rules():
        if rule.languages == ("*",) or language in rule.languages:
            out.append(rule)
    return out


# Languages that use C-style comments (and where '#' is NOT a comment - e.g. the
# C preprocessor '#include <openssl/md5.h>' is a meaningful crypto signal).
_C_FAMILY = {
    "C", "C++", "C#", "Java", "JavaScript", "TypeScript",
    "Go", "Rust", "Swift", "Kotlin", "Jenkins",
}

# Languages whose whole-line comments start with '#'
_HASH_COMMENT = {"Python", "Ruby", "YAML", "Dockerfile"}


def _comment_prefixes(language: str) -> Tuple[str, ...]:
    """Return the prefixes that mark a *whole line* as a comment for a language."""
    if language in _C_FAMILY:
        return ("//", "/*", "*/", "* ")
    if language == "PHP":
        return ("#", "//", "/*", "*/", "* ")
    if language == "Terraform":
        return ("#", "//", "/*", "*/", "* ")
    if language in _HASH_COMMENT:
        return ("#",)
    if language in ("Config", "INI"):
        return ("#", ";")
    if language == "XML":
        return ("<!--",)
    return ()  # Unknown (JSON, etc.): skip nothing, favour recall over precision.


def _is_comment_line(stripped: str, prefixes: Tuple[str, ...]) -> bool:
    return bool(prefixes) and stripped.startswith(prefixes)


def _attach_recommendation(finding: Finding, rule: Rule) -> None:
    rec = recommend(rule.pqc_category)
    if rec is None:
        return
    finding.pqc_primary = rec.primary.name
    finding.pqc_standard = rec.primary.standard
    finding.migration_difficulty = rec.migration_difficulty
    finding.pqc_guidance = rec.guidance


def scan_text(display_path: str, content: str, language: Optional[str] = None) -> List[Finding]:
    """Scan a single file's text content and return findings."""
    language = language or lang.detect_language(display_path) or "Unknown"

    # Python gets precise AST analysis (with taint tracking); fall back to regex
    # only if the file does not parse (syntax errors, Python 2, partial snippets).
    if language == "Python":
        try:
            from . import ast_analyzer

            return ast_analyzer.analyze_python(display_path, content, language)
        except SyntaxError:
            pass

    rules = _rules_for_language(language)
    prefixes = _comment_prefixes(language)
    findings: List[Finding] = []
    # (rule_id, line_no) already recorded -> avoid duplicate rule hits per line
    seen: set = set()

    lines = content.splitlines()
    for lineno, text in enumerate(lines, start=1):
        stripped = text.strip()
        if not stripped or _is_comment_line(stripped, prefixes):
            continue
        for rule in rules:
            key = (rule.id, lineno)
            if key in seen:
                continue
            for pattern in _compiled(rule.id):
                m = pattern.search(text)
                if m:
                    snippet = text.strip()
                    if len(snippet) > 200:
                        snippet = snippet[:197] + "..."
                    finding = Finding(
                        rule_id=rule.id,
                        name=rule.name,
                        algorithm=rule.algorithm,
                        family=rule.family,
                        quantum_threat=rule.quantum_threat,
                        severity=rule.severity,
                        confidence=rule.confidence,
                        language=language,
                        file=display_path,
                        line=lineno,
                        column=m.start() + 1,
                        snippet=snippet,
                        cwe=rule.cwe,
                        description=rule.description,
                        remediation=rule.remediation,
                    )
                    _attach_recommendation(finding, rule)
                    findings.append(finding)
                    seen.add(key)
                    break  # one hit per rule per line is enough
    return findings


def scan_sources(files: Dict[str, str]) -> ScanResult:
    """Scan a mapping of {display_path: content}. Used for uploads / pasted code."""
    result = ScanResult()
    for path, content in files.items():
        language = lang.detect_language(path) or "Unknown"
        result.files_scanned += 1
        result.lines_scanned += content.count("\n") + 1
        result.language_breakdown[language] = result.language_breakdown.get(language, 0) + 1
        file_findings = scan_text(path, content, language)
        if file_findings:
            result.files_with_findings += 1
            result.findings.extend(file_findings)
    return result


def scan_path(root: str) -> ScanResult:
    """Recursively scan a directory (or single file) on disk."""
    result = ScanResult()
    if os.path.isfile(root):
        targets = [root]
        base = os.path.dirname(root)
    else:
        targets = []
        base = root
        for dirpath, dirnames, filenames in os.walk(root):
            # prune ignored directories in place
            dirnames[:] = [d for d in dirnames if d not in lang.IGNORED_DIRS]
            for fn in filenames:
                targets.append(os.path.join(dirpath, fn))

    for full in targets:
        if not lang.is_scannable(full):
            continue
        try:
            if os.path.getsize(full) > lang.MAX_FILE_BYTES:
                continue
            with open(full, "r", encoding="utf-8", errors="replace") as fh:
                content = fh.read()
        except OSError as exc:
            result.errors.append(f"{full}: {exc}")
            continue

        rel = os.path.relpath(full, base) if base else full
        rel = rel.replace(os.sep, "/")
        language = lang.detect_language(full) or "Unknown"
        result.files_scanned += 1
        result.lines_scanned += content.count("\n") + 1
        result.language_breakdown[language] = result.language_breakdown.get(language, 0) + 1
        file_findings = scan_text(rel, content, language)
        if file_findings:
            result.files_with_findings += 1
            result.findings.extend(file_findings)

    return result

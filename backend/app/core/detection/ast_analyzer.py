"""
AST-based static analysis for Python.

Unlike regex scanning, this parses the real syntax tree, resolves imports and
aliases, and matches cryptographic API *calls* precisely — eliminating the
false positives regex suffers on comments, strings, and unrelated identifiers.

It also performs light **data-flow taint tracking**: string constants assigned
to secret-looking names are traced to the crypto sinks they flow into, producing
an explainable data-flow finding (assigned at line X → used at line Y).
"""
from __future__ import annotations

import ast
import re
from typing import Dict, List, Optional, Tuple

from .engine import Finding, _attach_recommendation
from .rules import RULES_BY_ID

# Resolved call name (last two dotted components) -> rule id
CALL_RULES: Dict[str, str] = {
    "hashlib.md5": "MD5",
    "hashlib.sha1": "SHA1",
    "hashlib.sha224": "SHA224",
    "RSA.generate": "RSA",
    "rsa.generate_private_key": "RSA",
    "ec.generate_private_key": "ECDSA",
    "dsa.generate_private_key": "DSA",
    "DES.new": "DES",
    "DES3.new": "3DES",
    "ARC4.new": "RC4",
    "Blowfish.new": "BLOWFISH",
    "random.random": "RNG_PY",
    "random.randint": "RNG_PY",
    "random.randrange": "RNG_PY",
    "random.getrandbits": "RNG_PY",
    "random.choice": "RNG_PY",
    "random.shuffle": "RNG_PY",
}

# ssl.PROTOCOL_* attributes that indicate obsolete TLS
_TLS_ATTRS = {"PROTOCOL_TLSv1", "PROTOCOL_TLSv1_1", "PROTOCOL_SSLv3", "PROTOCOL_SSLv23"}

_SECRET_NAME = re.compile(
    r"(secret|passw(or)?d|pwd|api[_-]?key|access[_-]?key|auth[_-]?token|token|"
    r"private[_-]?key|signing[_-]?key|_key$|^key$|\biv\b|nonce|salt)",
    re.IGNORECASE,
)


def _is_pem(v: str) -> bool:
    return "-----BEGIN" in v and "PRIVATE KEY" in v


def _resolve_imports(tree: ast.AST) -> Dict[str, str]:
    """Map local alias -> fully-qualified module/name."""
    table: Dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                table[alias.asname or alias.name.split(".")[0]] = alias.name
        elif isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                table[alias.asname or alias.name] = f"{node.module}.{alias.name}"
    return table


def _dotted(node: ast.AST) -> Optional[List[str]]:
    parts: List[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        parts.reverse()
        return parts
    return None


def _resolve_call(func: ast.AST, imports: Dict[str, str]) -> Optional[List[str]]:
    parts = _dotted(func)
    if not parts:
        return None
    head = parts[0]
    base = imports.get(head)
    if base:
        return base.split(".") + parts[1:]
    return parts


def _match(parts: List[str], node: ast.Call) -> Optional[str]:
    last2 = ".".join(parts[-2:]) if len(parts) >= 2 else parts[-1]
    if last2 in CALL_RULES:
        return CALL_RULES[last2]
    # hashlib.new("md5")
    if last2.endswith(".new") and parts[-1] == "new" and parts[-2] == "hashlib":
        if node.args and isinstance(node.args[0], ast.Constant):
            algo = str(node.args[0].value).lower().replace("-", "")
            return {"md5": "MD5", "sha1": "SHA1", "sha224": "SHA224"}.get(algo)
    return None


def _secret_kind(name: str, value: str) -> bool:
    if len(value) < 6:
        return False
    return _is_pem(value) or bool(_SECRET_NAME.search(name))


def analyze_python(display_path: str, content: str, language: str = "Python") -> List[Finding]:
    """Parse Python source and return findings. Raises SyntaxError on parse failure."""
    tree = ast.parse(content)
    lines = content.splitlines()
    imports = _resolve_imports(tree)
    findings: List[Finding] = []
    seen: set = set()

    def snippet_at(lineno: int) -> str:
        s = lines[lineno - 1].strip() if 0 < lineno <= len(lines) else ""
        return (s[:197] + "...") if len(s) > 200 else s

    def add(rule_id: str, lineno: int, col: int, dataflow: str = "") -> None:
        key = (rule_id, lineno)
        if key in seen:
            # allow upgrading dataflow on an existing secret finding
            return
        rule = RULES_BY_ID[rule_id]
        f = Finding(
            rule_id=rule.id, name=rule.name, algorithm=rule.algorithm, family=rule.family,
            quantum_threat=rule.quantum_threat, severity=rule.severity, confidence=rule.confidence,
            language=language, file=display_path, line=lineno, column=col + 1,
            snippet=snippet_at(lineno), cwe=rule.cwe, description=rule.description,
            remediation=rule.remediation, analysis="ast", dataflow=dataflow,
        )
        _attach_recommendation(f, rule)
        findings.append(f)
        seen.add(key)

    # --- Pass 1: taint sources (hardcoded secret-ish string constants) ---
    tainted: Dict[str, Tuple[int, bool]] = {}  # name -> (lineno, is_pem)
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            for tgt in node.targets:
                if isinstance(tgt, ast.Name) and _secret_kind(tgt.id, node.value.value):
                    tainted[tgt.id] = (node.lineno, _is_pem(node.value.value))

    # --- Pass 2: calls (crypto APIs) + taint uses + attributes ---
    taint_uses: Dict[str, Tuple[str, int]] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            parts = _resolve_call(node.func, imports)
            if parts:
                rid = _match(parts, node)
                if rid:
                    add(rid, node.lineno, node.col_offset)
                callname = ".".join(parts[-2:]) if len(parts) >= 2 else parts[-1]
            else:
                callname = "call"
            # taint: does any argument carry a tainted name?
            for arg in list(node.args) + [kw.value for kw in node.keywords]:
                for sub in ast.walk(arg):
                    if isinstance(sub, ast.Name) and sub.id in tainted and sub.id not in taint_uses:
                        taint_uses[sub.id] = (callname, node.lineno)
                    if isinstance(sub, ast.Constant) and isinstance(sub.value, str) and _is_pem(sub.value):
                        add("PRIVKEY", node.lineno, node.col_offset)
        elif isinstance(node, ast.Attribute):
            if node.attr == "MODE_ECB":
                add("AES_ECB", node.lineno, node.col_offset)
            elif node.attr in _TLS_ATTRS:
                add("TLS_WEAK", node.lineno, node.col_offset)
            elif node.attr in ("md5", "sha1", "sha224"):
                # bare reference like `hashlib.md5` passed as a digestmod argument
                aparts = _resolve_call(node, imports)
                if aparts:
                    key = ".".join(aparts[-2:])
                    if key in CALL_RULES:
                        add(CALL_RULES[key], node.lineno, node.col_offset)

    # --- Emit taint-source findings, with data-flow trace when they reach a sink ---
    for name, (lineno, is_pem) in tainted.items():
        rid = "PRIVKEY" if is_pem else "SECRET"
        dataflow = ""
        if name in taint_uses:
            call, uline = taint_uses[name]
            dataflow = (f"Hardcoded value assigned to `{name}` (line {lineno}) "
                        f"flows into `{call}()` at line {uline}.")
        add(rid, lineno, 0, dataflow=dataflow)

    return findings

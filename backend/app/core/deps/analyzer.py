"""
Dependency manifest analysis + SBOM generation.

Parses common dependency manifests, flags cryptographically-relevant and
deprecated packages using the advisory knowledge base, scores risk, and emits a
CycloneDX 1.5 SBOM.
"""
from __future__ import annotations

import json
import os
import re
import tomllib
import xml.etree.ElementTree as ET
from collections import Counter
from datetime import datetime, timezone
from typing import Dict, List, Optional

from . import knowledge

# filename (lowercased) -> ecosystem
_MANIFESTS = {
    "requirements.txt": "pypi",
    "requirements-dev.txt": "pypi",
    "package.json": "npm",
    "go.mod": "golang",
    "pom.xml": "maven",
    "cargo.toml": "cargo",
    "composer.json": "composer",
    "gemfile": "gem",
}

_PURL_PREFIX = {
    "pypi": "pkg:pypi/",
    "npm": "pkg:npm/",
    "golang": "pkg:golang/",
    "maven": "pkg:maven/",
    "cargo": "pkg:cargo/",
    "composer": "pkg:composer/",
    "gem": "pkg:gem/",
}


def detect_manifest(path: str) -> Optional[str]:
    return _MANIFESTS.get(os.path.basename(path).lower())


# --------------------------------------------------------------------- parsers
def _clean_version(spec: str) -> str:
    return re.sub(r"^[\^~>=<!\s]+", "", (spec or "").strip()).strip('"') or "*"


def _parse_requirements(content: str) -> List[dict]:
    out = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "-", "git+", "http")):
            continue
        m = re.match(r"^([A-Za-z0-9._-]+)\s*(?:\[[^\]]*\])?\s*(?:[=<>!~]=?\s*([0-9A-Za-z.*-]+))?", line)
        if m:
            out.append({"name": m.group(1), "version": m.group(2) or "*", "scope": "runtime"})
    return out


def _parse_package_json(content: str) -> List[dict]:
    data = json.loads(content)
    out = []
    for scope, key in (("runtime", "dependencies"), ("dev", "devDependencies")):
        for name, spec in (data.get(key) or {}).items():
            out.append({"name": name, "version": _clean_version(str(spec)), "scope": scope})
    return out


def _parse_composer_json(content: str) -> List[dict]:
    data = json.loads(content)
    out = []
    for scope, key in (("runtime", "require"), ("dev", "require-dev")):
        for name, spec in (data.get(key) or {}).items():
            if name.lower() in ("php",) or "/" not in name and name.startswith("ext-"):
                continue
            out.append({"name": name, "version": _clean_version(str(spec)), "scope": scope})
    return out


def _parse_go_mod(content: str) -> List[dict]:
    out, in_block = [], False
    for line in content.splitlines():
        line = line.strip()
        if line.startswith("require ("):
            in_block = True
            continue
        if in_block and line == ")":
            in_block = False
            continue
        m = re.match(r"^(?:require\s+)?([\w./-]+)\s+(v[0-9][\w.+-]*)", line)
        if (in_block or line.startswith("require ")) and m:
            out.append({"name": m.group(1), "version": m.group(2), "scope": "runtime"})
    return out


def _parse_cargo_toml(content: str) -> List[dict]:
    data = tomllib.loads(content)
    out = []
    for scope, key in (("runtime", "dependencies"), ("dev", "dev-dependencies"), ("build", "build-dependencies")):
        for name, spec in (data.get(key) or {}).items():
            version = spec if isinstance(spec, str) else (spec.get("version") if isinstance(spec, dict) else "*")
            out.append({"name": name, "version": _clean_version(str(version)), "scope": scope})
    return out


def _parse_pom_xml(content: str) -> List[dict]:
    out = []
    try:
        root = ET.fromstring(content)
    except ET.ParseError:
        return out

    def local(tag: str) -> str:
        return tag.rsplit("}", 1)[-1]

    for dep in root.iter():
        if local(dep.tag) != "dependency":
            continue
        fields = {local(c.tag): (c.text or "").strip() for c in dep}
        gid, aid = fields.get("groupId", ""), fields.get("artifactId", "")
        if aid:
            out.append({
                "name": f"{gid}:{aid}" if gid else aid,
                "version": fields.get("version", "*") or "*",
                "scope": fields.get("scope", "runtime") or "runtime",
            })
    return out


def _parse_gemfile(content: str) -> List[dict]:
    out = []
    for line in content.splitlines():
        m = re.match(r"""\s*gem\s+['"]([^'"]+)['"](?:\s*,\s*['"]([~><=!\s]*[0-9][\w.]*)['"])?""", line)
        if m:
            out.append({"name": m.group(1), "version": _clean_version(m.group(2) or "*"), "scope": "runtime"})
    return out


_PARSERS = {
    "pypi": _parse_requirements,
    "npm": _parse_package_json,
    "golang": _parse_go_mod,
    "maven": _parse_pom_xml,
    "cargo": _parse_cargo_toml,
    "composer": _parse_composer_json,
    "gem": _parse_gemfile,
}


def _purl(ecosystem: str, name: str, version: str) -> str:
    prefix = _PURL_PREFIX.get(ecosystem, "pkg:generic/")
    ver = "" if version in ("*", "") else f"@{version}"
    if ecosystem == "maven" and ":" in name:
        return f"{prefix}{name.replace(':', '/')}{ver}"
    return f"{prefix}{name}{ver}"


def _grade(score: int) -> str:
    if score < 20:
        return "A"
    if score < 40:
        return "B"
    if score < 60:
        return "C"
    if score < 80:
        return "D"
    return "F"


# ---------------------------------------------------------------------- analyze
def analyze(files: Dict[str, str]) -> dict:
    """Analyze one or more manifest files ({path: content})."""
    packages: List[dict] = []
    ecosystems: Counter = Counter()
    manifests: List[str] = []

    for path, content in files.items():
        eco = detect_manifest(path)
        if not eco:
            continue
        manifests.append(os.path.basename(path))
        try:
            parsed = _PARSERS[eco](content)
        except Exception:  # noqa: BLE001 - tolerate malformed manifests
            parsed = []
        for pkg in parsed:
            adv = knowledge.lookup(eco, pkg["name"])
            entry = {
                "name": pkg["name"],
                "version": pkg["version"],
                "ecosystem": eco,
                "scope": pkg["scope"],
                "purl": _purl(eco, pkg["name"], pkg["version"]),
                "is_crypto": adv is not None,
                "advisory": (
                    {
                        "severity": adv.severity,
                        "category": adv.category,
                        "note": adv.note,
                        "recommendation": adv.recommendation,
                    }
                    if adv
                    else None
                ),
            }
            packages.append(entry)
            ecosystems[eco] += 1

    flagged = [p for p in packages if p["advisory"]]
    by_severity = Counter(p["advisory"]["severity"] for p in flagged)
    by_category = Counter(p["advisory"]["category"] for p in flagged)

    weighted = sum(knowledge.severity_weight(p["advisory"]["severity"]) for p in flagged)
    risk_score = min(100, round(weighted / 18.0 * 100))

    return {
        "manifests": manifests,
        "packages": packages,
        "total_packages": len(packages),
        "flagged": len(flagged),
        "by_severity": {
            "High": by_severity.get("High", 0),
            "Medium": by_severity.get("Medium", 0),
            "Low": by_severity.get("Low", 0),
        },
        "by_category": dict(by_category.most_common()),
        "by_ecosystem": dict(ecosystems.most_common()),
        "risk_score": risk_score,
        "grade": _grade(risk_score),
        "sbom": build_sbom(packages),
    }


def build_sbom(packages: List[dict]) -> dict:
    """Emit a CycloneDX 1.5 SBOM for the parsed components."""
    components = []
    for p in packages:
        comp = {
            "type": "library",
            "name": p["name"],
            "version": p["version"],
            "purl": p["purl"],
            "scope": "required" if p["scope"] == "runtime" else "optional",
        }
        props = [{"name": "quantumshield:ecosystem", "value": p["ecosystem"]}]
        if p["advisory"]:
            props.append({"name": "quantumshield:advisory", "value": p["advisory"]["category"]})
            props.append({"name": "quantumshield:severity", "value": p["advisory"]["severity"]})
        comp["properties"] = props
        components.append(comp)

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": [{"vendor": "QuantumShield", "name": "QuantumShield SBOM", "version": "0.2.0"}],
        },
        "components": components,
    }

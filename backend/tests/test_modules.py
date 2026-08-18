"""Tests for the enterprise modules: certs, dependencies, advisor, scoring, reports."""
import builtins

import pytest

from app.core.advisor import assistant
from app.core.certs import analyzer as cert_analyzer
from app.core.certs import samples as cert_samples
from app.core.deps import analyzer as dep_analyzer
from app.core.compliance import engine as compliance_engine
from app.core.detection import engine
from app.core.migration import planner
from app.core.reporting import exporters
from app.core.risk import scoring
from app.core.simulation import simulator


# ------------------------------------------------------------------ certificates
def test_certificate_analysis_flags_short_key_and_quantum():
    certs = {label: pem for label, pem in cert_samples.generate()}
    legacy = cert_analyzer.analyze(certs["legacy-payments.example.com"])
    assert legacy["public_key_algorithm"] == "RSA"
    assert legacy["key_size"] == 1024
    assert legacy["quantum_vulnerable"] is True
    assert any("Short RSA key" in f["title"] for f in legacy["flags"])


def test_certificate_analysis_detects_expiry():
    certs = {label: pem for label, pem in cert_samples.generate()}
    expired = cert_analyzer.analyze(certs["vpn.example.com (expired)"])
    assert expired["is_expired"] is True
    assert any(f["severity"] == "Critical" for f in expired["flags"])


def test_certificate_bad_input_raises():
    import pytest
    with pytest.raises(cert_analyzer.CertificateError):
        cert_analyzer.analyze(b"not a certificate")


# ------------------------------------------------------------------ dependencies
def test_dependency_flags_pycrypto_and_builds_sbom():
    report = dep_analyzer.analyze({
        "requirements.txt": "pycrypto==2.6.1\nrequests==2.31.0\n",
        "package.json": '{"dependencies":{"md5":"^2.3.0","express":"^4.18.0"}}',
    })
    assert report["total_packages"] == 4
    flagged = {p["name"] for p in report["packages"] if p["advisory"]}
    assert "pycrypto" in flagged
    assert "md5" in flagged
    assert report["sbom"]["bomFormat"] == "CycloneDX"
    assert len(report["sbom"]["components"]) == 4


def test_dependency_purl_generation():
    report = dep_analyzer.analyze({"requirements.txt": "flask==2.3.2\n"})
    assert report["packages"][0]["purl"] == "pkg:pypi/flask@2.3.2"


# ------------------------------------------------------------------ advisor
def test_advisor_explains_rule_with_secure_code():
    out = assistant.explain_rule("RSA", "Python")
    assert out["target"].startswith("ML-KEM")
    assert "oqs" in out["secure_code"]  # PQC KEM snippet


def test_advisor_answer_routes_concepts():
    res = assistant.answer("what is ML-KEM?")
    assert res["kind"] == "concept"
    assert "FIPS 203" in res["answer"]


def test_advisor_summarize_uses_real_numbers():
    findings = engine.scan_sources({"a.py": "RSA.generate(2048)\nhashlib.md5(b'x')\n"}).findings
    summary = scoring.score(findings)
    res = assistant.summarize(summary, "test project")
    assert "test project" in res["answer"]
    assert str(summary["total_findings"]) in res["answer"]


# ------------------------------------------------------------------ scoring
def test_scoring_enterprise_metrics_present_and_bounded():
    findings = engine.scan_sources({"a.py": "RSA.generate(2048)\nk=ec.generate_private_key()\n"}).findings
    s = scoring.score(findings)
    for key in ("quantum_readiness", "migration_effort", "compliance_score", "confidence", "threat_level"):
        assert key in s
    assert 0 <= s["quantum_readiness"] <= 100
    assert 0 <= s["compliance_score"] <= 100
    assert s["threat_level"] in {"Critical", "High", "Elevated", "Guarded", "Low"}


# ------------------------------------------------------------------ reporting
def test_sarif_export_is_valid():
    import json
    findings = [f.to_dict() for f in engine.scan_sources({"a.py": "RSA.generate(2048)\n"}).findings]
    summary = scoring.score(findings)
    sarif = json.loads(exporters.to_sarif({"id": 1}, findings, summary))
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"][0]["ruleId"] == "RSA"


def test_pdf_export_produces_pdf_bytes():
    findings = [f.to_dict() for f in engine.scan_sources({"a.py": "RSA.generate(2048)\n"}).findings]
    summary = scoring.score(findings)
    pdf = exporters.to_pdf({"id": 1}, findings, summary)
    assert pdf[:5] == b"%PDF-"


def test_pdf_export_reports_missing_reportlab(monkeypatch):
    """A missing reportlab must surface as ExporterUnavailable, not a bare ImportError."""
    real_import = builtins.__import__

    def blocked(name, *args, **kwargs):
        if name.startswith("reportlab"):
            raise ImportError("No module named 'reportlab'")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", blocked)
    with pytest.raises(exporters.ExporterUnavailable) as excinfo:
        exporters.to_pdf({"id": 1}, [], {})
    assert "reportlab" in str(excinfo.value)
    assert excinfo.value.fmt == "pdf"


# ------------------------------------------------------------------ migration planner
def test_migration_plan_phases_and_effort():
    findings = [
        f.to_dict()
        for f in engine.scan_sources({
            "a.py": "RSA.generate(2048)\nhashlib.md5(b'x')\nk = ec.generate_private_key()\n",
            "b.js": "crypto.createHash('md5')\nMath.random()\n",
        }).findings
    ]
    plan = planner.generate_plan(findings)
    assert plan["total_findings"] == len(findings)
    assert plan["phases"], "expected at least one migration phase"
    # RSA -> key establishment phase (2); ECDSA -> signatures phase (3) must appear
    ids = {p["id"] for p in plan["phases"]}
    assert 1 in ids  # md5/rng quick wins
    assert 2 in ids  # RSA key establishment
    assert plan["total_effort_days"] > 0
    assert 0 <= plan["total_risk_reduction"] <= 100
    # phases are time-ordered
    starts = [p["start_week"] for p in plan["phases"]]
    assert starts == sorted(starts)


# ------------------------------------------------------------------ compliance
def test_compliance_maps_all_frameworks_and_flags_pqc():
    findings = [
        f.to_dict()
        for f in engine.scan_sources({"a.py": "RSA.generate(2048)\nhashlib.md5(b'x')\n"}).findings
    ]
    result = compliance_engine.compute(findings)
    names = {fw["name"] for fw in result["frameworks"]}
    assert "NIST PQC" in names and "PCI DSS" in names and "ISO 27001" in names
    nist_pqc = next(fw for fw in result["frameworks"] if fw["name"] == "NIST PQC")
    # RSA is Shor-broken -> NIST PQC must be impacted and failing
    assert nist_pqc["findings"] > 0
    assert nist_pqc["status"] == "Fail"


def test_compliance_clean_scan_passes():
    result = compliance_engine.compute([])
    assert result["overall"]["failed"] == 0
    assert all(fw["status"] == "Pass" for fw in result["frameworks"])


# ------------------------------------------------------------------ simulation
def test_simulation_computes_size_growth_and_bandwidth():
    findings = [
        f.to_dict()
        for f in engine.scan_sources({
            "a.py": "RSA.generate(2048)\nk = ec.generate_private_key()\n",
        }).findings
    ]
    sim = simulator.compute(findings)
    sig = next(m for m in sim["metrics"] if m["name"] == "Signature size")
    assert sig["after"] > sig["before"]  # ML-DSA signatures are much larger
    assert sim["bandwidth"]["per_handshake_delta_b"] > 0
    assert sim["api_sites_to_update"] >= 1
    assert 0 <= sim["compatibility_risk"] <= 90


def test_compliance_score_is_normalised_not_saturated():
    """A clean repo passes; severity degrades posture gradually, not off a cliff.

    The original formula summed severity weights unbounded and multiplied by 4,
    so three Critical findings pinned every framework to 0 and "Partial" was
    unreachable.
    """
    clean = compliance_engine.compute([])
    assert clean["overall"]["passed"] == len(clean["frameworks"])
    assert all(f["score"] == 100 for f in clean["frameworks"])

    def scores(sev, threat="classical", rule="MD5"):
        d = compliance_engine.compute([{"rule_id": rule, "severity": sev, "quantum_threat": threat}])
        return {f["name"]: f["score"] for f in d["frameworks"] if f["findings"]}

    low, medium, high = scores("Low"), scores("Medium"), scores("High")
    assert low and medium and high
    # Monotonic: heavier severity never scores better on the same control set.
    for name in low:
        assert low[name] >= medium[name] >= high[name]

    # Volume alone must not saturate the score to zero.
    many = compliance_engine.compute(
        [{"rule_id": "MD5", "severity": "Medium", "quantum_threat": "classical"}] * 200
    )
    assert any(f["score"] > 0 for f in many["frameworks"])

    # All three statuses must be reachable.
    statuses = set()
    for sev in ("Low", "Medium", "High", "Critical"):
        for threat, rule in (("classical", "MD5"), ("shor", "RSA")):
            d = compliance_engine.compute(
                [{"rule_id": rule, "severity": sev, "quantum_threat": threat}]
            )
            statuses.update(f["status"] for f in d["frameworks"])
    assert {"Pass", "Partial", "Fail"} <= statuses

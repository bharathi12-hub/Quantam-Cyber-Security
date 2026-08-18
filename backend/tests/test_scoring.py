"""Unit tests for the risk scoring aggregator."""
from app.core.detection import engine
from app.core.risk import scoring


def test_empty_summary_is_grade_a_zero_risk():
    s = scoring.empty_summary()
    assert s["risk_score"] == 0
    assert s["grade"] == "A"
    assert s["total_findings"] == 0


def test_score_ranges_and_grade_for_critical_findings():
    findings = engine.scan_sources(
        {"a.py": "k = RSA.generate(2048)\nj = ec.generate_private_key()\n"}
    ).findings
    s = scoring.score(findings)
    assert 0 <= s["risk_score"] <= 100
    assert s["grade"] in {"A", "B", "C", "D", "F"}
    # Two Shor-broken asymmetric primitives -> non-trivial risk.
    assert s["risk_score"] > 30
    assert s["quantum_vulnerable"] >= 1


def test_breakdowns_sum_to_total():
    findings = engine.scan_sources(
        {
            "a.py": "RSA.generate(2048)\nhashlib.md5(b'x')\n",
            "b.js": "Math.random()\ncrypto.createHash('sha1')\n",
        }
    ).findings
    s = scoring.score(findings)
    total = s["total_findings"]
    assert sum(s["by_severity"].values()) == total
    assert sum(s["by_quantum_threat"].values()) == total
    assert sum(s["by_family"].values()) == total


def test_recommended_targets_populated():
    findings = engine.scan_sources({"a.py": "RSA.generate(2048)\n"}).findings
    s = scoring.score(findings)
    assert "ML-KEM-768" in s["recommended_targets"]

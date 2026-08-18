"""Unit tests for the cryptographic detection engine."""
from app.core.detection import engine
from app.core.detection.rules import SHOR, CLASSICAL


def _algos(findings):
    return {f.algorithm for f in findings}


def _by_line(findings):
    return {(f.rule_id, f.line) for f in findings}


def test_detects_rsa_and_maps_to_ml_kem():
    findings = engine.scan_text("x.py", "key = RSA.generate(2048)\n")
    assert len(findings) == 1
    f = findings[0]
    assert f.algorithm == "RSA"
    assert f.quantum_threat == SHOR
    assert f.severity == "Critical"
    assert f.pqc_primary == "ML-KEM-768"
    assert f.pqc_standard == "FIPS 203"
    assert f.line == 1


def test_detects_md5_hash():
    findings = engine.scan_text("x.py", "import hashlib\nh = hashlib.md5(b'x')\n")
    md5 = [f for f in findings if f.algorithm == "MD5"]
    assert md5 and md5[0].quantum_threat == CLASSICAL
    assert md5[0].pqc_primary.startswith("SHA-256")


def test_ecdsa_maps_to_ml_dsa_signature():
    findings = engine.scan_text("x.go", "k, _ := ecdsa.GenerateKey(elliptic.P256(), r)\n")
    assert any(f.algorithm == "ECDSA" and f.pqc_primary == "ML-DSA-65" for f in findings)


def test_comment_only_line_is_ignored_in_python():
    # A pure comment mentioning MD5 must NOT produce a finding.
    findings = engine.scan_text("x.py", "# we used to call hashlib.md5 here\n")
    assert findings == []


def test_c_preprocessor_include_is_not_a_comment():
    # '#include' in C is meaningful, not a comment -> should be detected.
    findings = engine.scan_text("x.c", "#include <openssl/md5.h>\n")
    assert any(f.algorithm == "MD5" for f in findings)


def test_weak_rng_is_language_scoped():
    js = engine.scan_text("x.js", "const r = Math.random();\n")
    # The same text in a Python file must not trigger the JS rule.
    py = engine.scan_text("x.py", "const r = Math.random();\n")
    assert any(f.rule_id == "RNG_JS" for f in js)
    assert not any(f.rule_id == "RNG_JS" for f in py)


def test_hardcoded_private_key_is_critical():
    pem = "-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----\n"
    findings = engine.scan_text("id_rsa.key", pem)
    assert any(f.rule_id == "PRIVKEY" and f.severity == "Critical" for f in findings)


def test_des_and_ecb_are_independent_findings_on_one_line():
    findings = engine.scan_text("x.py", "c = DES.new(k, DES.MODE_ECB)\n")
    rule_ids = {f.rule_id for f in findings}
    assert "DES" in rule_ids
    assert "AES_ECB" in rule_ids


def test_ast_analysis_detects_call_precisely():
    findings = engine.scan_text("x.py", "import hashlib\nh = hashlib.md5(b'x')\n")
    md5 = [f for f in findings if f.rule_id == "MD5"]
    assert md5 and md5[0].analysis == "ast"


def test_ast_ignores_algorithm_name_in_string_or_comment():
    # Regex would flag 'md5' in the string; AST must not (it's not a call).
    findings = engine.scan_text("x.py", "note = 'we used to use md5 and des here'\n")
    assert findings == []


def test_ast_taint_traces_secret_into_sink():
    src = (
        "import hmac, hashlib\n"
        "SIGNING_KEY = 'hardcoded-secret-value-123'\n"
        "def s(m):\n"
        "    return hmac.new(SIGNING_KEY.encode(), m, hashlib.sha256).hexdigest()\n"
    )
    findings = engine.scan_text("x.py", src)
    secret = [f for f in findings if f.rule_id == "SECRET"]
    assert secret
    assert "flows into" in secret[0].dataflow
    assert secret[0].analysis == "ast"


def test_ast_falls_back_to_regex_on_syntax_error():
    # Not valid Python -> AST raises, regex fallback still finds MD5.
    findings = engine.scan_text("x.py", "import hashlib\nhashlib.md5(  <<< broken\n")
    assert any(f.rule_id == "MD5" for f in findings)
    assert all(f.analysis == "regex" for f in findings)


def test_scan_sources_language_breakdown_and_counts():
    result = engine.scan_sources(
        {
            "a.py": "k = RSA.generate(2048)\n",
            "b.js": "crypto.createHash('md5')\n",
        }
    )
    assert result.files_scanned == 2
    assert result.files_with_findings == 2
    assert result.language_breakdown == {"Python": 1, "JavaScript": 1}
    assert len(result.findings) >= 2

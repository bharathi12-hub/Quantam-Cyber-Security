"""
X.509 certificate analysis.

Parses PEM/DER certificates with the `cryptography` library, extracts the
material fields, and flags weaknesses: expiry, weak signature hashes, short
keys, self-signed, and — the headline for this platform — whether the public
key algorithm is broken by a quantum computer (Shor).
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa

_SEV_WEIGHT = {"Critical": 10.0, "High": 6.0, "Medium": 3.0, "Low": 1.0}
_WEAK_HASHES = {"md5", "sha1"}


class CertificateError(Exception):
    pass


def _load(data: bytes) -> x509.Certificate:
    try:
        return x509.load_pem_x509_certificate(data)
    except Exception:
        try:
            return x509.load_der_x509_certificate(data)
        except Exception as exc:  # noqa: BLE001
            raise CertificateError(f"Not a valid PEM/DER X.509 certificate: {exc}")


def _name_parts(name: x509.Name) -> tuple[str, str]:
    def attr(oid):
        vals = name.get_attributes_for_oid(oid)
        return vals[0].value if vals else ""

    cn = attr(x509.NameOID.COMMON_NAME)
    org = attr(x509.NameOID.ORGANIZATION_NAME)
    return cn, org


def _public_key_info(cert: x509.Certificate) -> dict:
    pk = cert.public_key()
    if isinstance(pk, rsa.RSAPublicKey):
        return {"algorithm": "RSA", "key_size": pk.key_size, "curve": None, "quantum_threat": "shor"}
    if isinstance(pk, ec.EllipticCurvePublicKey):
        return {"algorithm": "ECDSA", "key_size": pk.curve.key_size, "curve": pk.curve.name, "quantum_threat": "shor"}
    if isinstance(pk, dsa.DSAPublicKey):
        return {"algorithm": "DSA", "key_size": pk.key_size, "curve": None, "quantum_threat": "shor"}
    if isinstance(pk, ed25519.Ed25519PublicKey):
        return {"algorithm": "Ed25519", "key_size": 256, "curve": "ed25519", "quantum_threat": "shor"}
    if isinstance(pk, ed448.Ed448PublicKey):
        return {"algorithm": "Ed448", "key_size": 448, "curve": "ed448", "quantum_threat": "shor"}
    return {"algorithm": "Unknown", "key_size": 0, "curve": None, "quantum_threat": "none"}


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


def analyze(data: bytes) -> dict:
    """Analyze a single certificate; returns a structured report dict."""
    cert = _load(data)
    now = datetime.now(timezone.utc)

    not_before = cert.not_valid_before_utc
    not_after = cert.not_valid_after_utc
    days_to_expiry = (not_after - now).days
    is_expired = not_after < now
    not_yet_valid = not_before > now
    expiring_soon = (not is_expired) and days_to_expiry <= 30

    subject_cn, subject_org = _name_parts(cert.subject)
    issuer_cn, issuer_org = _name_parts(cert.issuer)
    is_self_signed = cert.subject == cert.issuer

    hash_alg = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "none"
    sig_alg = cert.signature_algorithm_oid._name

    pk = _public_key_info(cert)

    # SANs
    san: list[str] = []
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        san = ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        pass

    # CA?
    is_ca = False
    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        is_ca = bool(bc.value.ca)
    except x509.ExtensionNotFound:
        pass

    # ---- Flags ----
    flags: list[dict] = []
    if is_expired:
        flags.append({"severity": "Critical", "title": "Certificate expired",
                      "detail": f"Expired {abs(days_to_expiry)} day(s) ago ({not_after.date()})."})
    elif expiring_soon:
        flags.append({"severity": "Medium", "title": "Expiring soon",
                      "detail": f"Expires in {days_to_expiry} day(s)."})
    if not_yet_valid:
        flags.append({"severity": "Medium", "title": "Not yet valid",
                      "detail": f"Valid from {not_before.date()}."})

    if hash_alg in _WEAK_HASHES:
        flags.append({"severity": "High", "title": f"Weak signature hash ({hash_alg.upper()})",
                      "detail": "SHA-1/MD5 signatures are forgeable; browsers reject them."})

    if pk["algorithm"] == "RSA" and pk["key_size"] < 2048:
        flags.append({"severity": "High", "title": f"Short RSA key ({pk['key_size']}-bit)",
                      "detail": "RSA keys below 2048 bits are factorable; use >=3072-bit or migrate to PQC."})

    quantum_vulnerable = pk["quantum_threat"] == "shor"
    if quantum_vulnerable:
        flags.append({"severity": "High", "title": f"Quantum-vulnerable key ({pk['algorithm']})",
                      "detail": "Broken by Shor's algorithm. Plan migration to ML-DSA (FIPS 204) certificates."})

    if is_self_signed and not is_ca:
        flags.append({"severity": "Medium", "title": "Self-signed certificate",
                      "detail": "Not issued by a trusted CA; acceptable only for internal/dev use."})

    # ---- Score ----
    weighted = sum(_SEV_WEIGHT.get(f["severity"], 1.0) for f in flags)
    risk_score = min(100, round(weighted / 26.0 * 100))
    pqc_ready = not quantum_vulnerable

    return {
        "subject": subject_cn or cert.subject.rfc4514_string(),
        "subject_org": subject_org,
        "issuer": issuer_cn or cert.issuer.rfc4514_string(),
        "issuer_org": issuer_org,
        "serial": format(cert.serial_number, "x"),
        "version": cert.version.name,
        "not_before": not_before.isoformat(),
        "not_after": not_after.isoformat(),
        "days_to_expiry": days_to_expiry,
        "is_expired": is_expired,
        "expiring_soon": expiring_soon,
        "signature_algorithm": sig_alg,
        "hash_algorithm": hash_alg,
        "public_key_algorithm": pk["algorithm"],
        "key_size": pk["key_size"],
        "curve": pk["curve"],
        "san": san,
        "is_ca": is_ca,
        "is_self_signed": is_self_signed,
        "quantum_vulnerable": quantum_vulnerable,
        "quantum_threat": pk["quantum_threat"],
        "pqc_ready": pqc_ready,
        "pqc_recommendation": "ML-DSA-65 (FIPS 204)" if quantum_vulnerable else "Already quantum-safe",
        "fingerprint_sha256": cert.fingerprint(hashes.SHA256()).hex(),
        "risk_score": risk_score,
        "grade": _grade(risk_score),
        "flags": flags,
    }

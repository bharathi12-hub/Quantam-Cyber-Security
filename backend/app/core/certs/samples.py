"""
Generate real (self-signed) X.509 certificates for the demo, spanning a range
of security postures so the certificate inventory has meaningful data.

These are generated on the fly with the `cryptography` library — genuine
certificates, not fixtures — so the analyzer parses real material.
"""
from __future__ import annotations

import datetime
from typing import List, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID


def _name(cn: str, org: str) -> x509.Name:
    return x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
        ]
    )


def _build(cn: str, org: str, key, hash_alg, valid_from: datetime.datetime,
           valid_to: datetime.datetime) -> bytes:
    subject = issuer = _name(cn, org)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(valid_from)
        .not_valid_after(valid_to)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    )
    cert = builder.sign(private_key=key, algorithm=hash_alg)
    return cert.public_bytes(serialization.Encoding.PEM)


def generate() -> List[Tuple[str, bytes]]:
    """Return a list of (label, PEM bytes) demo certificates."""
    now = datetime.datetime.now(datetime.timezone.utc)
    day = datetime.timedelta(days=1)
    out: List[Tuple[str, bytes]] = []

    # 1) Legacy: RSA-1024 (short key), still "valid" -> short key + quantum-vulnerable.
    #    (Modern crypto libs refuse to *sign* with SHA-1/MD5; the analyzer still
    #     flags those hashes when they appear in real uploaded certificates.)
    k1 = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    out.append((
        "legacy-payments.example.com",
        _build("legacy-payments.example.com", "Example Payments Ltd", k1,
               hashes.SHA256(), now - 90 * day, now + 275 * day),
    ))

    # 2) Modern classical: RSA-2048 SHA-256, valid -> quantum-vulnerable only
    k2 = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    out.append((
        "api.example.com",
        _build("api.example.com", "Example Corp", k2,
               hashes.SHA256(), now - 30 * day, now + 335 * day),
    ))

    # 3) Expired: RSA-2048 SHA-256 but past not_after
    k3 = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    out.append((
        "vpn.example.com (expired)",
        _build("vpn.example.com", "Example Corp", k3,
               hashes.SHA256(), now - 800 * day, now - 20 * day),
    ))

    # 4) ECDSA P-256 SHA-256, valid -> quantum-vulnerable (ECDLP)
    k4 = ec.generate_private_key(ec.SECP256R1())
    out.append((
        "edge.example.com",
        _build("edge.example.com", "Example Edge Services", k4,
               hashes.SHA256(), now - 10 * day, now + 20 * day),  # expiring soon
    ))

    return out

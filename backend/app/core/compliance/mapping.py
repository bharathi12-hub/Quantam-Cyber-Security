"""
Compliance control mapping.

Maps each detection category (and the quantum-threat class) to the relevant
controls across major security frameworks. This lets QuantumShield translate raw
cryptographic findings into the compliance language auditors use.

Frameworks: NIST PQC (FIPS 203/204/205 + SP 1800-38 + CNSA 2.0), NIST SP 800-53
Rev5, OWASP ASVS 4.0, OWASP Top 10 2021, PCI DSS 4.0, ISO/IEC 27001:2022, SOC 2
(TSC), CIS Controls v8.
"""
from __future__ import annotations

from typing import Dict, List, Tuple

# Ordered list of frameworks we report on.
FRAMEWORKS = [
    "NIST PQC",
    "NIST 800-53",
    "OWASP ASVS",
    "OWASP Top 10",
    "PCI DSS",
    "ISO 27001",
    "SOC 2",
    "CIS Controls",
]

# A control reference = (framework, control_id, title)
Control = Tuple[str, str, str]

# Controls that ANY cryptographic weakness implicates.
_BASE_CRYPTO: List[Control] = [
    ("NIST 800-53", "SC-13", "Cryptographic Protection"),
    ("OWASP ASVS", "V6.2", "Algorithms"),
    ("OWASP Top 10", "A02:2021", "Cryptographic Failures"),
    ("PCI DSS", "4.2.1", "Strong cryptography for transmission"),
    ("ISO 27001", "A.8.24", "Use of cryptography"),
    ("SOC 2", "CC6.1", "Logical access & encryption"),
    ("CIS Controls", "3.11", "Encrypt sensitive data"),
]

# Extra controls when the primitive is broken by a quantum computer (Shor).
_QUANTUM: List[Control] = [
    ("NIST PQC", "FIPS 203/204/205", "Adopt standardized post-quantum algorithms"),
    ("NIST PQC", "SP 1800-38", "Migration to Post-Quantum Cryptography"),
    ("NIST 800-53", "SC-12", "Cryptographic Key Establishment & Management"),
]

# Category-specific controls, keyed by rule.pqc_category.
CATEGORY_CONTROLS: Dict[str, List[Control]] = {
    "pk-encryption": _QUANTUM + [("NIST 800-53", "SC-12", "Key Establishment & Management")],
    "key-exchange": _QUANTUM + [("OWASP ASVS", "V9.1", "Client communication security (TLS)")],
    "signature": _QUANTUM + [
        ("NIST 800-53", "SC-17", "Public Key Infrastructure Certificates"),
        ("ISO 27001", "A.5.33", "Protection of records"),
    ],
    "hash-broken": [
        ("OWASP ASVS", "V6.2", "Algorithms"),
        ("PCI DSS", "4.2.1", "Strong cryptography"),
        ("ISO 27001", "A.8.24", "Use of cryptography"),
    ],
    "cipher-broken": [("PCI DSS", "4.2.1", "Strong cryptography"), ("CIS Controls", "3.10", "Encrypt data in transit")],
    "cipher-grover": [("NIST 800-53", "SC-13", "Cryptographic Protection")],
    "rng-weak": [("OWASP ASVS", "V6.3", "Random values"), ("NIST 800-53", "SC-13", "Cryptographic Protection")],
    "iv-static": [("OWASP ASVS", "V6.2", "Algorithms"), ("PCI DSS", "4.2.1", "Strong cryptography")],
    "password-hash": [
        ("OWASP ASVS", "V2.4", "Credential storage"),
        ("OWASP Top 10", "A02:2021", "Cryptographic Failures"),
        ("PCI DSS", "8.3.1", "Strong authentication factors"),
        ("ISO 27001", "A.8.5", "Secure authentication"),
    ],
    "auth-weak": [
        ("OWASP Top 10", "A07:2021", "Identification & Authentication Failures"),
        ("OWASP ASVS", "V3.5", "Token-based session (JWT)"),
        ("PCI DSS", "8.3.1", "Strong authentication"),
        ("SOC 2", "CC6.1", "Logical access controls"),
    ],
    "secret": [
        ("OWASP ASVS", "V2.10", "Service authentication / secrets"),
        ("PCI DSS", "3.5.1", "Protect cryptographic keys"),
        ("ISO 27001", "A.8.24", "Use of cryptography"),
        ("CIS Controls", "3.11", "Encrypt / protect sensitive data"),
        ("SOC 2", "CC6.1", "Logical access controls"),
    ],
    "protocol-weak": [
        ("OWASP ASVS", "V9.1", "TLS configuration"),
        ("PCI DSS", "4.2.1", "Strong cryptography for transmission"),
        ("CIS Controls", "3.10", "Encrypt data in transit"),
        ("SOC 2", "CC6.6", "Encryption in transit"),
        ("NIST 800-53", "SC-8", "Transmission Confidentiality & Integrity"),
    ],
}


def controls_for(pqc_category: str | None, quantum_threat: str) -> List[Control]:
    """Return the deduplicated control set implicated by a finding."""
    controls: List[Control] = list(_BASE_CRYPTO)
    if pqc_category and pqc_category in CATEGORY_CONTROLS:
        controls += CATEGORY_CONTROLS[pqc_category]
    if quantum_threat == "shor":
        controls += _QUANTUM
    # dedupe preserving order
    seen = set()
    out: List[Control] = []
    for c in controls:
        key = (c[0], c[1])
        if key not in seen:
            seen.add(key)
            out.append(c)
    return out

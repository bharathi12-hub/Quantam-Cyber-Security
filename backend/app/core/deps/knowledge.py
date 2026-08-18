"""
Crypto-relevant dependency intelligence.

A curated advisory knowledge base of packages that are cryptographically
relevant (they ship or wrap crypto) or are known-deprecated/risky. This is
crypto-focused dependency analysis, not a general CVE feed — findings are about
cryptographic posture and post-quantum readiness.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional, Tuple


@dataclass(frozen=True)
class Advisory:
    severity: str  # High | Medium | Low
    category: str  # crypto-library | deprecated | jwt | ssh | password | quantum
    note: str
    recommendation: str


# Keyed by (ecosystem, lowercased package name)
ADVISORIES: Dict[Tuple[str, str], Advisory] = {
    # ---- Python (PyPI) ----
    ("pypi", "pycrypto"): Advisory(
        "High", "deprecated",
        "PyCrypto is unmaintained since 2014 and has known vulnerabilities (e.g. CVE-2013-7459).",
        "Replace with pycryptodome or the cryptography library.",
    ),
    ("pypi", "m2crypto"): Advisory(
        "Medium", "deprecated",
        "M2Crypto is thinly maintained and wraps legacy OpenSSL APIs.",
        "Prefer the cryptography library.",
    ),
    ("pypi", "rsa"): Advisory(
        "Medium", "quantum",
        "python-rsa implements RSA (quantum-vulnerable) in pure Python; has had timing issues.",
        "Plan migration to ML-KEM/ML-DSA; use vetted libraries for interim RSA.",
    ),
    ("pypi", "ecdsa"): Advisory(
        "Medium", "quantum",
        "python-ecdsa is quantum-vulnerable (ECDLP) and not constant-time by default.",
        "Migrate signatures to ML-DSA (FIPS 204).",
    ),
    ("pypi", "paramiko"): Advisory(
        "Medium", "ssh",
        "Paramiko (SSH) may negotiate ssh-rsa/SHA-1 host keys on older versions.",
        "Pin a recent version; disable ssh-rsa, prefer ed25519.",
    ),
    ("pypi", "pyjwt"): Advisory(
        "Medium", "jwt",
        "PyJWT must be used carefully — never accept the 'none' algorithm.",
        "Pin the expected asymmetric algorithm; validate exp/aud/iss.",
    ),
    ("pypi", "pycryptodome"): Advisory(
        "Low", "crypto-library",
        "Active crypto library. Ensure AEAD modes and modern primitives are used.",
        "Keep updated; avoid ECB/DES/MD5 APIs it still exposes.",
    ),
    ("pypi", "cryptography"): Advisory(
        "Low", "crypto-library",
        "Well-maintained crypto library.",
        "Keep updated; adopt hybrid PQC when your stack supports it.",
    ),
    # ---- npm ----
    ("npm", "md5"): Advisory(
        "High", "deprecated",
        "Dedicated MD5 hashing package — MD5 is collision-broken.",
        "Use the built-in crypto module with SHA-256; never hash passwords with MD5.",
    ),
    ("npm", "sha1"): Advisory(
        "High", "deprecated",
        "Dedicated SHA-1 package — SHA-1 is collision-broken.",
        "Use SHA-256 via the built-in crypto module.",
    ),
    ("npm", "crypto-js"): Advisory(
        "Medium", "crypto-library",
        "crypto-js ships weak algorithms (MD5, DES) and is not constant-time.",
        "Prefer the Web Crypto API / Node crypto; never use for password hashing.",
    ),
    ("npm", "jsonwebtoken"): Advisory(
        "Medium", "jwt",
        "jsonwebtoken has a history of algorithm-confusion issues.",
        "Pin algorithms, reject 'none', keep >=9.x.",
    ),
    ("npm", "elliptic"): Advisory(
        "Medium", "quantum",
        "elliptic implements ECC (quantum-vulnerable) and has had nonce-generation CVEs.",
        "Pin a patched version; plan ML-DSA migration.",
    ),
    ("npm", "node-forge"): Advisory(
        "Low", "crypto-library",
        "Pure-JS crypto toolkit; has had prototype-pollution/verification CVEs historically.",
        "Keep >=1.3.0; prefer native crypto where possible.",
    ),
    # ---- Go ----
    ("golang", "github.com/dgrijalva/jwt-go"): Advisory(
        "High", "deprecated",
        "dgrijalva/jwt-go is unmaintained and has CVE-2020-26160 (access control).",
        "Migrate to github.com/golang-jwt/jwt (v5+).",
    ),
    ("golang", "github.com/golang-jwt/jwt"): Advisory(
        "Medium", "jwt",
        "golang-jwt requires careful algorithm handling.",
        "Pin algorithms; reject 'none'; use >=v5.",
    ),
    # ---- Java (Maven) ----
    ("maven", "org.bouncycastle:bcprov-jdk15on"): Advisory(
        "Medium", "crypto-library",
        "bcprov-jdk15on is the legacy classifier with several historical CVEs.",
        "Migrate to bcprov-jdk18on and update.",
    ),
    ("maven", "io.jsonwebtoken:jjwt"): Advisory(
        "Medium", "jwt",
        "JJWT usage must reject 'none' and pin algorithms.",
        "Use jjwt-api/impl >=0.11 and asymmetric signing.",
    ),
    # ---- Rust (Cargo) ----
    ("cargo", "rsa"): Advisory(
        "Medium", "quantum",
        "The rsa crate was affected by the Marvin timing attack (RUSTSEC-2023-0071) and is quantum-vulnerable.",
        "Update; plan ML-KEM/ML-DSA migration.",
    ),
    ("cargo", "md5"): Advisory(
        "High", "deprecated",
        "MD5 crate — MD5 is collision-broken.",
        "Use sha2 crate (SHA-256).",
    ),
    # ---- PHP (Composer) ----
    ("composer", "firebase/php-jwt"): Advisory(
        "Medium", "jwt",
        "firebase/php-jwt must pin algorithms and reject 'none'.",
        "Use >=6.x and asymmetric keys.",
    ),
    # ---- Ruby (Gem) ----
    ("gem", "jwt"): Advisory(
        "Medium", "jwt",
        "ruby-jwt must reject 'none' and pin algorithms.",
        "Verify signatures; pin algorithm.",
    ),
}

_SEV_WEIGHT = {"High": 6.0, "Medium": 3.0, "Low": 0.5}


def lookup(ecosystem: str, name: str) -> Optional[Advisory]:
    return ADVISORIES.get((ecosystem, name.lower()))


def severity_weight(sev: str) -> float:
    return _SEV_WEIGHT.get(sev, 0.0)

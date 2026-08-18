"""
Post-Quantum Cryptography recommendation catalog.

Maps classical, quantum-vulnerable primitives to NIST-standardized
post-quantum replacements (FIPS 203 / 204 / 205) and to the appropriate
classical hardening where PQC does not apply (e.g. broken hashes / ciphers).

References
----------
* FIPS 203 - Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM / Kyber)
* FIPS 204 - Module-Lattice-Based Digital Signature Algorithm (ML-DSA / Dilithium)
* FIPS 205 - Stateless Hash-Based Digital Signature Algorithm (SLH-DSA / SPHINCS+)
* NIST SP 800-208 - Stateful Hash-Based Signatures (LMS / XMSS)
* CNSA 2.0 - Commercial National Security Algorithm Suite 2.0 timelines
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional


@dataclass(frozen=True)
class PQCAlgorithm:
    """A standardized post-quantum (or hardened classical) target algorithm."""

    name: str
    standard: str
    kind: str  # kem | signature | hash | cipher | rng | process
    nist_security_category: int  # 1..5, NIST PQC security strength category
    summary: str
    public_key_bytes: Optional[int] = None
    private_key_bytes: Optional[int] = None
    ciphertext_or_sig_bytes: Optional[int] = None
    notes: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


# --- Standardized post-quantum algorithms -------------------------------------

ML_KEM_768 = PQCAlgorithm(
    name="ML-KEM-768",
    standard="FIPS 203",
    kind="kem",
    nist_security_category=3,
    summary="Module-lattice key encapsulation. Drop-in replacement for RSA/ECDH "
    "key establishment. Balanced Category-3 parameter set.",
    public_key_bytes=1184,
    private_key_bytes=2400,
    ciphertext_or_sig_bytes=1088,
    notes="Recommended default for TLS/VPN key exchange. Pair in hybrid mode "
    "(X25519 + ML-KEM-768) during transition.",
)

ML_DSA_65 = PQCAlgorithm(
    name="ML-DSA-65",
    standard="FIPS 204",
    kind="signature",
    nist_security_category=3,
    summary="Module-lattice digital signatures. Primary replacement for "
    "RSA/ECDSA/EdDSA signing. Category-3 parameter set.",
    public_key_bytes=1952,
    private_key_bytes=4032,
    ciphertext_or_sig_bytes=3309,
    notes="Fast verification, moderate signature size. Preferred for code "
    "signing, TLS certificates, and document signing.",
)

SLH_DSA_SHA2_128S = PQCAlgorithm(
    name="SLH-DSA-SHA2-128s",
    standard="FIPS 205",
    kind="signature",
    nist_security_category=1,
    summary="Stateless hash-based signatures. Conservative, structure-free "
    "security assumption. Alternative to ML-DSA where lattice risk is a concern.",
    public_key_bytes=32,
    private_key_bytes=64,
    ciphertext_or_sig_bytes=7856,
    notes="Very small keys but large, slow signatures. Ideal for long-lived "
    "roots of trust (firmware, PKI roots) where signing is infrequent.",
)

# --- Hardened classical targets (Grover-resistant / non-broken) ---------------

AES_256_GCM = PQCAlgorithm(
    name="AES-256-GCM",
    standard="FIPS 197 / SP 800-38D",
    kind="cipher",
    nist_security_category=5,
    summary="Authenticated symmetric encryption. 256-bit keys retain a "
    "128-bit security margin against Grover's algorithm.",
    notes="Symmetric crypto is NOT broken by quantum computers; doubling the "
    "key size fully mitigates Grover. Use AEAD (GCM) never ECB/CBC-unauthenticated.",
)

SHA_256 = PQCAlgorithm(
    name="SHA-256 / SHA-3-256",
    standard="FIPS 180-4 / FIPS 202",
    kind="hash",
    nist_security_category=5,
    summary="Collision-resistant cryptographic hash. Grover halves preimage "
    "strength to 128 bits, which remains secure.",
    notes="SHA-256 and SHA3-256 are quantum-safe for realistic parameters. "
    "Migrate away from MD5/SHA-1 which are classically broken.",
)

CSPRNG = PQCAlgorithm(
    name="CSPRNG (OS entropy)",
    standard="SP 800-90A/B/C",
    kind="rng",
    nist_security_category=5,
    summary="Cryptographically secure RNG seeded from the operating system "
    "entropy source (getrandom/BCryptGenRandom).",
    notes="Never use general-purpose PRNGs (rand, Math.random, java.util.Random) "
    "for keys, nonces, IVs, tokens, or salts.",
)

SECRETS_MANAGER = PQCAlgorithm(
    name="Managed secret store",
    standard="Process control",
    kind="process",
    nist_security_category=5,
    summary="Externalize secrets to a vault/KMS (HashiCorp Vault, AWS KMS, "
    "Azure Key Vault) with rotation and access auditing.",
    notes="Hardcoded keys/secrets are an immediate compromise vector "
    "independent of the quantum timeline.",
)

TLS_13 = PQCAlgorithm(
    name="TLS 1.3 (PQC-hybrid ready)",
    standard="RFC 8446",
    kind="process",
    nist_security_category=5,
    summary="Modern TLS with forward secrecy and AEAD-only cipher suites; "
    "supports hybrid X25519+ML-KEM key exchange.",
    notes="Disable TLS 1.0/1.1 and static-RSA key exchange to enable a clean "
    "path to PQC-hybrid handshakes.",
)

ARGON2 = PQCAlgorithm(
    name="Argon2id",
    standard="RFC 9106",
    kind="process",
    nist_security_category=5,
    summary="Memory-hard password hashing function. Purpose-built to resist "
    "GPU/ASIC brute force, unlike general-purpose hashes.",
    notes="Never hash passwords with MD5/SHA-1/SHA-256. Use Argon2id (or "
    "scrypt/bcrypt/PBKDF2-HMAC-SHA256) with a per-user salt and strong parameters.",
)

VERIFIED_JWT = PQCAlgorithm(
    name="Verified JWT (EdDSA / ML-DSA)",
    standard="RFC 8725",
    kind="process",
    nist_security_category=5,
    summary="JWT best practice: always verify signatures, pin the expected "
    "algorithm, and reject 'none'. Migrate signing to ML-DSA for PQC.",
    notes="'alg: none' and disabled verification are authentication bypasses. "
    "Enforce a fixed asymmetric algorithm and validate exp/aud/iss.",
)


# --- Migration mapping --------------------------------------------------------

@dataclass(frozen=True)
class Recommendation:
    """A concrete migration recommendation attached to a detection category."""

    primary: PQCAlgorithm
    alternative: Optional[PQCAlgorithm]
    migration_difficulty: str  # Low | Medium | High
    guidance: str
    size_impact: str
    perf_impact: str

    def to_dict(self) -> dict:
        return {
            "primary": self.primary.to_dict(),
            "alternative": self.alternative.to_dict() if self.alternative else None,
            "migration_difficulty": self.migration_difficulty,
            "guidance": self.guidance,
            "size_impact": self.size_impact,
            "perf_impact": self.perf_impact,
        }


# The category key here matches Rule.pqc_category in the detection ruleset.
RECOMMENDATIONS: Dict[str, Recommendation] = {
    "pk-encryption": Recommendation(
        primary=ML_KEM_768,
        alternative=None,
        migration_difficulty="High",
        guidance="Replace RSA/ECC encryption and key transport with an ML-KEM "
        "key-encapsulation mechanism. Encapsulate a symmetric key with ML-KEM, "
        "then encrypt payload with AES-256-GCM (KEM-DEM). Deploy in hybrid mode "
        "(classical + ML-KEM) first to preserve interoperability.",
        size_impact="Public keys grow from ~256 B (RSA-2048) to ~1.2 KB; "
        "ciphertext ~1.1 KB per encapsulation.",
        perf_impact="ML-KEM keygen/encaps/decaps are faster than RSA-2048 in CPU "
        "time; the cost is bandwidth and key storage, not compute.",
    ),
    "key-exchange": Recommendation(
        primary=ML_KEM_768,
        alternative=None,
        migration_difficulty="High",
        guidance="Migrate Diffie-Hellman / ECDH key agreement to ML-KEM. For TLS, "
        "adopt the X25519MLKEM768 hybrid group so a break of either component "
        "still leaves the handshake secure.",
        size_impact="Handshake key-share grows by ~1.1-1.2 KB per direction.",
        perf_impact="Negligible added CPU; one extra MTU of handshake data.",
    ),
    "signature": Recommendation(
        primary=ML_DSA_65,
        alternative=SLH_DSA_SHA2_128S,
        migration_difficulty="High",
        guidance="Replace RSA/ECDSA/EdDSA/DSA signatures with ML-DSA. Use "
        "SLH-DSA for long-lived roots of trust where a conservative, hash-based "
        "assumption is preferred. Issue PQC or hybrid certificates from your CA.",
        size_impact="Signatures grow from ~64-256 B to ~3.3 KB (ML-DSA) or "
        "~7.9 KB (SLH-DSA); certificates and chains grow accordingly.",
        perf_impact="ML-DSA verification is fast; signature size drives "
        "certificate-chain and bandwidth growth.",
    ),
    "hash-broken": Recommendation(
        primary=SHA_256,
        alternative=None,
        migration_difficulty="Low",
        guidance="MD5 and SHA-1 are collision-broken and must be replaced with "
        "SHA-256 or SHA3-256 for any security purpose (signatures, integrity, "
        "certificate fingerprints, HMAC).",
        size_impact="Negligible (32-byte digests).",
        perf_impact="Negligible; modern CPUs hardware-accelerate SHA-2.",
    ),
    "cipher-broken": Recommendation(
        primary=AES_256_GCM,
        alternative=None,
        migration_difficulty="Medium",
        guidance="DES, 3DES, RC4, and Blowfish are obsolete/broken. Replace with "
        "AES-256 in an AEAD mode (GCM or ChaCha20-Poly1305). Never use ECB mode "
        "or unauthenticated CBC.",
        size_impact="Negligible.",
        perf_impact="AES-NI makes AES-256-GCM faster than legacy ciphers.",
    ),
    "cipher-grover": Recommendation(
        primary=AES_256_GCM,
        alternative=None,
        migration_difficulty="Low",
        guidance="128-bit symmetric keys drop to a 64-bit effective margin under "
        "Grover. Upgrade to 256-bit keys (AES-256) to restore a 128-bit margin.",
        size_impact="Negligible.",
        perf_impact="Marginal; a few extra AES rounds.",
    ),
    "rng-weak": Recommendation(
        primary=CSPRNG,
        alternative=None,
        migration_difficulty="Low",
        guidance="Replace non-cryptographic PRNGs with a CSPRNG (secrets, "
        "os.urandom, SecureRandom, crypto.randomBytes, RAND_bytes) for all "
        "keys, IVs, nonces, salts, and tokens.",
        size_impact="None.",
        perf_impact="None.",
    ),
    "secret": Recommendation(
        primary=SECRETS_MANAGER,
        alternative=None,
        migration_difficulty="Medium",
        guidance="Remove hardcoded keys/credentials from source. Load from a "
        "secrets manager/KMS at runtime, rotate the exposed secret immediately, "
        "and add secret scanning to CI to prevent regressions.",
        size_impact="None.",
        perf_impact="None.",
    ),
    "protocol-weak": Recommendation(
        primary=TLS_13,
        alternative=None,
        migration_difficulty="Medium",
        guidance="Disable TLS 1.0/1.1 and static-RSA key exchange. Require "
        "TLS 1.3 with forward-secret, AEAD cipher suites as the foundation for "
        "PQC-hybrid handshakes.",
        size_impact="None.",
        perf_impact="TLS 1.3 reduces handshake round-trips.",
    ),
    "password-hash": Recommendation(
        primary=ARGON2,
        alternative=None,
        migration_difficulty="Medium",
        guidance="Replace fast/general-purpose hashes used for passwords with "
        "Argon2id (or scrypt/bcrypt/PBKDF2). Add a per-user salt, tune the work "
        "factor, and re-hash on next login during migration.",
        size_impact="Negligible.",
        perf_impact="Intentionally slower (that is the security property).",
    ),
    "auth-weak": Recommendation(
        primary=VERIFIED_JWT,
        alternative=None,
        migration_difficulty="Low",
        guidance="Always verify token signatures, pin the expected algorithm, "
        "and reject 'none'. Move to asymmetric signing (EdDSA today, ML-DSA for "
        "post-quantum) and validate exp/aud/iss claims.",
        size_impact="None.",
        perf_impact="Negligible.",
    ),
    "iv-static": Recommendation(
        primary=CSPRNG,
        alternative=None,
        migration_difficulty="Low",
        guidance="Never reuse a hardcoded IV/nonce. Generate a fresh random "
        "IV/nonce per message from a CSPRNG and transmit it alongside the "
        "ciphertext. Static IVs break the security of CBC/CTR/GCM.",
        size_impact="One IV/nonce per message (12-16 bytes).",
        perf_impact="None.",
    ),
}


def recommend(pqc_category: Optional[str]) -> Optional[Recommendation]:
    """Return the migration recommendation for a detection category."""
    if not pqc_category:
        return None
    return RECOMMENDATIONS.get(pqc_category)


def catalog() -> List[dict]:
    """Return the full PQC target catalog (for the API / UI reference view)."""
    seen: Dict[str, PQCAlgorithm] = {}
    for rec in RECOMMENDATIONS.values():
        seen[rec.primary.name] = rec.primary
        if rec.alternative:
            seen[rec.alternative.name] = rec.alternative
    return [alg.to_dict() for alg in seen.values()]

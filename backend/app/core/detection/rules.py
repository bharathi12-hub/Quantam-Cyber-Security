"""
Cryptographic detection ruleset.

Each rule describes a cryptographic primitive or misuse, how to recognize it in
source code across languages (regular expressions), how a quantum adversary
affects it, and which migration category it maps to in the PQC catalog.

Quantum-threat model
--------------------
* SHOR   - Shor's algorithm breaks the underlying hard problem outright
           (integer factorisation / discrete log). RSA, ECC, DSA, DH.
           => must migrate to a post-quantum primitive.
* GROVER - Grover's algorithm gives a quadratic speed-up, halving the effective
           security of symmetric keys / hashes. Mitigated by doubling sizes.
* CLASSICAL - Already weak or broken by classical cryptanalysis, independent of
           quantum computing (MD5, SHA-1, DES, RC4, hardcoded keys, weak RNG).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

# Quantum-threat classes
SHOR = "shor"
GROVER = "grover"
CLASSICAL = "classical"

# Severity levels
CRITICAL = "Critical"
HIGH = "High"
MEDIUM = "Medium"
LOW = "Low"

ALL = ("*",)


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    algorithm: str
    family: str
    quantum_threat: str
    severity: str
    pqc_category: Optional[str]
    cwe: str
    description: str
    remediation: str
    patterns: Tuple[str, ...]
    languages: Tuple[str, ...] = ALL
    confidence: str = "High"
    case_sensitive: bool = False


RULES: List[Rule] = [
    # ---------------------------------------------------------------- Shor-broken
    Rule(
        id="RSA",
        name="RSA key generation / encryption",
        algorithm="RSA",
        family="Asymmetric Encryption",
        quantum_threat=SHOR,
        severity=CRITICAL,
        pqc_category="pk-encryption",
        cwe="CWE-327",
        description="RSA relies on integer factorisation, which Shor's algorithm "
        "solves in polynomial time on a cryptographically relevant quantum "
        "computer. All RSA key transport and encryption is quantum-vulnerable. "
        "If this RSA key is used for signatures, migrate to ML-DSA instead of "
        "ML-KEM.",
        remediation="Adopt ML-KEM (FIPS 203) for key establishment in hybrid mode; "
        "use ML-DSA (FIPS 204) if the key signs.",
        patterns=(
            r"RSA\.generate\s*\(",
            r"rsa\.generate_private_key\s*\(",
            r"RSA_generate_key(_ex)?\s*\(",
            r'getInstance\s*\(\s*"RSA',
            r"""generateKeyPair(Sync)?\s*\(\s*['"]rsa['"]""",
            r"rsa\.GenerateKey\s*\(",
            r"RSACryptoServiceProvider",
            r"RSA\.Create\s*\(",
            r"new\s+RSACng",
            r"RsaPrivateKey::|RsaPublicKey::",
            r"openssl_pkey_new",
        ),
    ),
    Rule(
        id="ECDSA",
        name="Elliptic-curve signatures (ECDSA / ECC)",
        algorithm="ECDSA",
        family="Digital Signature",
        quantum_threat=SHOR,
        severity=CRITICAL,
        pqc_category="signature",
        cwe="CWE-327",
        description="ECDSA and elliptic-curve cryptography rely on the elliptic "
        "curve discrete-log problem, which Shor's algorithm breaks. Signatures "
        "and the associated keys are quantum-vulnerable.",
        remediation="Migrate signing to ML-DSA (FIPS 204); use SLH-DSA (FIPS 205) "
        "for long-lived roots of trust.",
        patterns=(
            r"ec\.generate_private_key\s*\(",
            r"\bECDSA\b",
            r'getInstance\s*\(\s*"EC(DSA)?"',
            r"ecdsa\.GenerateKey\s*\(",
            r"elliptic\.(P224|P256|P384|P521)\s*\(",
            r"EC_KEY_(new|generate_key)|EVP_PKEY_EC",
            r"ECDsa(Cng)?\.Create|ECDsaCng",
            r"crypto/ecdsa",
            r"(secp256r1|secp384r1|secp521r1|secp256k1|prime256v1|NIST P-\d{3})",
        ),
    ),
    Rule(
        id="ECDH",
        name="Elliptic-curve / Diffie-Hellman key exchange",
        algorithm="ECDH",
        family="Key Exchange",
        quantum_threat=SHOR,
        severity=CRITICAL,
        pqc_category="key-exchange",
        cwe="CWE-327",
        description="ECDH (including X25519) and finite-field Diffie-Hellman key "
        "agreement rely on discrete logarithms and are broken by Shor's "
        "algorithm. A recorded handshake can be decrypted once a quantum "
        "computer is available ('harvest now, decrypt later').",
        remediation="Adopt ML-KEM (FIPS 203); deploy the X25519MLKEM768 hybrid "
        "group for TLS during transition.",
        patterns=(
            r"\bECDH\b",
            r"\bX25519\b",
            r"[Cc]urve25519",
            r"crypto/ecdh",
            r"EVP_PKEY_derive\b",
            r"KeyAgreement\.getInstance",
            r"\bECDHE?_RSA\b|\bECDHE?_ECDSA\b",
        ),
    ),
    Rule(
        id="EDDSA",
        name="EdDSA signatures (Ed25519 / Ed448)",
        algorithm="Ed25519",
        family="Digital Signature",
        quantum_threat=SHOR,
        severity=CRITICAL,
        pqc_category="signature",
        cwe="CWE-327",
        description="EdDSA (Ed25519/Ed448) is an elliptic-curve signature scheme "
        "and is broken by Shor's algorithm despite its strong classical "
        "security.",
        remediation="Migrate signing to ML-DSA (FIPS 204).",
        patterns=(
            r"\bEd25519\b",
            r"\bEd448\b",
            r"\bEdDSA\b",
            r"ed25519_dalek",
            r"nacl\.sign|tweetnacl",
        ),
    ),
    Rule(
        id="DSA",
        name="Digital Signature Algorithm (DSA)",
        algorithm="DSA",
        family="Digital Signature",
        quantum_threat=SHOR,
        severity=HIGH,
        pqc_category="signature",
        cwe="CWE-327",
        description="DSA depends on the discrete-logarithm problem and is broken "
        "by Shor's algorithm.",
        remediation="Migrate to ML-DSA (FIPS 204).",
        patterns=(
            r'getInstance\s*\(\s*"DSA"',
            r"DSA\.generate\s*\(",
            r"dsa\.generate_private_key\s*\(",
            r"crypto/dsa",
            r"DSACryptoServiceProvider",
        ),
    ),
    Rule(
        id="DH",
        name="Finite-field Diffie-Hellman",
        algorithm="Diffie-Hellman",
        family="Key Exchange",
        quantum_threat=SHOR,
        severity=HIGH,
        pqc_category="key-exchange",
        cwe="CWE-327",
        description="Classic finite-field Diffie-Hellman key agreement relies on "
        "discrete logarithms and is broken by Shor's algorithm.",
        remediation="Adopt ML-KEM (FIPS 203) key encapsulation.",
        patterns=(
            r"[Dd]iffie-?[Hh]ellman",
            r"DH_generate_(key|parameters)",
            r'getInstance\s*\(\s*"DH"',
            r"\bdhparam\b",
            r"DHParameterSpec",
        ),
    ),
    # ------------------------------------------------------------ Classically broken hashes
    Rule(
        id="MD5",
        name="MD5 message digest",
        algorithm="MD5",
        family="Hash Function",
        quantum_threat=CLASSICAL,
        severity=HIGH,
        pqc_category="hash-broken",
        cwe="CWE-328",
        description="MD5 is collision-broken and unsuitable for any security "
        "purpose (signatures, integrity, fingerprints, HMAC).",
        remediation="Replace with SHA-256 or SHA3-256.",
        patterns=(
            r"\bMD5\b",
            r"hashlib\.md5\s*\(",
            r"createHash\s*\(\s*['\"]md5['\"]",
            r"EVP_md5\b",
            r"MD5\.Create\s*\(",
        ),
    ),
    Rule(
        id="SHA1",
        name="SHA-1 message digest",
        algorithm="SHA-1",
        family="Hash Function",
        quantum_threat=CLASSICAL,
        severity=HIGH,
        pqc_category="hash-broken",
        cwe="CWE-328",
        description="SHA-1 is collision-broken (SHAttered) and deprecated for "
        "signatures and certificates.",
        remediation="Replace with SHA-256 or SHA3-256.",
        patterns=(
            r"\bSHA-?1\b",
            r"hashlib\.sha1\s*\(",
            r"createHash\s*\(\s*['\"]sha1['\"]",
            r"EVP_sha1\b",
            r"SHA1\.Create\s*\(",
            r"crypto/sha1",
        ),
    ),
    # ------------------------------------------------------------ Broken symmetric ciphers
    Rule(
        id="DES",
        name="DES block cipher",
        algorithm="DES",
        family="Symmetric Cipher",
        quantum_threat=CLASSICAL,
        severity=HIGH,
        pqc_category="cipher-broken",
        cwe="CWE-327",
        description="Single-DES has a 56-bit key and is brute-forceable in "
        "hours. It is obsolete.",
        remediation="Replace with AES-256-GCM.",
        patterns=(
            r"DES\.new\s*\(",
            r'getInstance\s*\(\s*"DES(?!ede)',
            r"EVP_des_(cbc|ecb|cfb|ofb)\b",
            r"crypto/des",
            r"DESCryptoServiceProvider",
            r"createCipheriv\s*\(\s*['\"]des-",
        ),
    ),
    Rule(
        id="3DES",
        name="Triple DES (3DES / DESede)",
        algorithm="3DES",
        family="Symmetric Cipher",
        quantum_threat=CLASSICAL,
        severity=MEDIUM,
        pqc_category="cipher-broken",
        cwe="CWE-327",
        description="Triple-DES is deprecated by NIST (SP 800-131A), has a small "
        "64-bit block (Sweet32), and is slow.",
        remediation="Replace with AES-256-GCM.",
        patterns=(
            r"\b3DES\b",
            r"TripleDES",
            r"DESede",
            r"EVP_des_ede3",
            r"createCipheriv\s*\(\s*['\"]des-ede3",
        ),
    ),
    Rule(
        id="RC4",
        name="RC4 stream cipher",
        algorithm="RC4",
        family="Symmetric Cipher",
        quantum_threat=CLASSICAL,
        severity=HIGH,
        pqc_category="cipher-broken",
        cwe="CWE-327",
        description="RC4 has multiple practical biases and is prohibited in TLS "
        "(RFC 7465).",
        remediation="Replace with AES-256-GCM or ChaCha20-Poly1305.",
        patterns=(
            r"\bRC4\b",
            r"\bARC4\b",
            r"arcfour",
            r"EVP_rc4\b",
            r"createCipheriv\s*\(\s*['\"]rc4",
        ),
    ),
    Rule(
        id="BLOWFISH",
        name="Blowfish block cipher",
        algorithm="Blowfish",
        family="Symmetric Cipher",
        quantum_threat=CLASSICAL,
        severity=MEDIUM,
        pqc_category="cipher-broken",
        cwe="CWE-327",
        description="Blowfish has a 64-bit block (Sweet32-vulnerable) and is "
        "superseded by AES.",
        remediation="Replace with AES-256-GCM.",
        patterns=(
            r"\bBlowfish\b",
            r"BF_(set_key|encrypt|cbc|ecb)\b",
            r"createCipheriv\s*\(\s*['\"]bf-",
        ),
    ),
    Rule(
        id="AES_ECB",
        name="Insecure cipher mode (ECB)",
        algorithm="AES-ECB",
        family="Cipher Mode",
        quantum_threat=CLASSICAL,
        severity=HIGH,
        pqc_category="cipher-broken",
        cwe="CWE-327",
        description="ECB mode encrypts identical plaintext blocks to identical "
        "ciphertext, leaking structure. Even with AES, ECB is insecure.",
        remediation="Use an AEAD mode: AES-256-GCM or ChaCha20-Poly1305.",
        patterns=(
            r"MODE_ECB",
            r"/ECB/",
            r"-ecb\b",
            r"CipherMode\.ECB",
            r"AES/ECB",
        ),
    ),
    Rule(
        id="AES128",
        name="128-bit symmetric key (Grover margin)",
        algorithm="AES-128",
        family="Symmetric Cipher",
        quantum_threat=GROVER,
        severity=LOW,
        pqc_category="cipher-grover",
        cwe="CWE-326",
        description="A 128-bit symmetric key retains only a 64-bit effective "
        "margin under Grover's algorithm. Not broken, but below the recommended "
        "post-quantum margin.",
        remediation="Upgrade to 256-bit keys (AES-256).",
        patterns=(
            r"AES-?128",
            r"aes-128-",
        ),
    ),
    # ------------------------------------------------------------ Weak RNG (per language)
    Rule(
        id="RNG_JS",
        name="Non-cryptographic RNG (Math.random)",
        algorithm="Math.random",
        family="Random Number Generation",
        quantum_threat=CLASSICAL,
        severity=MEDIUM,
        pqc_category="rng-weak",
        cwe="CWE-338",
        description="Math.random() is not cryptographically secure and must not "
        "be used for keys, tokens, IVs, nonces, or salts.",
        remediation="Use crypto.randomBytes() / crypto.getRandomValues().",
        patterns=(r"Math\.random\s*\(",),
        languages=("JavaScript", "TypeScript"),
        case_sensitive=True,
    ),
    Rule(
        id="RNG_PY",
        name="Non-cryptographic RNG (random module)",
        algorithm="random",
        family="Random Number Generation",
        quantum_threat=CLASSICAL,
        severity=MEDIUM,
        pqc_category="rng-weak",
        cwe="CWE-338",
        description="Python's random module is a Mersenne-Twister PRNG and is not "
        "cryptographically secure. Using it for security values is unsafe.",
        remediation="Use the secrets module or os.urandom().",
        patterns=(r"random\.(random|randint|randrange|choice|getrandbits|shuffle)\s*\(",),
        languages=("Python",),
        case_sensitive=True,
    ),
    Rule(
        id="RNG_JAVA",
        name="Non-cryptographic RNG (java.util.Random)",
        algorithm="java.util.Random",
        family="Random Number Generation",
        quantum_threat=CLASSICAL,
        severity=MEDIUM,
        pqc_category="rng-weak",
        cwe="CWE-338",
        description="java.util.Random is predictable and not cryptographically "
        "secure. Do not use it for security-sensitive values.",
        remediation="Use java.security.SecureRandom.",
        patterns=(r"new\s+Random\s*\(",),
        languages=("Java", "Kotlin"),
        case_sensitive=True,
    ),
    Rule(
        id="RNG_C",
        name="Non-cryptographic RNG (rand/srand)",
        algorithm="rand",
        family="Random Number Generation",
        quantum_threat=CLASSICAL,
        severity=MEDIUM,
        pqc_category="rng-weak",
        cwe="CWE-338",
        description="The C standard-library rand()/srand() PRNG is not "
        "cryptographically secure.",
        remediation="Use a CSPRNG: getrandom(2), RAND_bytes (OpenSSL), or "
        "BCryptGenRandom (Windows).",
        patterns=(r"\bs?rand\s*\(", r"\brandom\s*\(\s*\)"),
        languages=("C", "C++"),
        case_sensitive=True,
    ),
    Rule(
        id="RNG_PHP",
        name="Non-cryptographic RNG (rand/mt_rand)",
        algorithm="mt_rand",
        family="Random Number Generation",
        quantum_threat=CLASSICAL,
        severity=MEDIUM,
        pqc_category="rng-weak",
        cwe="CWE-338",
        description="PHP's rand()/mt_rand() are not cryptographically secure.",
        remediation="Use random_bytes() or random_int().",
        patterns=(r"\b(mt_rand|rand)\s*\(",),
        languages=("PHP",),
        case_sensitive=True,
    ),
    Rule(
        id="RNG_GO",
        name="Non-cryptographic RNG (math/rand)",
        algorithm="math/rand",
        family="Random Number Generation",
        quantum_threat=CLASSICAL,
        severity=MEDIUM,
        pqc_category="rng-weak",
        cwe="CWE-338",
        description="Go's math/rand package is not cryptographically secure.",
        remediation="Use crypto/rand.",
        patterns=(r'"math/rand"',),
        languages=("Go",),
        case_sensitive=True,
    ),
    # ------------------------------------------------------------ Secrets & protocols
    Rule(
        id="PRIVKEY",
        name="Hardcoded private key",
        algorithm="Private Key Material",
        family="Secret Management",
        quantum_threat=CLASSICAL,
        severity=CRITICAL,
        pqc_category="secret",
        cwe="CWE-321",
        description="A PEM-encoded private key is embedded in source. Anyone with "
        "repository access owns this key.",
        remediation="Remove the key, rotate it immediately, and load from a "
        "secrets manager / KMS.",
        patterns=(
            r"-----BEGIN (RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----",
        ),
    ),
    Rule(
        id="SECRET",
        name="Hardcoded credential / secret",
        algorithm="Embedded Secret",
        family="Secret Management",
        quantum_threat=CLASSICAL,
        severity=HIGH,
        pqc_category="secret",
        cwe="CWE-798",
        description="A credential or API key appears to be hardcoded as a string "
        "literal. Review and externalize.",
        remediation="Load secrets from environment / a secrets manager and rotate "
        "the exposed value.",
        patterns=(
            r"""(?i)(password|passwd|pwd|secret|api[_-]?key|access[_-]?key|auth[_-]?token)\s*[:=]\s*['"][^'"\s]{6,}['"]""",
        ),
        confidence="Medium",
    ),
    Rule(
        id="TLS_WEAK",
        name="Obsolete TLS/SSL protocol version",
        algorithm="TLS 1.0/1.1 / SSLv3",
        family="Transport Security",
        quantum_threat=CLASSICAL,
        severity=HIGH,
        pqc_category="protocol-weak",
        cwe="CWE-326",
        description="Obsolete TLS/SSL versions are enabled. These lack modern "
        "cipher suites and forward secrecy and block a clean path to PQC-hybrid "
        "handshakes.",
        remediation="Require TLS 1.3 (or 1.2 minimum) with AEAD, forward-secret "
        "cipher suites; disable SSLv3/TLS 1.0/1.1.",
        patterns=(
            r"\bSSLv2\b|\bSSLv3\b|\bSSLv23\b",
            r"PROTOCOL_TLSv1(?!_2|_3)\b",
            r"TLSv1\.[01]\b",
            r"TLSv1_1\b",
            r"TLS_?1\.0|TLS_?1\.1",
        ),
    ),
    # ------------------------------------------------------------ Additional ciphers/hashes
    Rule(
        id="RC2",
        name="RC2 block cipher",
        algorithm="RC2",
        family="Symmetric Cipher",
        quantum_threat=CLASSICAL,
        severity=MEDIUM,
        pqc_category="cipher-broken",
        cwe="CWE-327",
        description="RC2 is an obsolete 64-bit block cipher with known weaknesses.",
        remediation="Replace with AES-256-GCM.",
        patterns=(
            r"\bRC2\b",
            r"RC2CryptoServiceProvider",
            r"EVP_rc2",
            r"createCipheriv\s*\(\s*['\"]rc2",
        ),
    ),
    Rule(
        id="SHA224",
        name="SHA-224 message digest",
        algorithm="SHA-224",
        family="Hash Function",
        quantum_threat=CLASSICAL,
        severity=LOW,
        pqc_category="hash-broken",
        cwe="CWE-328",
        description="SHA-224 provides only ~112-bit collision resistance, below "
        "the modern 128-bit baseline.",
        remediation="Prefer SHA-256 or SHA3-256.",
        patterns=(
            r"\bSHA-?224\b",
            r"hashlib\.sha224\s*\(",
            r"EVP_sha224\b",
        ),
    ),
    # ------------------------------------------------------------ Auth / protocol misuse
    Rule(
        id="JWT_NONE",
        name="Insecure JWT verification",
        algorithm="JWT (alg:none / unverified)",
        family="Authentication",
        quantum_threat=CLASSICAL,
        severity=HIGH,
        pqc_category="auth-weak",
        cwe="CWE-347",
        description="The JWT 'none' algorithm or disabled signature verification "
        "allows attackers to forge tokens - an authentication bypass.",
        remediation="Verify signatures, pin the expected algorithm, reject 'none'.",
        patterns=(
            r"alg[a-z]*['\"]?\s*[:=]\s*\[?\s*['\"]none['\"]",
            r"jwt\.decode\([^)\n]*verify\s*=\s*False",
            r"verify_signature['\"]?\s*[:=]\s*false",
        ),
    ),
    Rule(
        id="SSH_WEAK",
        name="Weak SSH key type / cipher",
        algorithm="ssh-rsa / ssh-dss",
        family="Transport Security",
        quantum_threat=SHOR,
        severity=HIGH,
        pqc_category="signature",
        cwe="CWE-326",
        description="Legacy SSH host-key types (ssh-rsa with SHA-1, ssh-dss) and "
        "CBC/arcfour ciphers are weak; the underlying RSA/DSA keys are also "
        "quantum-vulnerable.",
        remediation="Use ed25519 keys today; plan ML-DSA for post-quantum. "
        "Disable CBC/arcfour ciphers.",
        patterns=(
            r"\bssh-rsa\b",
            r"\bssh-dss\b",
            r"HostKeyAlgorithms[^\n]*ssh-rsa",
            r"PubkeyAcceptedKeyTypes[^\n]*ssh-rsa",
            r"\bCiphers\s+[^\n]*(3des-cbc|arcfour|blowfish)",
        ),
    ),
    Rule(
        id="PASSWORD_HASH",
        name="Weak password hashing",
        algorithm="Fast hash for passwords",
        family="Password Storage",
        quantum_threat=CLASSICAL,
        severity=HIGH,
        pqc_category="password-hash",
        cwe="CWE-916",
        description="Passwords appear to be hashed with a fast, general-purpose "
        "hash (MD5/SHA-x). These are trivially brute-forced with GPUs.",
        remediation="Use Argon2id / scrypt / bcrypt / PBKDF2 with a per-user salt.",
        patterns=(
            r"(md5|sha-?1|sha224|sha256)[^\n]{0,25}passw",
            r"passw[a-z_]*[^\n]{0,25}(md5|sha-?1|sha256)",
            r"DigestUtils\.(md5|sha1)Hex",
        ),
        confidence="Medium",
    ),
    Rule(
        id="STATIC_IV",
        name="Hardcoded / static IV or nonce",
        algorithm="Static IV/Nonce",
        family="Key Management",
        quantum_threat=CLASSICAL,
        severity=MEDIUM,
        pqc_category="iv-static",
        cwe="CWE-329",
        description="A hardcoded initialization vector / nonce is reused across "
        "messages, breaking the security of CBC/CTR/GCM modes.",
        remediation="Generate a fresh random IV/nonce per message from a CSPRNG.",
        patterns=(
            r"\b(iv|nonce)\s*=\s*b?['\"][0-9A-Za-z+/=]{6,}['\"]",
            r"new\s+IvParameterSpec\s*\(\s*['\"][^'\"]+['\"]",
            r"IvParameterSpec\([^)\n]*getBytes",
        ),
        confidence="Medium",
    ),
    Rule(
        id="SHORT_KEY",
        name="Short RSA key length (<2048)",
        algorithm="Short RSA key",
        family="Asymmetric Encryption",
        quantum_threat=SHOR,
        severity=HIGH,
        pqc_category="pk-encryption",
        cwe="CWE-326",
        description="An RSA key of 1024 bits or smaller is factorable with modest "
        "resources today and is additionally quantum-vulnerable.",
        remediation="Interim: use >=3072-bit RSA. Strategic: migrate to ML-KEM/ML-DSA.",
        patterns=(
            r"RSA\.generate\(\s*(512|768|1024)\b",
            r"key_size\s*=\s*(512|768|1024)\b",
            r"modulusLength\s*[:=]\s*(512|768|1024)\b",
            r"initialize\(\s*(512|768|1024)\s*\)",
            r"RSA_generate_key(_ex)?\([^)\n]*\b(512|768|1024)\b",
        ),
    ),
    Rule(
        id="RNG_RUBY",
        name="Non-cryptographic RNG (Kernel#rand)",
        algorithm="rand",
        family="Random Number Generation",
        quantum_threat=CLASSICAL,
        severity=MEDIUM,
        pqc_category="rng-weak",
        cwe="CWE-338",
        description="Ruby's Kernel#rand / Random are not cryptographically secure.",
        remediation="Use SecureRandom.",
        patterns=(r"\brand\s*\(", r"Random\.rand", r"Kernel\.rand"),
        languages=("Ruby",),
        case_sensitive=True,
    ),
]

# Fast lookup by id
RULES_BY_ID: Dict[str, Rule] = {r.id: r for r in RULES}


def all_rules() -> List[Rule]:
    return RULES

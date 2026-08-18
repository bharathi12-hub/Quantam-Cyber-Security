"""
Knowledge base for the AI Security Advisor.

Deterministic, offline domain knowledge: concept explanations (algorithms, NIST
standards, quantum threats) and correct secure-replacement code snippets keyed
by migration category and language. No external LLM required.
"""
from __future__ import annotations

# --------------------------------------------------------------- concept explainers
# Keyed by normalized term. `answer()` routing maps synonyms to these keys.
CONCEPTS: dict[str, dict] = {
    "rsa": {
        "title": "RSA",
        "body": "RSA is a public-key cryptosystem whose security rests on the difficulty "
        "of factoring the product of two large primes. Shor's algorithm factors integers "
        "in polynomial time on a cryptographically relevant quantum computer, so every RSA "
        "key (encryption and signatures) is quantum-vulnerable. Classically, keys below "
        "2048 bits are already too weak.",
        "migrate_to": "ML-KEM-768 (FIPS 203) for key establishment; ML-DSA-65 (FIPS 204) for signatures.",
    },
    "ecdsa": {
        "title": "ECDSA / Elliptic-Curve Cryptography",
        "body": "ECDSA and ECC rely on the elliptic-curve discrete-logarithm problem. Shor's "
        "algorithm solves discrete logs, so ECDSA/ECDH/EdDSA are all broken by a quantum "
        "computer despite their strong classical security and small key sizes.",
        "migrate_to": "ML-DSA-65 (FIPS 204) for signatures; ML-KEM-768 for ECDH key exchange.",
    },
    "ecdh": {
        "title": "ECDH / Diffie-Hellman Key Exchange",
        "body": "ECDH and finite-field Diffie-Hellman derive a shared secret using the "
        "discrete-log problem. They are broken by Shor's algorithm. Recorded handshakes are "
        "exposed to 'harvest now, decrypt later' attacks.",
        "migrate_to": "ML-KEM-768 (FIPS 203); deploy the X25519MLKEM768 hybrid group in TLS.",
    },
    "md5": {
        "title": "MD5",
        "body": "MD5 is a 128-bit hash that is collision-broken; attackers can craft two "
        "inputs with the same digest cheaply. It must never be used for signatures, "
        "integrity, or password storage. This is a classical break, independent of quantum.",
        "migrate_to": "SHA-256 or SHA3-256.",
    },
    "sha1": {
        "title": "SHA-1",
        "body": "SHA-1 is collision-broken (the SHAttered attack produced a real collision). "
        "Browsers and CAs have deprecated it for certificates and signatures.",
        "migrate_to": "SHA-256 or SHA3-256.",
    },
    "des": {
        "title": "DES / 3DES",
        "body": "Single DES has a 56-bit key brute-forceable in hours. Triple-DES has a small "
        "64-bit block (Sweet32) and is deprecated by NIST. Both are obsolete.",
        "migrate_to": "AES-256-GCM.",
    },
    "rc4": {
        "title": "RC4",
        "body": "RC4 is a stream cipher with multiple practical keystream biases and is "
        "prohibited in TLS (RFC 7465).",
        "migrate_to": "AES-256-GCM or ChaCha20-Poly1305.",
    },
    "ml-kem": {
        "title": "ML-KEM (FIPS 203, formerly Kyber)",
        "body": "ML-KEM is the NIST-standardized module-lattice Key-Encapsulation Mechanism. "
        "It replaces RSA/ECDH for establishing symmetric keys and is believed secure against "
        "both classical and quantum attackers. ML-KEM-768 targets NIST security category 3.",
        "migrate_to": "Adopt in hybrid mode (X25519 + ML-KEM-768) during transition.",
    },
    "ml-dsa": {
        "title": "ML-DSA (FIPS 204, formerly Dilithium)",
        "body": "ML-DSA is the NIST-standardized module-lattice digital signature algorithm, "
        "the primary post-quantum replacement for RSA/ECDSA/EdDSA signatures. Signatures are "
        "larger (~3.3 KB) but verification is fast.",
        "migrate_to": "Use for code signing, TLS certificates, and document signing.",
    },
    "slh-dsa": {
        "title": "SLH-DSA (FIPS 205, formerly SPHINCS+)",
        "body": "SLH-DSA is a stateless hash-based signature scheme. Its security rests only "
        "on the hash function, making it a conservative, structure-free alternative to "
        "lattice signatures - ideal for long-lived roots of trust. Signatures are large and "
        "slow to produce.",
        "migrate_to": "Use for firmware/PKI roots where signing is infrequent.",
    },
    "shor": {
        "title": "Shor's Algorithm",
        "body": "Shor's algorithm is a quantum algorithm that factors integers and computes "
        "discrete logarithms in polynomial time. It breaks RSA, Diffie-Hellman, and all "
        "elliptic-curve cryptography once a large enough quantum computer exists.",
        "migrate_to": "Migrate all public-key crypto to ML-KEM / ML-DSA / SLH-DSA.",
    },
    "grover": {
        "title": "Grover's Algorithm",
        "body": "Grover's algorithm gives a quadratic speed-up for brute-force search, "
        "effectively halving the security of symmetric keys and hash preimages. It does NOT "
        "break symmetric crypto - doubling key/hash sizes fully mitigates it.",
        "migrate_to": "Use AES-256 and SHA-384/SHA3-256 for a 128-bit post-quantum margin.",
    },
    "hndl": {
        "title": "Harvest Now, Decrypt Later",
        "body": "Adversaries record encrypted traffic today and store it until a quantum "
        "computer can decrypt it. Any data with a long confidentiality lifetime (health, "
        "financial, state secrets) is already at risk, which is why migration is urgent even "
        "before quantum computers arrive.",
        "migrate_to": "Prioritize key-exchange (ML-KEM) migration for long-lived secrets.",
    },
    "pqc": {
        "title": "Post-Quantum Cryptography",
        "body": "PQC is cryptography designed to resist both classical and quantum attackers, "
        "running on today's hardware. NIST standardized the first algorithms in 2024: "
        "ML-KEM (FIPS 203), ML-DSA (FIPS 204), and SLH-DSA (FIPS 205).",
        "migrate_to": "Inventory crypto, prioritize by data lifetime, deploy hybrid, then pure PQC.",
    },
}

_SYNONYMS = {
    "kyber": "ml-kem", "mlkem": "ml-kem", "ml kem": "ml-kem",
    "dilithium": "ml-dsa", "mldsa": "ml-dsa", "ml dsa": "ml-dsa",
    "sphincs": "slh-dsa", "sphincs+": "slh-dsa", "slhdsa": "slh-dsa",
    "ecc": "ecdsa", "elliptic": "ecdsa", "eddsa": "ecdsa", "ed25519": "ecdsa",
    "diffie": "ecdh", "diffie-hellman": "ecdh", "dh": "ecdh", "x25519": "ecdh",
    "sha-1": "sha1", "sha 1": "sha1",
    "3des": "des", "triple des": "des", "tripledes": "des",
    "harvest now decrypt later": "hndl", "harvest": "hndl",
    "post-quantum": "pqc", "post quantum": "pqc", "quantum safe": "pqc", "nist": "pqc",
}


def resolve_concept(term: str) -> str | None:
    t = term.lower().strip()
    if t in CONCEPTS:
        return t
    return _SYNONYMS.get(t)


# --------------------------------------------------------------- secure code library
# category -> language -> snippet. "*" is a language-agnostic fallback.
SECURE_CODE: dict[str, dict[str, str]] = {
    "hash-broken": {
        "Python": "import hashlib\n"
        "digest = hashlib.sha256(data).hexdigest()  # or hashlib.sha3_256",
        "JavaScript": "const crypto = require('crypto');\n"
        "const digest = crypto.createHash('sha256').update(data).digest('hex');",
        "Java": 'MessageDigest md = MessageDigest.getInstance("SHA-256");\n'
        "byte[] digest = md.digest(data);",
        "*": "Use SHA-256 or SHA3-256 instead of MD5/SHA-1.",
    },
    "cipher-broken": {
        "Python": "import os\nfrom cryptography.hazmat.primitives.ciphers.aead import AESGCM\n"
        "key = AESGCM.generate_key(bit_length=256)\n"
        "aes = AESGCM(key)\nnonce = os.urandom(12)\n"
        "ct = nonce + aes.encrypt(nonce, plaintext, associated_data)",
        "JavaScript": "const crypto = require('crypto');\n"
        "const key = crypto.randomBytes(32);\nconst nonce = crypto.randomBytes(12);\n"
        "const c = crypto.createCipheriv('aes-256-gcm', key, nonce);\n"
        "const ct = Buffer.concat([c.update(pt), c.final()]);\nconst tag = c.getAuthTag();",
        "Java": 'Cipher c = Cipher.getInstance("AES/GCM/NoPadding");\n'
        "c.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, nonce));\n"
        "byte[] ct = c.doFinal(plaintext);",
        "*": "Use AES-256 in an AEAD mode (GCM) or ChaCha20-Poly1305 with a random nonce.",
    },
    "cipher-grover": {
        "*": "Use 256-bit symmetric keys (AES-256) to keep a 128-bit margin under Grover.",
    },
    "rng-weak": {
        "Python": "import secrets\ntoken = secrets.token_bytes(32)   # keys/nonces/salts\n"
        "num = secrets.randbelow(1_000_000)",
        "JavaScript": "const crypto = require('crypto');\n"
        "const token = crypto.randomBytes(32);\n"
        "const num = crypto.randomInt(0, 1_000_000);",
        "Java": "SecureRandom rng = new SecureRandom();\nbyte[] token = new byte[32];\n"
        "rng.nextBytes(token);",
        "*": "Use a CSPRNG (secrets / crypto.randomBytes / SecureRandom / RAND_bytes).",
    },
    "password-hash": {
        "Python": "from argon2 import PasswordHasher   # pip install argon2-cffi\n"
        "ph = PasswordHasher()\nhashed = ph.hash(password)\n"
        "ph.verify(hashed, password)",
        "JavaScript": "const argon2 = require('argon2');   // npm i argon2\n"
        "const hashed = await argon2.hash(password, { type: argon2.argon2id });\n"
        "await argon2.verify(hashed, password);",
        "Java": "// Spring Security\n"
        "PasswordEncoder enc = new Argon2PasswordEncoder(16, 32, 1, 1 << 14, 2);\n"
        "String hashed = enc.encode(password);",
        "*": "Hash passwords with Argon2id (or scrypt/bcrypt/PBKDF2) and a per-user salt.",
    },
    "auth-weak": {
        "Python": "import jwt\n"
        "# Never accept 'none'. Pin the algorithm and verify.\n"
        "claims = jwt.decode(token, public_key, algorithms=['EdDSA'],\n"
        "                    options={'require': ['exp', 'iss', 'aud']})",
        "JavaScript": "const jwt = require('jsonwebtoken');\n"
        "const claims = jwt.verify(token, publicKey, { algorithms: ['EdDSA'] });",
        "*": "Verify signatures, pin an asymmetric algorithm, reject 'none', validate exp/aud/iss.",
    },
    "iv-static": {
        "Python": "import os\nnonce = os.urandom(12)   # fresh per message, sent with ciphertext",
        "JavaScript": "const nonce = require('crypto').randomBytes(12); // fresh per message",
        "*": "Generate a fresh random IV/nonce per message from a CSPRNG; never hardcode it.",
    },
    "secret": {
        "Python": "import os\napi_key = os.environ['API_KEY']   # from a vault/KMS, not source",
        "*": "Load secrets from a vault/KMS at runtime; rotate any exposed value immediately.",
    },
    "protocol-weak": {
        "*": "Require TLS 1.3 (or 1.2 minimum) with AEAD, forward-secret suites; disable "
        "TLS 1.0/1.1 and static-RSA key exchange.",
    },
    "pk-encryption": {
        "Python": "# Post-quantum KEM (pip install liboqs-python)\n"
        "import oqs, os\nfrom cryptography.hazmat.primitives.ciphers.aead import AESGCM\n"
        "with oqs.KeyEncapsulation('ML-KEM-768') as kem:\n"
        "    public_key = kem.generate_keypair()\n"
        "    ciphertext, shared = kem.encap_secret(public_key)\n"
        "aes = AESGCM(shared[:32]); nonce = os.urandom(12)\n"
        "sealed = nonce + aes.encrypt(nonce, payload, None)   # KEM-DEM",
        "JavaScript": "// npm i @noble/post-quantum\n"
        "import { ml_kem768 } from '@noble/post-quantum/ml-kem';\n"
        "const { publicKey, secretKey } = ml_kem768.keygen();\n"
        "const { cipherText, sharedSecret } = ml_kem768.encapsulate(publicKey);\n"
        "// derive an AES-256-GCM key from sharedSecret",
        "Java": "// BouncyCastle 1.78+ provides ML-KEM (MLKEMKeyPairGenerator)\n"
        "// Use hybrid X25519 + ML-KEM-768 during transition.",
        "*": "Replace RSA/ECDH with ML-KEM-768 (FIPS 203) in hybrid mode (KEM-DEM).",
    },
    "key-exchange": {
        "*": "Replace ECDH/DH with ML-KEM-768 (FIPS 203); use the X25519MLKEM768 hybrid group in TLS.",
    },
    "signature": {
        "Python": "# Post-quantum signatures (pip install liboqs-python)\n"
        "import oqs\nwith oqs.Signature('ML-DSA-65') as signer:\n"
        "    public_key = signer.generate_keypair()\n"
        "    signature = signer.sign(message)",
        "JavaScript": "import { ml_dsa65 } from '@noble/post-quantum/ml-dsa';\n"
        "const { publicKey, secretKey } = ml_dsa65.keygen();\n"
        "const sig = ml_dsa65.sign(secretKey, message);",
        "*": "Replace RSA/ECDSA/EdDSA signatures with ML-DSA-65 (FIPS 204); SLH-DSA for roots of trust.",
    },
}


def secure_code(category: str | None, language: str | None) -> str | None:
    if not category:
        return None
    table = SECURE_CODE.get(category)
    if not table:
        return None
    if language and language in table:
        return table[language]
    return table.get("*")

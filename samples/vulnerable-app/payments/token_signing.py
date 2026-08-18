"""
Sample token signing (INTENTIONALLY VULNERABLE - for QuantumShield demo).
Demonstrates AST data-flow taint: a hardcoded key flows into a crypto sink.
"""
import hashlib
import hmac

# Hardcoded signing key (taint source)
SIGNING_SECRET = "s3cr3t-signing-key-do-not-ship-2023"


def sign(message: bytes) -> str:
    # SIGNING_SECRET flows into hmac.new here (taint sink), and the digestmod
    # is MD5 (weak hash).
    return hmac.new(SIGNING_SECRET.encode(), message, hashlib.md5).hexdigest()


def make_rsa():
    from Crypto.PublicKey import RSA

    return RSA.generate(1024)  # short + quantum-vulnerable

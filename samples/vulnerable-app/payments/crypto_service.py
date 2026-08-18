"""
Sample payment crypto module (INTENTIONALLY VULNERABLE - for QuantumShield demo).
Do not use any of this in production.
"""
import hashlib
import random
from Crypto.Cipher import DES
from Crypto.PublicKey import RSA


# Hardcoded secret - should come from a vault
API_SIGNING_KEY = "sk_live_9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c"


def generate_customer_keypair():
    # RSA is broken by Shor's algorithm on a quantum computer
    key = RSA.generate(2048)
    return key.export_key()


def hash_card_number(pan: str) -> str:
    # MD5 is collision-broken
    return hashlib.md5(pan.encode()).hexdigest()


def legacy_fingerprint(data: bytes) -> str:
    # SHA-1 is deprecated
    return hashlib.sha1(data).hexdigest()


def encrypt_pin(pin: str, key: bytes) -> bytes:
    # Single DES with a 56-bit key
    cipher = DES.new(key, DES.MODE_ECB)
    return cipher.encrypt(pin.ljust(8).encode())


def generate_transaction_token() -> int:
    # Non-cryptographic RNG used for a security token
    return random.randint(100000, 999999)

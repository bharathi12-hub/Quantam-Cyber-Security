// INTENTIONALLY VULNERABLE sample for QuantumShield demo.
const crypto = require('crypto');

// Math.random is not cryptographically secure
function generateSessionId() {
  return Math.random().toString(36).substring(2);
}

// MD5 for password hashing - broken
function hashPassword(pw) {
  return crypto.createHash('md5').update(pw).digest('hex');
}

// RC4 stream cipher - prohibited in TLS
function legacyEncrypt(key, data) {
  const cipher = crypto.createCipheriv('rc4', key, '');
  return Buffer.concat([cipher.update(data), cipher.final()]);
}

// RSA key generation - quantum vulnerable
function makeKeys() {
  return crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
}

const DB_PASSWORD = "P@ssw0rd_prod_2023!";

module.exports = { generateSessionId, hashPassword, legacyEncrypt, makeKeys };

// INTENTIONALLY VULNERABLE sample for QuantumShield demo.
const crypto = require('crypto');
const jwt = require('jsonwebtoken');

// Hardcoded, reused IV - breaks CBC/GCM security
const iv = "1234567890123456";

function encrypt(key, data) {
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  return Buffer.concat([cipher.update(data), cipher.final()]);
}

function verify(token) {
  // Signature verification disabled
  return jwt.verify(token, key, { algorithms: ['none'] });
}

module.exports = { encrypt, verify };

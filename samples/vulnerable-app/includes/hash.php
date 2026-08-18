<?php
// INTENTIONALLY VULNERABLE sample for QuantumShield demo.

// MD5 password hashing - broken.
function hash_password($pw) {
    return md5($pw);
}

// SHA-1 - deprecated.
function file_fingerprint($path) {
    return sha1_file($path);
}

// mt_rand is not cryptographically secure.
function make_token() {
    return mt_rand(100000, 999999);
}

// Hardcoded database credential.
$db_secret = "super_secret_password_123";
?>

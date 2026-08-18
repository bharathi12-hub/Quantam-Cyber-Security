package com.example.auth;

import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.util.Random;
import javax.crypto.Cipher;

// INTENTIONALLY VULNERABLE sample for QuantumShield demo.
public class TokenManager {

    // java.util.Random is predictable - not for security use
    private final Random rng = new Random();

    public byte[] issueSessionToken() {
        byte[] token = new byte[16];
        rng.nextBytes(token);
        return token;
    }

    public String digest(String input) throws Exception {
        // SHA-1 is collision-broken
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        return new String(md.digest(input.getBytes()));
    }

    public KeyPairGenerator buildKeyGen() throws Exception {
        // RSA keys are broken by Shor's algorithm
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        return kpg;
    }

    public Cipher legacyCipher() throws Exception {
        // Triple DES - deprecated by NIST
        return Cipher.getInstance("DESede/CBC/PKCS5Padding");
    }

    public String signWith() throws Exception {
        // ECDSA relies on ECDLP, broken by Shor
        MessageDigest.getInstance("SHA-256");
        return "SHA256withECDSA";
    }
}

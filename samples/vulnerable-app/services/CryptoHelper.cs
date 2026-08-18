// INTENTIONALLY VULNERABLE sample for QuantumShield demo.
using System;
using System.Security.Cryptography;

namespace Example.Services
{
    public static class CryptoHelper
    {
        // RSA - broken by Shor's algorithm.
        public static RSA NewKey() => new RSACryptoServiceProvider(2048);

        // SHA-1 is collision-broken.
        public static byte[] Fingerprint(byte[] data)
        {
            using var sha1 = SHA1.Create();
            return sha1.ComputeHash(data);
        }

        // Triple DES is deprecated.
        public static SymmetricAlgorithm LegacyCipher() => new TripleDESCryptoServiceProvider();

        // System.Random is not cryptographically secure.
        public static int WeakNonce() => new Random().Next();
    }
}

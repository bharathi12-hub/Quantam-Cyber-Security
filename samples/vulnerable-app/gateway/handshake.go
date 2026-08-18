// INTENTIONALLY VULNERABLE sample for QuantumShield demo.
package gateway

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	mrand "math/rand"
)

// RSA key generation - broken by Shor's algorithm.
func newRSAKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

// ECDSA over P-256 - elliptic-curve discrete log, broken by Shor.
func newECDSAKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// MD5 digest - collision broken.
func fingerprint(b []byte) string {
	sum := md5.Sum(b)
	return fmt.Sprintf("%x", sum)
}

// math/rand is not cryptographically secure.
func weakNonce() int {
	return mrand.Intn(1 << 30)
}

/* INTENTIONALLY VULNERABLE sample for QuantumShield demo. */
#include <openssl/rsa.h>
#include <openssl/md5.h>
#include <openssl/des.h>
#include <stdlib.h>
#include <string.h>

/* RSA key generation - broken by Shor's algorithm. */
RSA *make_rsa_key(void) {
    return RSA_generate_key(2048, RSA_F4, NULL, NULL);
}

/* MD5 digest - collision broken. */
void digest(const unsigned char *in, size_t n, unsigned char out[16]) {
    MD5(in, n, out);
}

/* Single DES encryption - 56-bit key. */
void encrypt_block(DES_cblock *in, DES_cblock *out, DES_key_schedule *ks) {
    DES_ecb_encrypt(in, out, ks, DES_ENCRYPT);
}

/* rand() is not a CSPRNG. */
unsigned int weak_token(void) {
    srand(1234);
    return (unsigned int) rand();
}

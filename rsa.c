#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "rsa.h"
#include "prf.h"


/**
 * @file rsa.c
 * @brief RSA encryption and decryption functions.
 *
 * This file contains functions for RSA key generation, encryption, and decryption.
 * It also includes functions for reading and writing RSA keys from and to files.
 */



#define ISPRIME(x) mpz_probab_prime_p(x,10)
/** takes a multiple precision integer and returns 2 if it is definitely prime, 1 if it is probably prime, 0 if it is
 * definitely composite. */

/* NOTE: a random composite surviving 10 Miller-Rabin tests is extremely
 * unlikely.  See Pomerance et al.:
 * http://www.ams.org/mcom/1993-61-203/S0025-5718-1993-1189518-9/
 * */

#define NEWZ(x) mpz_t x; mpz_init(x) /** declare and initialize a new mpz_t */
#define BYTES2Z(x, buf, len) mpz_import(x,len,-1,1,0,0,buf) /** import a byte array into an mpz_t */
#define Z2BYTES(buf, len, x) mpz_export(buf,&len,-1,1,0,0,x) /** export an mpz_t into a byte array */


/* utility functions to read/write mpz_t with streams: */
/**
 * @brief Writes a multiple precision integer to a file.
 *
 * @param f Pointer to the file to write to.
 * @param x The multiple precision integer to write.
 *
 * Writes a multiple precision integer to a file. Allocates buffer at least size of integer in bytes. Exports integer to
 * buffer and writes buffer to file. Also writes size of integer before integer to allow for correct reading of integer.
 * Buffer is cleared and freed to prevent sensitive data from remaining in memory.
 *
 * @return This function returns 0 on success.
 */
int zToFile(FILE *f, mpz_t x) {
    size_t i, len = mpz_size(x) * sizeof(mp_limb_t); /* len may overestimate number of bytes required. */
    unsigned char *buf = malloc(len);
    Z2BYTES(buf, len, x);
    /* force little endian-ness: */
    for (i = 0; i < 8; i++) {
        unsigned char b = (len >> 8 * i) % 256;
        fwrite(&b, 1, 1, f);
    }
    fwrite(buf, 1, len, f);
    memset(buf, 0, len);
    free(buf);
    return 0;
}

/**
 * @brief Reads a multiple precision integer from a file.
 *
 * @param f Pointer to the file to read from.
 * @param x The multiple precision integer to store the read value.
 *
 * Reads multiple precision integer from file. Teads size integer, allocates a buffer of appropriate size, then reads
 * integer into buffer and imports buffer integer. Buffer cleared and freed to prevent sensitive data from remaining.
 *
 * @return This function returns 0 on success.
 */
int zFromFile(FILE *f, mpz_t x) {
    size_t i, len = 0;
    /* force little endian-ness: */
    for (i = 0; i < 8; i++) {
        unsigned char b;
        /* XXX error check this; return meaningful value. */
        fread(&b, 1, 1, f);
        len += (b << 8 * i);
    }
    unsigned char *buf = malloc(len);
    fread(buf, 1, len, f);
    BYTES2Z(x, buf, len);
    memset(buf, 0, len);
    free(buf);
    return 0;
}


/**
 * @brief Generates an RSA key pair.
 *
 * @param keyBits The size of the key in bits. This should be a multiple of 16 to avoid rounding.
 * @param K A pointer to an RSA_KEY structure where the generated key pair will be stored.
 *
 * This function generates an RSA key pair. The key size is specified by `keyBits`. The generated key pair is stored in the RSA_KEY structure pointed to by `K`.
 *
 * The function first initializes the RSA_KEY structure using the `rsa_initKey` function. It then generates two prime numbers `p` and `q` each of size `keyBits/16` bytes. These primes are generated by repeatedly generating random bytes and checking if the resulting number is prime using the `ISPRIME` macro. This process is repeated until two prime numbers are found.
 *
 * The function then computes `n = p * q` and `t = (p-1) * (q-1)`. The public exponent `e` is set to a small prime number (65537). The private exponent `d` is computed as `e^-1 mod t` using the `mpz_invert` function.
 *
 * If `e` has no inverse modulo `t`, the function returns -1. This should not happen if `p` and `q` are primes.
 *
 * @return This function returns 0 on success.
 */
int rsa_keyGen(size_t keyBits, RSA_KEY *K) {
    rsa_initKey(K);
    NEWZ(t);
    unsigned char buffer[keyBits / 16]; // Buffer for random bytes

    do { // Generate prime p
        randBytes(buffer, keyBits / 16);
        BYTES2Z(K->p, buffer, keyBits / 16);
    } while (!ISPRIME(K->p));

    do { // Generate prime q, different from p
        randBytes(buffer, keyBits / 16);
        BYTES2Z(K->q, buffer, keyBits / 16);
    } while (!ISPRIME(K->q) || mpz_cmp(K->p, K->q) == 0);

    mpz_mul(K->n, K->p, K->q);    // Compute n = p * q

    mpz_sub_ui(t, K->p, 1);
    mpz_sub_ui(K->q, K->q, 1);
    mpz_mul(t, t, K->q);    // Compute t = (p-1) * (q-1)

    mpz_set_ui(K->e, 65537);    // Set e to a small prime number

    // Compute d = e^-1 mod t
    if (mpz_invert(K->d, K->e, t) == 0) {
        mpz_clear(t);
        return -1; // e has no inverse mod t, should not happen if p and q are primes
    }

    mpz_clear(t);
    return 0;
}

/**
 * @brief Encrypts a message using RSA.
 *
 * @param outBuf Pointer to the buffer where the encrypted message will be stored.
 * @param inBuf Pointer to the buffer containing the message to be encrypted.
 * @param len Length of the message to be encrypted.
 * @param K Pointer to the RSA_KEY structure containing the public key.
 *
 * This function encrypts a message using RSA. The message to be encrypted is stored in the buffer pointed to by
 * `inBuf` and has length `len`. The encrypted message is stored in the buffer pointed to by `outBuf`.
 *
 * The message is first interpreted as an integer. If the integer is greater than `n`, the function returns 0.
 * Otherwise, the message is encrypted using the public key `K` and the result is stored in `outBuf`.
 *
 * @return This function returns the number of bytes written to `outBuf`.
 */
size_t rsa_encrypt(unsigned char *outBuf, unsigned char *inBuf, size_t len, RSA_KEY *K) {
    NEWZ(m);
    NEWZ(c); // m: message as integer, c: encrypted message as integer
    BYTES2Z(m, inBuf, len); // convert input buffer to mpz_t m

    // if m >= n, cannot properly decrypt cipher because m^e mod n <= n not m.
    if (mpz_cmp(m, K->n) >= 0) {
        mpz_clear(m);
        mpz_clear(c);
        return 0;
    }

    mpz_powm(c, m, K->e, K->n); // c = m^e mod n
    size_t outLen = mpz_sizeinbase(c, 256); // get size of c in bytes
    Z2BYTES(outBuf, outLen, c); // convert c to byte array
    mpz_clear(m);
    mpz_clear(c);

    return outLen;
}

/**
 * @brief Decrypts a message using RSA.
 *
 * @param outBuf Pointer to the buffer where the decrypted message will be stored.
 * @param inBuf Pointer to the buffer containing the message to be decrypted.
 * @param len Length of the message to be decrypted.
 * @param K Pointer to the RSA_KEY structure containing the private key.
 *
 * This function decrypts a message using RSA. The message to be decrypted is stored in the buffer pointed to by
 * `inBuf` and has length `len`. The decrypted message is stored in the buffer pointed to by `outBuf`.
 *
 * The message is first interpreted as an integer. The message is then decrypted using the private key `K` and the
 * result is stored in `outBuf`.
 *
 * @return This function returns the number of bytes written to `outBuf`.
 */
size_t rsa_decrypt(unsigned char *outBuf, unsigned char *inBuf, size_t len, RSA_KEY *K) {
    NEWZ(c);
    NEWZ(m); // c: encrypted message as integer, m: decrypted message as integer
    BYTES2Z(c, inBuf, len); // convert input buffer to mpz_t c
    mpz_powm(m, c, K->d, K->n); // m = c^d mod n
    size_t outLen = mpz_sizeinbase(m, 256); // get size of m in bytes
    Z2BYTES(outBuf, outLen, m); // convert m to byte array
    mpz_clear(c);
    mpz_clear(m);

    return outLen;
}


size_t rsa_numBytesN(RSA_KEY *K) {
    return mpz_size(K->n) * sizeof(mp_limb_t);
}

/**
 * @brief Initializes an RSA key.
 *
 * @param K Pointer to the RSA_KEY to initialize.
 *
 * Initializes an RSA key by setting all members to 0. RSA key consists of five fields:
 * - p: One of the two prime numbers used to generate keys.
 * - q: Other prime number used to generate keys.
 * - n: Modulus for both the public and private keys, product of p and q.
 * - e: Public exponent used in encryption process.
 * - d: Private exponent used in decryption process.
 *
 * @return This function returns 0 on success.
 */
int rsa_initKey(RSA_KEY *K) {
    mpz_init(K->d);
    mpz_set_ui(K->d, 0);
    mpz_init(K->e);
    mpz_set_ui(K->e, 0);
    mpz_init(K->p);
    mpz_set_ui(K->p, 0);
    mpz_init(K->q);
    mpz_set_ui(K->q, 0);
    mpz_init(K->n);
    mpz_set_ui(K->n, 0);
    return 0;
}

int rsa_writePublic(FILE *f, RSA_KEY *K) {
    /* only write n,e */
    zToFile(f, K->n);
    zToFile(f, K->e);
    return 0;
}

int rsa_writePrivate(FILE *f, RSA_KEY *K) {
    zToFile(f, K->n);
    zToFile(f, K->e);
    zToFile(f, K->p);
    zToFile(f, K->q);
    zToFile(f, K->d);
    return 0;
}

int rsa_readPublic(FILE *f, RSA_KEY *K) {
    rsa_initKey(K); /* will set all unused members to 0 */
    zFromFile(f, K->n);
    zFromFile(f, K->e);
    return 0;
}

int rsa_readPrivate(FILE *f, RSA_KEY *K) {
    rsa_initKey(K);
    zFromFile(f, K->n);
    zFromFile(f, K->e);
    zFromFile(f, K->p);
    zFromFile(f, K->q);
    zFromFile(f, K->d);
    return 0;
}

int rsa_shredKey(RSA_KEY *K) {
    /* clear memory for key. */
    mpz_t *L[5] = {&K->d, &K->e, &K->n, &K->p, &K->q};
    size_t i;
    for (i = 0; i < 5; i++) {
        size_t nLimbs = mpz_size(*L[i]);
        if (nLimbs) {
            memset(mpz_limbs_write(*L[i], nLimbs), 0, nLimbs * sizeof(mp_limb_t));
            mpz_clear(*L[i]);
        }
    }
    /* NOTE: a quick look at the gmp source reveals that the return of
     * mpz_limbs_write is only different from the existing limbs when
     * the number requested is larger than the allocation (which is
     * of course larger than mpz_size(X)) */
    return 0;
}

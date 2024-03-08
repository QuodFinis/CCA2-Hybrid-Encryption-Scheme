#include "prf.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <gmp.h>

/**
 * @file prf.c
 * @brief Pseudo-Random Function (PRF) based on HMAC.
 *
 * This code implements a Pseudo-Random Function (PRF) based on HMAC.
 * It's a simple implementation and not particularly efficient.
 * It's intended for use in the RSA Key Encapsulation Mechanism (KEM),
 * and is not suitable for standalone cryptographic applications.
 */

#define BLOCK_LEN 64 /**< Block length for SHA512 */
static mpz_t rcount; /**< GMP multiple precision integer to keep track of how many blocks have been generated */
static unsigned char rkey[BLOCK_LEN]; /**< Key for the PRF, an array of length BLOCK_LEN of unsigned char (bytes) */
static int prf_initialized; /**< Flag to check if the PRF has been initialized. Static variables in C default to 0. */
#define VERY_YES 9191919 /**< A constant used to indicate that the PRF has been initialized */


int setSeed(unsigned char *entropy, size_t len) {
    /**
     * @brief Initialize the PRF with a seed.
     *
     * @param entropy Pointer to an array of bytes to use as a seed.
     * @param len Length of the seed.
     *
     * If entropy is NULL, then len is ignored and the PRF is seeded with 32 bytes from /dev/urandom.
     * Otherwise, the PRF is seeded with the bytes in entropy.
     *
     * If entropy is not NULL, then len must be at least 32 and PRF is initialized to the state where
     * it has generated 0 blocks.
     *
     * If the PRF has already been initialized, then this function will reinitialize the PRF.
     *
     * @return This function returns 0 on success, and -1 on failure.
     */
    if (prf_initialized != VERY_YES) mpz_init(rcount);
    mpz_set_ui(rcount, 1);
    int callFree = 0; /* Flag to indicate whether we need to free the entropy array */

    if (!entropy) { /* If entropy is NULL, generate a random seed */
        callFree = 1;
        len = 32;
        entropy = malloc(len);
        FILE *frand = fopen("/dev/urandom", "rb"); /* Open /dev/urandom to generate random bytes */
        fread(entropy, 1, len, frand);
        fclose(frand);
    }

    SHA512(entropy, len, rkey); /* Hash the entropy using SHA512 and store the result in rkey */
    if (callFree) free(entropy);
    prf_initialized = VERY_YES; /* Set initialized flag to VERY_YES */
    return 0;
}

int randBytes(unsigned char *outBuf, size_t len) {
    /**
     * @brief Generate sequence of pseudo-random bytes using HMAC-SHA51 using seed from setSeed.
     *
     * @param outBuf Pointer to an array of bytes to store the pseudo-random bytes.
     * @param len Length of the pseudo-random bytes to generate.
     *
     * It first checks if the PRF has been initialized by checking the prf_initialized flag. If it hasn't been
     * initialized, it calls setSeed with entropy set to NULL and len set to 0, which will generate a random seed
     *
     * Calculate the number of full blocks of bytes it needs to generate. Each block is BLOCK_LEN bytes long, which is
     * the output size of the SHA512 hash function.
     *
     * Generate each block of bytes using HMAC-SHA512 and store the result in outBuf. If the requested number of bytes
     * (len) is not a multiple of BLOCK_LEN, generates one more block and copies necessary bytes to outBuf.
     *
     * @return This function returns 0 on success, and -1 on failure.
 */
    if (prf_initialized != VERY_YES) setSeed(0, 0); /* If the PRF has not been initialized, initialize it */
    size_t nBlocks = len / BLOCK_LEN; /* Number of blocks to generate */
    size_t i;

    for (i = 0; i < nBlocks; i++) {
        /* Generate a block using HMAC-SHA512 with rkey as the key and rcount as the data */
        HMAC(EVP_sha512(), rkey, BLOCK_LEN, (unsigned char *) mpz_limbs_read(rcount),
             sizeof(mp_limb_t) * mpz_size(rcount), outBuf, NULL);
        mpz_add_ui(rcount, rcount, 1); /* Increment the counter */
        outBuf += BLOCK_LEN; /* Move the pointer to the next block */
    }

    /* Handle the final block if len is not a multiple of BLOCK_LEN */
    unsigned char fblock[BLOCK_LEN];
    if (len % BLOCK_LEN) {
        HMAC(EVP_sha512(), rkey, BLOCK_LEN, (unsigned char *) mpz_limbs_read(rcount),
             sizeof(mp_limb_t) * mpz_size(rcount), fblock, NULL);
        mpz_add_ui(rcount, rcount, 1);
        memcpy(outBuf, fblock, len % BLOCK_LEN);
    }

    return 0;
}
#include "ske.h"
#include "prf.h"
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h> /* memcpy */
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>

#ifdef LINUX
#define MMAP_SEQ MAP_PRIVATE|MAP_POPULATE
#else
#define MMAP_SEQ MAP_PRIVATE
#endif

/* NOTE: since we use counter mode, we don't need padding, as the
 * ciphertext length will be the same as that of the plaintext.
 * Here's the message format we'll use for the ciphertext:
 * +------------+--------------------+----------------------------------+
 * | 16 byte IV | C = AES(plaintext) | HMAC(IV|C) (32 bytes for SHA256) |
 * +------------+--------------------+----------------------------------+
 * */

/* we'll use hmac with sha256, which produces 32 byte output */
#define HM_LEN 32
#define KDF_KEY "qVHqkOVJLb7EolR9dsAMVwH1hRCYVx#I"
/* need to make sure KDF is orthogonal to other hash functions, like
 * the one used in the KDF, so we use hmac with a key. */


/**
 * @brief Calculate the output length for symmetric key encryption.
 *
 * @param inputLen Length of the input plaintext.
 *
 * This function calculates the length of the output ciphertext for symmetric key encryption.
 * The output length is the sum of the AES block size, the input plaintext length, and the HMAC length.
 *
 * @return This function returns the calculated output length.
 */
size_t ske_getOutputLen(size_t inputLen) {
    return AES_BLOCK_SIZE + inputLen + HM_LEN;
}


/**
 * @brief Generate a symmetric key.
 *
 * @param K Pointer to the SKE_KEY structure where the generated keys will be stored.
 * @param entropy Pointer to the buffer containing entropy. If NULL, a random key is generated.
 * @param entLen Length of the entropy buffer.
 *
 * This function generates a symmetric key for encryption and decryption. If entropy is provided,
 * it applies a Key Derivation Function (KDF) to it to get the keys. If entropy is not provided,
 * it generates a random key.
 *
 * @return This function returns 0 on success.
 */
int ske_keyGen(SKE_KEY *K, unsigned char *entropy, size_t entLen) {
    if (entropy) {
        // Apply HMAC-SHA256 with KDF_KEY to the entropy to get the HMAC
        HMAC(EVP_sha512(), KDF_KEY, strlen(KDF_KEY), entropy, entLen,
             K->hmacKey, NULL);
        HMAC(EVP_sha512(), KDF_KEY, strlen(KDF_KEY), entropy, entLen,
             K->aesKey, NULL);
    } else { // generate random key
        randBytes(K->hmacKey, KLEN_SKE);
        randBytes(K->aesKey, KLEN_SKE);
    }

    return 0;
}

/**
 * @brief Encrypts a message using symmetric key encryption.
 *
 * @param outBuf Pointer to the buffer where the ciphertext will be stored.
 * @param inBuf Pointer to the buffer containing the plaintext to be encrypted.
 * @param len Length of the plaintext to be encrypted.
 * @param K Pointer to the SKE_KEY structure containing the encryption key.
 * @param IV Pointer to the buffer containing the initialization vector. If NULL, a random IV is generated.
 *
 * This function encrypts a message using symmetric key encryption. The function uses AES-256 in counter mode to encrypt
 * the plaintext. The IV is used to initialize the counter. The IV is concatenated with the ciphertext, and the HMAC of
 * the IV and the ciphertext is calculated and concatenated with the IV and ciphertext.
 *
 * If IV is NULL, a random IV is generated. The IV is concatenated with the ciphertext, and the HMAC of the IV and the
 * ciphertext is calculated and concatenated with the IV and ciphertext.
 *
 * @return This function returns the number of bytes written to `outBuf`.
 */
size_t ske_encrypt(unsigned char *outBuf, unsigned char *inBuf, size_t len, SKE_KEY *K, unsigned char *IV) {
    if (!IV) { // if IV is not given, generate a random IV
        unsigned char *entropy = malloc(32);
        setSeed(entropy, 32);
        IV = malloc(16);
        randBytes(IV, 16);
        free(entropy);
    }

    // Write IV to output buffer
    memcpy(outBuf, IV, 16);

    // Encrypt the plaintext
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, K->aesKey, IV);
    int outLen;
    EVP_EncryptUpdate(ctx, outBuf + 16, &outLen, inBuf, len);
    EVP_EncryptFinal_ex(ctx, outBuf + 16 + outLen, &outLen);
    EVP_CIPHER_CTX_free(ctx);

    // Calculate HMAC (IV|C) and write it to output buffer
    unsigned char *hmac = HMAC(EVP_sha256(), K->hmacKey, KLEN_SKE, outBuf, len + 16, NULL, NULL);
    memcpy(outBuf + 16 + len, hmac, HM_LEN);

    return 16 + len + HM_LEN;
}

/**
 * @brief Decrypts a message using symmetric key encryption.
 *
 * @param outBuf Pointer to the buffer where the plaintext will be stored.
 * @param inBuf Pointer to the buffer containing the ciphertext to be decrypted.
 * @param len Length of the ciphertext to be decrypted.
 * @param K Pointer to the SKE_KEY structure containing the decryption key.
 *
 * This function decrypts a message using symmetric key encryption. The function uses AES-256 in counter mode to decrypt
 * the ciphertext. The IV is extracted from the ciphertext and used to initialize the counter. The HMAC of the IV and the
 * ciphertext is calculated and compared with the HMAC in the ciphertext. If the HMACs match, the ciphertext is decrypted.
 * If the HMACs do not match, the function returns -1 to indicate that the ciphertext is invalid.
 *
 * @return This function returns the number of bytes written to `outBuf` if the decryption is successful, or -1 if the
 * ciphertext is invalid.
 */
size_t ske_decrypt(unsigned char *outBuf, unsigned char *inBuf, size_t len, SKE_KEY *K) {
    // Extract IV, HMAC, and ciphertext from input buffer
    unsigned char *IV = inBuf;
    unsigned char *hmac = inBuf + len - HM_LEN;
    unsigned char *ciphertext = inBuf + 16;
    size_t ciphertext_len = len - 16 - HM_LEN;

    // Calculate HMAC of IV and ciphertext
    unsigned char *calculated_hmac = HMAC(EVP_sha256(), K->hmacKey, KLEN_SKE, inBuf,
                                          len - HM_LEN, NULL, NULL);

    // Compare calculated HMAC with extracted HMAC, if HMACs don't match, ciphertext is invalid
    if (memcmp(hmac, calculated_hmac, HM_LEN) != 0) {
        return -1;
    }

    // Decrypt ciphertext
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, K->aesKey, IV);
    int outLen;
    EVP_DecryptUpdate(ctx, outBuf, &outLen, ciphertext, ciphertext_len);
    EVP_DecryptFinal_ex(ctx, outBuf + outLen, &outLen);
    EVP_CIPHER_CTX_free(ctx);

    return outLen; // number of bytes written
}

/**
 * @brief Encrypts a file using symmetric key encryption.
 *
 * @param fnout Pointer to the filename where the ciphertext will be stored.
 * @param fnin Pointer to the filename containing the plaintext to be encrypted.
 * @param K Pointer to the SKE_KEY structure containing the encryption key.
 * @param IV Pointer to the buffer containing the initialization vector. If NULL, a random IV is generated.
 * @param offset_out Offset to begin writing to the output file. Set to 0 to erase the file and write it from scratch.
 *
 * This function encrypts a file using symmetric key encryption. The function reads the plaintext from the file specified
 * by `fnin`, encrypts it using the `ske_encrypt` function, and writes the ciphertext to the file specified by `fnout`.
 * If `offset_out` is set to 0, the function erases the file and writes the ciphertext from scratch. If `offset_out` is
 * greater than 0, the function writes the ciphertext to the file starting at the specified offset.
 *
 * @return This function returns the number of bytes written to the output file.
 */
size_t ske_encrypt_file(const char *fnout, const char *fnin, SKE_KEY *K, unsigned char *IV, size_t offset_out) {
    /* TODO: write this.  Hint: mmap. */
    return 0;
}

/**
 * @brief Decrypts a file using symmetric key encryption.
 *
 * @param fnout Pointer to the filename where the plaintext will be stored.
 * @param fnin Pointer to the filename containing the ciphertext to be decrypted.
 * @param K Pointer to the SKE_KEY structure containing the decryption key.
 * @param offset_in Offset to begin reading the input file.
 *
 * This function decrypts a file using symmetric key encryption. The function reads the ciphertext from the file specified
 * by `fnin`, decrypts it using the `ske_decrypt` function, and writes the plaintext to the file specified by `fnout`.
 * If `offset_in` is greater than 0, the function reads the ciphertext from the file starting at the specified offset.
 *
 * @return This function returns the number of bytes written to the output file.
 */
size_t ske_decrypt_file(const char *fnout, const char *fnin, SKE_KEY *K, size_t offset_in) {
    /* TODO: write this. */
    return 0;
}

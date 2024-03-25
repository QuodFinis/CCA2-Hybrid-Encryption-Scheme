/* kem-enc.c
 * A simple encryption utility providing CCA2 security.
 * It is based on the KEM/DEM hybrid model. */

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <fcntl.h>
#include <openssl/sha.h>
#include <unistd.h>

#include "ske.h"
#include "rsa.h"
#include "prf.h"

// Usage message for the command-line interface
static const char *usage =
        "Usage: %s [OPTIONS]...\n"
        "Encrypt or decrypt data.\n\n"
        "   -i,--in     FILE   read input from FILE.\n"
        "   -o,--out    FILE   write output to FILE.\n"
        "   -k,--key    FILE   the key.\n"
        "   -r,--rand   FILE   use FILE to seed RNG (defaults to /dev/urandom).\n"
        "   -e,--enc           encrypt (this is the default action).\n"
        "   -d,--dec           decrypt.\n"
        "   -g,--gen    FILE   generate new key and write to FILE{,.pub}\n"
        "   -b,--BITS   NBITS  length of new key (NOTE: this corresponds to the\n"
        "                      RSA key; the symmetric key will always be 256 bits).\n"
        "                      Defaults to %lu.\n"
        "   --help             show this message and exit.\n";

#define FNLEN 255

// Enum for the modes of operation: encryption, decryption, and key generation
enum modes {
    ENC,
    DEC,
    GEN
};

/* Let SK denote the symmetric key.  Then to format ciphertext, we
 * simply concatenate:
 * +------------+----------------+
 * | RSA-KEM(X) | SKE ciphertext |
 * +------------+----------------+
 * NOTE: reading such a file is only useful if you have the key,
 * and from the key you can infer the length of the RSA ciphertext.
 * We'll construct our KEM as KEM(X) := RSA(X)|H(X), and define the
 * key to be SK = KDF(X).  Naturally H and KDF need to be "orthogonal",
 * so we will use different hash functions:  H := SHA256, while
 * KDF := HMAC-SHA512, where the key to the hmac is defined in ske.c
 * (see KDF_KEY).
 * */

#define HASHLEN 32 /* for sha256 */


/**
 * @brief Encrypt a file using the RSA-KEM/DEM hybrid model.
 * @param fnOut Path to the output file.
 * @param fnIn path to the input file.
 * @param K public key.
 *
 * This function encrypts the file `fnIn` using the RSA-KEM/DEM hybrid model. It generates a random symmetric key,
 * encrypts it using the public key `K`, and then uses the symmetric key to encrypt the file. The encrypted file is
 * written to `fnOut`.
 *
 * The RSA-KEM/DEM hybrid model is a combination of Key Encapsulation Mechanism (KEM) and Data Encapsulation Mechanism (DEM).
 * In this model, the symmetric key is randomly generated and encrypted using RSA (KEM part). This encrypted symmetric key
 * is then concatenated with the hash of the symmetric key. The actual data is encrypted using the symmetric key (DEM part).
 *
 * @return This function returns 0 on success and non-zero on failure.
 */
int kem_encrypt(const char *fnOut, const char *fnIn, RSA_KEY *K) {
    size_t keyLen = rsa_numBytesN(K);    // Generate ephemeral key
    unsigned char *ephemKey = malloc(keyLen);

    randBytes(ephemKey, keyLen);    // Generate random key
    SKE_KEY SK;
    ske_keyGen(&SK, ephemKey, keyLen);

    size_t len = rsa_numBytesN(K);    // Encrypt ephemeral key
    unsigned char *x = malloc(len);

    randBytes(x, len);
    ske_keyGen(&SK, x, len);

    size_t encapLen = len + HASHLEN;    // Encapsulate
    unsigned char *encap = malloc(encapLen);

    rsa_encrypt(encap, x, len, K);    // Encrypt

    unsigned char *h = malloc(HASHLEN);    // Hash
    SHA256(x, len, h);
    memcpy(encap + len, h, HASHLEN);    // Append hash

    int fdout = open(fnOut, O_CREAT | O_RDWR, S_IRWXU);    // Write to file
    write(fdout, encap, encapLen);
    close(fdout);

    ske_encrypt_file(fnOut, fnIn, &SK, NULL, encapLen);    // Encrypt file

    free(x);
    free(encap);
    free(h);
    return 0;
}

/**
 * @brief Decrypt a file using the RSA-KEM/DEM hybrid model.
 * @param fnOut Path to the output file.
 * @param fnIn path to the input file.
 * @param K private key.
 *
 * This function decrypts the file `fnIn` using the RSA-KEM/DEM hybrid model. It reads the encrypted symmetric key from
 * the file, decrypts it using the private key `K`, and then uses the symmetric key to decrypt the file. The decrypted file
 * is written to `fnOut`.
 *
 * The RSA-KEM/DEM hybrid model is a combination of Key Encapsulation Mechanism (KEM) and Data Encapsulation Mechanism (DEM).
 * In this model, the symmetric key is read from the file and decrypted using RSA (KEM part). The actual data is decrypted
 * using the symmetric key (DEM part).
 *
 * @return This function returns 0 on success and non-zero on failure.
 */
int kem_decrypt(const char *fnOut, const char *fnIn, RSA_KEY *K) {
    size_t keyLen = rsa_numBytesN(K);    // Generate ephemeral key
    unsigned char *ephemKey = malloc(keyLen);

    int fdin = open(fnIn, O_RDONLY);    // Generate random key

    size_t encapLen = lseek(fdin, 0, SEEK_END);    // Read encapsulated key
    lseek(fdin, 0, SEEK_SET);

    unsigned char *encap = malloc(encapLen);    // Read encapsulated key
    read(fdin, encap, encapLen);
    close(fdin);

    size_t len = rsa_numBytesN(K);    // Decrypt

    unsigned char *x = malloc(len);    // Check if the file is too short
    memcpy(x, encap, len);

    unsigned char *h = malloc(HASHLEN);    // Hash
    memcpy(h, encap + len, HASHLEN);
    unsigned char *h2 = malloc(HASHLEN);    // Check hash
    SHA256(x, len, h2);
    rsa_decrypt(x, x, len, K);    // Check if the hash is correct

    SKE_KEY SK;    // Generate key
    ske_keyGen(&SK, x, len);

    ske_decrypt_file(fnOut, fnIn, &SK, encapLen);    // Decrypt file

    free(x);
    free(h);
    free(h2);
    free(encap);

    return 0;
}

/**
 * @brief Encrypt a file using a given key.
 * @param fnOut Path to the output file.
 * @param fnIn Path to the input file.
 * @param fnKey Path to the key file.
 * @return int This function returns 0 on success and non-zero on failure.
 *
 * This function encrypts the file `fnIn` using the key stored in `fnKey`. The encrypted file is written to `fnOut`.
 */
int encrypt(char *fnOut, char *fnIn, char *fnKey) {
    FILE *keyFile = fopen(fnKey, "r");    // Open the key file
    printf("Key file: %s\n", fnKey);

    if (keyFile == NULL) {    // Check if the key file exists
        printf("Key file does not exist\n");
        return -1;
    }

    RSA_KEY K;    // Read the public key from the key file
    rsa_readPublic(keyFile, &K);

    kem_encrypt(fnOut, fnIn, &K);    // Encrypt the input file and write the result to the output file

    rsa_shredKey(&K);    // Shred the key for security

    fclose(keyFile);    // Close the key file

    return 0;
}

/**
 * @brief Generate a new RSA key pair.
 * @param fnOut Path to the output file for the private key.
 * @param nBits The number of bits for the new key.
 * @return int This function returns 0 on success and non-zero on failure.
 *
 * This function generates a new RSA key pair with `nBits` bits. The private key is written to `fnOut` and the public key is written to `fnOut.pub`.
 */
int generate(char *fnOut, size_t nBits) {
    RSA_KEY K;    // Initialize the RSA key structure

    char *fPub = malloc(strlen(fnOut) + 5);    // Create a new file name with .pub extension for the public key
    strcpy(fPub, fnOut);
    strcat(fPub, ".pub");

    FILE *outPrivate = fopen(fnOut, "w");    // Open the output files for the private and public keys
    FILE *outPublic = fopen(fPub, "w");

    rsa_keyGen(nBits, &K);    // Generate the RSA key pair

    rsa_writePrivate(outPrivate, &K);    // Write the private and public keys to their respective files
    rsa_writePublic(outPublic, &K);

    fclose(outPrivate);    // Close the output files
    fclose(outPublic);

    rsa_shredKey(&K);    // Shred the key for security

    free(fPub);    // Free the memory allocated for the public key file name

    return 0;
}

/**
 * @brief Decrypt a file using a given key.
 * @param fnOut Path to the output file.
 * @param fnIn Path to the input file.
 * @param fnKey Path to the key file.
 * @return int This function returns 0 on success and non-zero on failure.
 *
 * This function decrypts the file `fnIn` using the key stored in `fnKey`. The decrypted file is written to `fnOut`.
 */
int decrypt(char *fnOut, char *fnIn, char *fnKey) {
    FILE *privateKey = fopen(fnKey, "r");    // Open the key file
    printf("Key file: %s\n", fnKey);

    if (privateKey == NULL) {    // Check if the key file exists
        printf("Key file does not exist\n");
        return -1;
    }

    RSA_KEY K;    // Read the private key from the key file
    rsa_readPrivate(privateKey, &K);

    fclose(privateKey);    // Close the key file

    kem_decrypt(fnOut, fnIn, &K); // Decrypt the input file and write the result to the output file

    rsa_shredKey(&K);    // Shred the key for security

    return 0;
}

int main(int argc, char *argv[]) {
    /* define long options */
    static struct option long_opts[] = {
            {"in",   required_argument, 0, 'i'},
            {"out",  required_argument, 0, 'o'},
            {"key",  required_argument, 0, 'k'},
            {"rand", required_argument, 0, 'r'},
            {"gen",  required_argument, 0, 'g'},
            {"bits", required_argument, 0, 'b'},
            {"enc",  no_argument,       0, 'e'},
            {"dec",  no_argument,       0, 'd'},
            {"help", no_argument,       0, 'h'},
            {0, 0,                      0, 0}
    };
    /* process options: */
    char c;
    int opt_index = 0;
    char fnRnd[FNLEN + 1] = "/dev/urandom";
    fnRnd[FNLEN] = 0;
    char fnIn[FNLEN + 1];
    char fnOut[FNLEN + 1];
    char fnKey[FNLEN + 1];
    memset(fnIn, 0, FNLEN + 1);
    memset(fnOut, 0, FNLEN + 1);
    memset(fnKey, 0, FNLEN + 1);
    int mode = ENC;
    // size_t nBits = 2048;
    size_t nBits = 1024;
    while ((c = getopt_long(argc, argv, "edhi:o:k:r:g:b:", long_opts, &opt_index)) != -1) {
        switch (c) {
            case 'h':
                printf(usage, argv[0], nBits);
                return 0;
            case 'i':
                strncpy(fnIn, optarg, FNLEN);
                break;
            case 'o':
                strncpy(fnOut, optarg, FNLEN);
                break;
            case 'k':
                strncpy(fnKey, optarg, FNLEN);
                break;
            case 'r':
                strncpy(fnRnd, optarg, FNLEN);
                break;
            case 'e':
                mode = ENC;
                break;
            case 'd':
                mode = DEC;
                break;
            case 'g':
                mode = GEN;
                strncpy(fnOut, optarg, FNLEN);
                break;
            case 'b':
                nBits = atol(optarg);
                break;
            case '?':
                printf(usage, argv[0], nBits);
                return 1;
        }
    }

    switch (mode) {
        case ENC:
            encrypt(fnOut, fnIn, fnKey);
            break;
        case DEC:
            decrypt(fnOut, fnIn, fnKey);
            break;
        case GEN:
            generate(fnOut, nBits);
            break;
        default:
            return 1;
    }

    return 0;
}

/* kem-enc.c
 * simple encryption utility providing CCA2 security.
 * based on the KEM/DEM hybrid model. */

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

int kem_encrypt(const char *fnOut, const char *fnIn, RSA_KEY *K) {
    // generate ephemeral key
    size_t keyLen = rsa_numBytesN(K);
    unsigned char *ephemKey = malloc(keyLen);

    // generate random key
    randBytes(ephemKey, keyLen);
    SKE_KEY SK;
    ske_keyGen(&SK, ephemKey, keyLen);

    // encrypt ephemeral key
    size_t len = rsa_numBytesN(K);
    unsigned char *x = malloc(len);

    randBytes(x, len);
    ske_keyGen(&SK, x, len);

    // encapsulate
    size_t encapLen = len + HASHLEN;
    unsigned char *encap = malloc(encapLen);

    // encrypt
    rsa_encrypt(encap, x, len, K);

    // hash
    unsigned char *h = malloc(HASHLEN);
    SHA256(x, len, h);

    // append hash
    memcpy(encap + len, h, HASHLEN);

    // write to file
    int fdout = open(fnOut, O_CREAT | O_RDWR, S_IRWXU);
    write(fdout, encap, encapLen);
    close(fdout);

    // encrypt file
    ske_encrypt_file(fnOut, fnIn, &SK, NULL, encapLen);

    free(x);
    free(encap);
    free(h);
    return 0;
}

int kem_decrypt(const char *fnOut, const char *fnIn, RSA_KEY *K) {
    // generate ephemeral key
    size_t keyLen = rsa_numBytesN(K);
    unsigned char *ephemKey = malloc(keyLen);

    // generate random key
    int fdin = open(fnIn, O_RDONLY);

    // read encapsulated key
    size_t encapLen = lseek(fdin, 0, SEEK_END);
    lseek(fdin, 0, SEEK_SET);

    // read encapsulated key
    unsigned char *encap = malloc(encapLen);
    read(fdin, encap, encapLen);
    close(fdin);

    // decrypt
    size_t len = rsa_numBytesN(K);

    // check if the file is too short
    unsigned char *x = malloc(len);
    memcpy(x, encap, len);

    // hash
    unsigned char *h = malloc(HASHLEN);
    memcpy(h, encap + len, HASHLEN);

    // check hash
    unsigned char *h2 = malloc(HASHLEN);
    SHA256(x, len, h2);

    // check if the hash is correct
    rsa_decrypt(x, x, len, K);

    // generate key
    SKE_KEY SK;
    ske_keyGen(&SK, x, len);

    // decrypt file
    ske_decrypt_file(fnOut, fnIn, &SK, encapLen);

    free(x);
    free(h);
    free(h2);
    free(encap);

    return 0;
}

int encrypt(char *fnOut, char *fnIn, char *fnKey) {
    FILE *keyFile = fopen(fnKey, "r");
    printf("Key file: %s\n", fnKey);
    if (keyFile == NULL) {
        printf("Key file does not exist\n");
        return -1;
    }

    RSA_KEY K;
    rsa_readPublic(keyFile, &K);
    kem_encrypt(fnOut, fnIn, &K);
    rsa_shredKey(&K);
    fclose(keyFile);
    return 0;
}

int generate(char *fnOut, size_t nBits) {
    RSA_KEY K;

    //create new file with .pub extension
    char *fPub = malloc(strlen(fnOut) + 5);
    strcpy(fPub, fnOut);
    strcat(fPub, ".pub");

    FILE *outPrivate = fopen(fnOut, "w");
    FILE *outPublic = fopen(fPub, "w");

    rsa_keyGen(nBits, &K);
    rsa_writePrivate(outPrivate, &K);
    rsa_writePublic(outPublic, &K);

    fclose(outPrivate);
    fclose(outPublic);
    rsa_shredKey(&K);
    free(fPub);
    return 0;
}

int decrypt(char *fnOut, char *fnIn, char *fnKey) {
    FILE *privateKey = fopen(fnKey, "r");
    printf("Key file: %s\n", fnKey);
    if (privateKey == NULL) {
        printf("Key file does not exist\n");
        return -1;
    }

    RSA_KEY K;
    rsa_readPrivate(privateKey, &K);
    fclose(privateKey);
    kem_decrypt(fnOut, fnIn, &K);
    rsa_shredKey(&K);
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

    /* TODO: finish this off.  Be sure to erase sensitive data
     * like private keys when you're done with them (see the
     * rsa_shredKey function). */
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

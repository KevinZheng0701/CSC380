/* kem-enc.c
 * simple encryption utility providing CCA2 security.
 * based on the KEM/DEM hybrid model. */

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <fcntl.h>
#include <openssl/sha.h>

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

enum modes
{
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

int kem_encrypt(const char *fnOut, const char *fnIn, RSA_KEY *K)
{
	// Length of RSA key
	size_t RSALength = rsa_numBytesN(K);
	unsigned char *x = malloc(RSALength);
	if (x == NULL)
	{
		perror("Failed to allocate space for x");
		return 0;
	}
	// Generate the symmetric key
	randBytes(x, RSALength);
	SKE_KEY SK;
	size_t EncapLength = RSALength + HASHLEN;
	unsigned char *Encapsulation = malloc(EncapLength);
	if (Encapsulation == NULL)
	{
		perror("Failed to allocate space for Encapsulation");
		free(x);
		return 0;
	}
	// Encrypt using RSA
	if (RSALength != rsa_encrypt(Encapsulation, x, RSALength, K))
	{
		printf("Error: RSA encryption failed\n");
		free(Encapsulation);
		free(x);
		return 0;
	}
	unsigned char *h = malloc(HASHLEN);
	if (h == NULL)
	{
		perror("Failed to allocate space for h");
		free(x);
		free(Encapsulation);
		return 0;
	}
	// Hash x
	SHA256(x, RSALength, h);
	memcpy(Encapsulation + RSALength, h, HASHLEN);
	int outputFile = open(fnOut, O_CREAT | O_RDWR, 0666);
	if (outputFile == -1)
	{
		perror("Failed to open output file");
		free(h);
		free(x);
		free(Encapsulation);
		return 0;
	}
	ssize_t bytesWritten = write(outputFile, Encapsulation, EncapLength);
	if (bytesWritten != EncapLength)
	{
		perror("Failed to write encapsulation to output file");
		close(outputFile);
		free(h);
		free(x);
		free(Encapsulation);
		return 0;
	}
	close(outputFile);
	ske_encrypt_file(fnOut, fnIn, &SK, NULL, EncapLength);
	free(h);
	free(x);
	free(Encapsulation);
	return 0;
}

/* NOTE: make sure you check the decapsulation is valid before continuing */
int kem_decrypt(const char *fnOut, const char *fnIn, RSA_KEY *K)
{
	/* TODO: write this. */
	/* step 1: recover the symmetric key */
	/* step 2: check decapsulation */
	/* step 3: derive key from ephemKey and decrypt data. */
	// Length of RSA key
	size_t RSALength = rsa_numBytesN(K);
	// Length of encapsulation
	size_t EncapLength = RSALength + HASHLEN;
	// Open input file
	int inputFile = open(fnIn, O_RDONLY);
	if (inputFile == -1)
	{
		perror("Failed to open input file");
		return 0;
	}
	// Make storage for Encapsulation
	unsigned char *Encapsulation = malloc(EncapLength);
	if (Encapsulation == NULL)
	{
		perror("Failed to create buffer");
		close(inputFile);
		return 0;
	}
	// Read the encapsulation
	ssize_t bytesRead = read(inputFile, Encapsulation, EncapLength);
	if (bytesRead != EncapLength)
	{
		perror("Failed to read encapsulation from input file");
		free(Encapsulation);
		close(inputFile);
		return 0;
	}
	close(inputFile);
	// Buffer to store x after decrypting with RSA
	unsigned char *x = malloc(RSALength);
	if (x == NULL)
	{
		perror("Failed to allocate space");
		free(Encapsulation);
		return 0;
	}
	if (RSALength != rsa_decrypt(x, Encapsulation, RSALength, K))
	{
		printf("Failed to decrypt");
		free(x);
		free(Encapsulation);
		return 0;
	}
	// Find H(x)
	unsigned char *h = malloc(HASHLEN);
	if (h == NULL)
	{
		perror("Failed to allocate space");
		free(x);
		free(Encapsulation);
		return 0;
	}
	// Hash x
	SHA256(x, RSALength, h);
	// Read H(X) from input file and store it
	unsigned char hashVal[HASHLEN];
	memcpy(hashVal, Encapsulation + RSALength, HASHLEN);
	if (memcmp(h, hashVal, HASHLEN) != 0)
	{
		printf("Hash mismatched");
		free(x);
		free(Encapsulation);
		free(h);
		return 0;
	}
	// Get the SK
	SKE_KEY SK;
	ske_keyGen(&SK, x, RSALength);
	// Decrypt the ciphertext using SK
	ske_decrypt_file(fnOut, fnIn, &SK, EncapLength);
	// Free memory
	free(x);
	free(Encapsulation);
	free(h);
	return 0;
}

// Generation mode
int generateKeys(const char *fnKey, size_t nBits)
{
	RSA_KEY K;
	char *keyFile = malloc(strlen(fnKey) + 4);
	strcpy(keyFile, fnKey);
	strcat(keyFile, ".pub");
	FILE *fnPri = fopen(fnKey, "w");
	FILE *fnPub = fopen(keyFile, "w");
	rsa_keyGen(nBits, &K);
	rsa_writePrivate(fnPri, &K);
	rsa_writePublic(fnPub, &K);
	fclose(fnPri);
	fclose(fnPub);
	rsa_shredKey(&K);
	return 0;
}

// Encrypt mode
int encryptData(const char *fnOut, const char *fnIn, const char *fnKey)
{
	FILE *keyFile = fopen(fnKey, "r");
	if (keyFile == NULL)
	{
		perror("Failed to open key file");
		return 0;
	}
	RSA_KEY K;
	rsa_readPublic(keyFile, &K);
	kem_encrypt(fnOut, fnIn, &K);
	rsa_shredKey(&K);
	fclose(keyFile);
	return 0;
}
// Decrypt mode
int decryptData(const char *fnOut, const char *fnIn, const char *fnKey)
{
	FILE *keyFile = fopen(fnKey, "r");
	if (keyFile == NULL)
	{
		perror("Failed to open key file");
		return 0;
	}
	RSA_KEY K;
	rsa_readPrivate(keyFile, &K);
	kem_decrypt(fnOut, fnIn, &K);
	fclose(keyFile);
	rsa_shredKey(&K);
	return 0;
}

int main(int argc, char *argv[])
{
	/* define long options */
	static struct option long_opts[] = {
		{"in", required_argument, 0, 'i'},
		{"out", required_argument, 0, 'o'},
		{"key", required_argument, 0, 'k'},
		{"rand", required_argument, 0, 'r'},
		{"gen", required_argument, 0, 'g'},
		{"bits", required_argument, 0, 'b'},
		{"enc", no_argument, 0, 'e'},
		{"dec", no_argument, 0, 'd'},
		{"help", no_argument, 0, 'h'},
		{0, 0, 0, 0}};
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
	while ((c = getopt_long(argc, argv, "edhi:o:k:r:g:b:", long_opts, &opt_index)) != -1)
	{
		switch (c)
		{
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
			strncpy(fnKey, optarg, FNLEN);
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
	switch (mode)
	{
	case ENC:
		encryptData(fnOut, fnIn, fnKey);
		break;
	case DEC:
		decryptData(fnOut, fnIn, fnKey);
		break;
	case GEN:
		generateKeys(fnKey, nBits);
		break;
	default:
		return 1;
	}

	return 0;
}
// gcc -o ./kem-enc ./kem-enc.c rsa.c prf.c ske.c -I/opt/homebrew/Cellar/gmp/6.3.0/include -I/opt/homebrew/opt/openssl@3/include -lssl -lcrypto -lgmp -L/opt/homebrew/Cellar/gmp/6.3.0/lib -L/opt/homebrew/opt/openssl@3/lib

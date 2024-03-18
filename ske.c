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
#define MMAP_SEQ MAP_PRIVATE | MAP_POPULATE
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

int ske_keyGen(SKE_KEY *K, unsigned char *entropy, size_t entLen)
{
	/* TODO: write this.  If entropy is given, apply a KDF to it to get
	 * the keys (something like HMAC-SHA512 with KDF_KEY will work).
	 * If entropy is null, just get a random key (you can use the PRF). */
	if (entropy != NULL) // entropy is given
	{
		// generate aeskey
		HMAC(EVP_sha512(), KDF_KEY, strlen(KDF_KEY), entropy, entLen, K->aesKey, NULL);
		// generate hmackey
		HMAC(EVP_sha512(), KDF_KEY, strlen(KDF_KEY), entropy, entLen, K->hmacKey, NULL);
	}
	else // entropy is not given
	{
		// generate random keys
		randBytes(K->aesKey, KLEN_SKE);
		randBytes(K->hmacKey, KLEN_SKE);
	}
	return 0;
}
size_t ske_getOutputLen(size_t inputLen)
{
	return AES_BLOCK_SIZE + inputLen + HM_LEN;
}
size_t ske_encrypt(unsigned char *outBuf, unsigned char *inBuf, size_t len,
				   SKE_KEY *K, unsigned char *IV)
{
	/* TODO: finish writing this.  Look at ctr_example() in aes-example.c
	 * for a hint.  Also, be sure to setup a random IV if none was given.
	 * You can assume outBuf has enough space for the result. */
	// generate random IV if none is given
	if (IV == NULL)
		randBytes(IV, 16);
	// encrypt the plaintext using aeskey and get the ciphertext
	EVP_CIPHER_CTX *ciphertext = EVP_CIPHER_CTX_new();
	EVP_EncryptInit_ex(ciphertext, EVP_aes_256_ctr(), 0, K->aesKey, IV);
	int bytesWritten;
	EVP_EncryptUpdate(ciphertext, outBuf, &bytesWritten, (unsigned char *)inBuf, len);
	EVP_CIPHER_CTX_free(ciphertext);
	// Set up the concanentation of IV and ciphertext
	unsigned int HMACLength = 32;
	unsigned char *IVC = malloc(16 + bytesWritten);
	if (IVC == NULL)
	{
		perror("Failed to allocate space for buffer");
		return 0;
	}
	memcpy(IVC, IV, 16);
	memcpy(IVC + 16, outBuf, bytesWritten);
	// Do HMAC(IV|C)
	unsigned char *hmac = malloc(HMACLength);
	if (hmac == NULL)
	{
		perror("Failed to allocate space for buffer");
		free(IVC);
		return 0;
	}
	HMAC(EVP_sha256(), K->hmacKey, HMACLength, IVC, 16 + bytesWritten, hmac, NULL);
	// Form the ciphertext from the three components, IV, C, and HMAC(IV|C) and write to buffer
	size_t ciphertextLength = bytesWritten + HMACLength + 16;
	memcpy(outBuf, IVC, 16 + bytesWritten);
	memcpy(outBuf + 16 + bytesWritten, hmac, HMACLength);
	// free up memory
	free(IVC);
	free(hmac);
	return ciphertextLength; /* TODO: should return number of bytes written, which
									 hopefully matches ske_getOutputLen(...). */
}

size_t ske_decrypt(unsigned char *outBuf, unsigned char *inBuf, size_t len,
				   SKE_KEY *K)
{
	/* TODO: write this.  Make sure you check the mac before decypting!
	 * Oh, and also, return -1 if the ciphertext is found invalid.
	 * Otherwise, return the number of bytes written.  See aes-example.c
	 * for how to do basic decryption. */
	// extract IV
	unsigned char IV[16];
	memcpy(IV, inBuf, 16);
	// extract ciphertext
	unsigned int ciphertextLength = len - 16 - 32;
	unsigned char c[ciphertextLength];
	memcpy(c, inBuf + 16, ciphertextLength);
	// extract hmac
	unsigned char hmac[32];
	memcpy(hmac, inBuf + ciphertextLength + 16, 32);
	// check if the mac is valid
	unsigned char *checkhmac = malloc(32);
	if (checkhmac == NULL)
	{
		perror("Failed to allocate space");
		return 0;
	}
	unsigned char IVC[len - 32];
	memcpy(IVC, inBuf, len - 32);
	HMAC(EVP_sha256(), K->hmacKey, 32, IVC, len - 32, checkhmac, NULL);
	if (memcmp(hmac, checkhmac, 32) != 0)
	{
		free(checkhmac);
		return -1;
	}
	// perform the decryption
	EVP_CIPHER_CTX *ciphertext = EVP_CIPHER_CTX_new();
	EVP_DecryptInit_ex(ciphertext, EVP_aes_256_ctr(), 0, K->aesKey, IV);
	int bytesWritten;
	EVP_DecryptUpdate(ciphertext, outBuf, &bytesWritten, c, ciphertextLength);
	// free up memory
	EVP_CIPHER_CTX_free(ciphertext);
	free(checkhmac);
	return bytesWritten;
}

size_t ske_encrypt_file(const char *fnout, const char *fnin,
						SKE_KEY *K, unsigned char *IV, size_t offset_out)
{
	/* TODO: write this.  Hint: mmap. */
	// Open the input file
	int inputFile = open(fnin, O_RDONLY);
	if (inputFile == -1)
	{
		perror("Failed to open input file");
		return 0;
	}
	// Get the size of the input file
	struct stat st;
	if (fstat(inputFile, &st) == -1)
	{
		perror("Failed to get file stat");
		close(inputFile);
		return 0;
	}
	// Map the input file into memory
	unsigned char *inputData = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, inputFile, 0);
	if (inputData == MAP_FAILED)
	{
		perror("Failed mapping input file into memory");
		close(inputFile);
		return 0;
	}
	close(inputFile);
	// Get output length and allocate buffer space
	size_t outputLength = ske_getOutputLen(st.st_size);
	unsigned char *outputData = malloc(outputLength);
	if (outputData == NULL)
	{
		perror("Failed to create output buffer");
		munmap(inputData, st.st_size);
		return 0;
	}
	// Encrypt the input data and store into output data
	size_t ciphertextLength = ske_encrypt(outputData, inputData, st.st_size, K, IV);
	// Open the output file with write access
	int outputFile = open(fnout, O_RDWR | O_CREAT, 0666);
	if (outputFile == -1)
	{
		perror("Failed to open output file");
		free(outputData);
		munmap(inputData, st.st_size);
		return 0;
	}
	// Set the file offset
	lseek(outputFile, offset_out, SEEK_SET);
	// Write the output buffer to the output file
	if (write(outputFile, outputData, ciphertextLength) == -1)
	{
		perror("Failed to write data to output file");
		free(outputData);
		close(outputFile);
		munmap(inputData, st.st_size);
		return 0;
	}
	// Release memory
	free(outputData);
	close(outputFile);
	munmap(inputData, st.st_size);
	return ciphertextLength;
}

size_t ske_decrypt_file(const char *fnout, const char *fnin,
						SKE_KEY *K, size_t offset_in)
{
	/* TODO: write this. */
	int inputFile = open(fnin, O_RDONLY);
	if (inputFile == -1)
	{
		perror("Failed to open input file");
		return 0;
	}
	// Set the offset
	lseek(inputFile, offset_in, SEEK_SET);
	// Get the size of the input file
	struct stat st;
	if (fstat(inputFile, &st) == -1)
	{
		perror("Failed to get file stat");
		close(inputFile);
		return 0;
	}
	// Map the file into the buffer
	unsigned char *inputData = mmap(NULL, st.st_size - offset_in, PROT_READ, MAP_PRIVATE, inputFile, offset_in);
	if (inputData == MAP_FAILED)
	{
		perror("Failed mapping from input file into memory");
		close(inputFile);
		return 0;
	}
	close(inputFile);
	// Open the output file with write access
	int outputFile = open(fnout, O_RDWR | O_CREAT, 0666);
	if (outputFile == -1)
	{
		perror("Failed to open output file");
		munmap(inputData, st.st_size - offset_in);
		return 0;
	}
	// Allocate memory for output buffer
	size_t outputSize = st.st_size - HM_LEN - offset_in - 16;
	unsigned char *outputData = malloc(outputSize);
	if (outputData == NULL)
	{
		perror("Failed to create output buffer");
		munmap(inputData, st.st_size - offset_in);
		close(outputFile);
		return 0;
	}
	// Decrypt the input data and store into output data
	size_t bytesWritten = ske_decrypt(outputData, inputData, st.st_size - offset_in, K);
	// Write the output buffer to output file
	if (write(outputFile, outputData, bytesWritten) == -1)
	{
		perror("Failed to write data to output file");
		munmap(inputData, st.st_size - offset_in);
		close(outputFile);
		free(outputData);
		return 0;
	}
	// Release memory
	munmap(inputData, st.st_size - offset_in);
	close(outputFile);
	free(outputData);
	return bytesWritten;
}

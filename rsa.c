#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "rsa.h"
#include "prf.h"

/* NOTE: a random composite surviving 10 Miller-Rabin tests is extremely
 * unlikely.  See Pomerance et al.:
 * http://www.ams.org/mcom/1993-61-203/S0025-5718-1993-1189518-9/
 * */
#define ISPRIME(x) mpz_probab_prime_p(x, 10)
#define NEWZ(x) \
	mpz_t x;    \
	mpz_init(x)
#define BYTES2Z(x, buf, len) mpz_import(x, len, -1, 1, 0, 0, buf)
#define Z2BYTES(buf, len, x) mpz_export(buf, &len, -1, 1, 0, 0, x)

/* utility function for read/write mpz_t with streams: */
int zToFile(FILE *f, mpz_t x)
{
	size_t i, len = mpz_size(x) * sizeof(mp_limb_t);
	/* NOTE: len may overestimate the number of bytes actually required. */
	unsigned char *buf = malloc(len);
	Z2BYTES(buf, len, x);
	/* force little endian-ness: */
	for (i = 0; i < 8; i++)
	{
		unsigned char b = (len >> 8 * i) % 256;
		fwrite(&b, 1, 1, f);
	}
	fwrite(buf, 1, len, f);
	/* kill copy in buffer, in case this was sensitive: */
	memset(buf, 0, len);
	free(buf);
	return 0;
}
int zFromFile(FILE *f, mpz_t x)
{
	size_t i, len = 0;
	/* force little endian-ness: */
	for (i = 0; i < 8; i++)
	{
		unsigned char b;
		/* XXX error check this; return meaningful value. */
		fread(&b, 1, 1, f);
		len += (b << 8 * i);
	}
	unsigned char *buf = malloc(len);
	fread(buf, 1, len, f);
	BYTES2Z(x, buf, len);
	/* kill copy in buffer, in case this was sensitive: */
	memset(buf, 0, len);
	free(buf);
	return 0;
}

int rsa_keyGen(size_t keyBits, RSA_KEY *K)
{
	rsa_initKey(K);
	/* TODO: write this.  Use the prf to get random byte strings of
	 * the right length, and then test for primality (see the ISPRIME
	 * macro above).  Once you've found the primes, set up the other
	 * pieces of the key ({en,de}crypting exponents, and n=pq). */
	size_t halfKeyBits = keyBits / 2;
	NEWZ(p);
	NEWZ(q);
	unsigned char *buf = malloc(halfKeyBits / 8);
	size_t len = halfKeyBits / 8;
	// Generate p
	do
	{
		randBytes(buf, len);
		BYTES2Z(p, buf, len);
	} while (!ISPRIME(p));
	// Generate q
	do
	{
		randBytes(buf, len);
		BYTES2Z(q, buf, len);
	} while (!ISPRIME(q));
	// Regenerate q if p and q are equal
	while (mpz_cmp(p, q) == 0)
	{
		do
		{
			randBytes(buf, len);
			BYTES2Z(q, buf, len);
		} while (!ISPRIME(q));
	}
	// Get n from p and q
	NEWZ(n);
	mpz_mul(n, p, q);
	// Get the totient
	NEWZ(totient);
	NEWZ(pminus1);
	NEWZ(qminus1);
	mpz_sub_ui(pminus1, p, 1);
	mpz_sub_ui(qminus1, q, 1);
	mpz_mul(totient, pminus1, qminus1);
	// Generate e where GCD(e, (p-1)*(q-1)) = 1, one commonly used one is 65537
	NEWZ(e);
	NEWZ(gcd);
	NEWZ(one);
	mpz_set_ui(one, 1);
	do
	{
		randBytes(buf, len);
		BYTES2Z(e, buf, len);
		mpz_gcd(gcd, e, totient);
	} while (mpz_cmp_ui(gcd, 1) != 0);

	// Generate the private d key
	NEWZ(d);
	mpz_invert(d, e, totient);
	// Assign the keys back to K
	mpz_set(K->p, p);
	mpz_set(K->q, q);
	mpz_set(K->n, n);
	mpz_set(K->e, e);
	mpz_set(K->d, d);
	// free up any memory
	mpz_clear(p);
	mpz_clear(q);
	mpz_clear(n);
	mpz_clear(e);
	mpz_clear(d);
	mpz_clear(pminus1);
	mpz_clear(qminus1);
	mpz_clear(totient);
	mpz_clear(gcd);
	mpz_clear(one);
	free(buf);
	return 0;
}

size_t rsa_encrypt(unsigned char *outBuf, unsigned char *inBuf, size_t len,
				   RSA_KEY *K)
{
	/* TODO: write this.  Use BYTES2Z to get integers, and then
	 * Z2BYTES to write the output buffer. */
	NEWZ(ciphertext);
	NEWZ(message);
	// convert buffer message to integer
	BYTES2Z(message, inBuf, len);
	// check if m is within the len of n
	if (mpz_cmp(message, K->n) >= 0)
	{
		mpz_clear(message);
		mpz_clear(ciphertext);
		return 0;
	}
	// perform the one way function
	mpz_powm(ciphertext, message, K->e, K->n);
	size_t ciphertextLength = mpz_sizeinbase(ciphertext, 256);
	// convert the ciphertext integer back to bytes
	Z2BYTES(outBuf, ciphertextLength, ciphertext);
	// free up memory
	mpz_clear(message);
	mpz_clear(ciphertext);
	return ciphertextLength; /* TODO: return should be # bytes written */
}
size_t rsa_decrypt(unsigned char *outBuf, unsigned char *inBuf, size_t len,
				   RSA_KEY *K)
{
	/* TODO: write this.  See remarks above. */
	NEWZ(ciphertext);
	NEWZ(message);
	// convert buffer ciphertext to integer
	BYTES2Z(ciphertext, inBuf, len);
	// reverse the ciphertext using the secret key
	mpz_powm(message, ciphertext, K->d, K->n);
	size_t messageLength = mpz_sizeinbase(message, 256);
	// convert the message integer back to bytes
	Z2BYTES(outBuf, messageLength, message);
	// free up memory
	mpz_clear(message);
	mpz_clear(ciphertext);
	return messageLength;
}

size_t rsa_numBytesN(RSA_KEY *K)
{
	return mpz_size(K->n) * sizeof(mp_limb_t);
}

int rsa_initKey(RSA_KEY *K)
{
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

int rsa_writePublic(FILE *f, RSA_KEY *K)
{
	/* only write n,e */
	zToFile(f, K->n);
	zToFile(f, K->e);
	return 0;
}
int rsa_writePrivate(FILE *f, RSA_KEY *K)
{
	zToFile(f, K->n);
	zToFile(f, K->e);
	zToFile(f, K->p);
	zToFile(f, K->q);
	zToFile(f, K->d);
	return 0;
}
int rsa_readPublic(FILE *f, RSA_KEY *K)
{
	rsa_initKey(K); /* will set all unused members to 0 */
	zFromFile(f, K->n);
	zFromFile(f, K->e);
	return 0;
}
int rsa_readPrivate(FILE *f, RSA_KEY *K)
{
	rsa_initKey(K);
	zFromFile(f, K->n);
	zFromFile(f, K->e);
	zFromFile(f, K->p);
	zFromFile(f, K->q);
	zFromFile(f, K->d);
	return 0;
}
int rsa_shredKey(RSA_KEY *K)
{
	/* clear memory for key. */
	mpz_t *L[5] = {&K->d, &K->e, &K->n, &K->p, &K->q};
	size_t i;
	for (i = 0; i < 5; i++)
	{
		size_t nLimbs = mpz_size(*L[i]);
		if (nLimbs)
		{
			memset(mpz_limbs_write(*L[i], nLimbs), 0, nLimbs * sizeof(mp_limb_t));
			mpz_clear(*L[i]);
		}
	}
	/* NOTE: a quick look at the gmp source reveals that the return of
	 * mpz_limbs_write is only different than the existing limbs when
	 * the number requested is larger than the allocation (which is
	 * of course larger than mpz_size(X)) */
	return 0;
}

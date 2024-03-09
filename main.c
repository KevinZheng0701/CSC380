#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "rsa.h"

int main()
{
    // Generate RSA keys
    size_t keyBits = 1024; // Example key size
    RSA_KEY K;
    rsa_keyGen(keyBits, &K);

    // Print generated keys
    gmp_printf("p: %Zd\n", K.p);
    gmp_printf("q: %Zd\n", K.q);
    gmp_printf("n: %Zd\n", K.n);
    gmp_printf("e: %Zd\n", K.e);
    gmp_printf("d: %Zd\n", K.d);
    // Original message
    unsigned char *original_message = (unsigned char *)"Hello how are you today. Password 123";
    gmp_printf("Original message: %s\n", original_message);
    size_t original_message_len = strlen((const char *)original_message);
    // Encrypt message
    size_t encrypted_message_len = (keyBits / 8) + 1; // Adjust length for padding
    unsigned char *encrypted_message = malloc(encrypted_message_len);
    size_t encrypted_bytes = rsa_encrypt(encrypted_message, original_message, original_message_len, &K);
    gmp_printf("Encrypted message: ");
    for (size_t i = 0; i < encrypted_bytes; i++)
    {
        gmp_printf("%02x", encrypted_message[i]);
    }
    gmp_printf("\n");
    // Decrypt message
    unsigned char *decrypted_message = malloc(original_message_len);
    size_t decrypted_bytes = rsa_decrypt(decrypted_message, encrypted_message, encrypted_bytes, &K);
    // Print results
    gmp_printf("Decrypted message: %s\n", decrypted_message);

    // Free memory
    free(encrypted_message);
    free(decrypted_message);
    mpz_clear(K.p);
    mpz_clear(K.q);
    mpz_clear(K.n);
    mpz_clear(K.e);
    mpz_clear(K.d);

    return 0;
}

// gcc -o test_rsa main.c rsa.c prf.c -I/opt/homebrew/Cellar/gmp/6.3.0/include -L/opt/homebrew/Cellar/gmp/6.3.0/lib -lgmp -I/opt/homebrew/Cellar/gmp/6.3.0/include -L/opt/homebrew/Cellar/gmp/6.3.0/lib -lgmp -I/opt/homebrew/opt/openssl@3/include -L/opt/homebrew/opt/openssl@3/lib -lssl -lcrypto

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/bio.h>
#include <stddef.h>
#include <assert.h>

// ChatGPT: "How to remove any whitespace from a char buffer"
// Modified to remove only newlines --> commands contain \n at the end
void remove_whitespace(char *str) {
    char *i = str;
    char *j = str;
    while (*j != '\0') {
        if (*j != '\n') {
            *i = *j;
            i++;
        }
        j++;
    }
    *i = '\0';
}

unsigned char* hash_input(unsigned char *input, size_t input_len) {
    const EVP_MD *md = EVP_get_digestbyname("sha256"); // get hashing algorithm
    if (md == NULL) {
        return NULL;
    }

    unsigned int md_len = EVP_MD_size(md);

    unsigned char *output = malloc(md_len);
    if (output == NULL) {
        return NULL;
    }

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
	if (ctx == NULL) {
	    return NULL;
    }

    if (1 != EVP_DigestInit_ex(ctx, md, NULL)) {
        return NULL;
    }

    if (1 != EVP_DigestUpdate(ctx, input, input_len)) {
        return NULL;
    }

    if (1 != EVP_DigestFinal_ex(ctx, output, &md_len)) {
        return NULL;
    }

    EVP_MD_CTX_free(ctx);

    return output;
}

unsigned char *encrypt_and_mac(unsigned char *s_key, unsigned char *input, 
                                    size_t input_len, unsigned int seqno, size_t *output_len) {
    unsigned char iv[16];

    assert(RAND_bytes(iv, sizeof(iv)) == 1);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    assert(ctx != NULL);
    
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, s_key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }

    // Seqno = 10 digits. Msg_length represented as 4 digits
    size_t plaintext_len = 10 + 4 + input_len;
    unsigned char plaintext[plaintext_len + 1];
    snprintf(plaintext, plaintext_len + 1, "%010u%04ld", seqno, input_len);
    memcpy(plaintext + 10 + 4, input, input_len);

    int max_message_len = 288;
    size_t rand_len = max_message_len - plaintext_len;
    unsigned char noise[rand_len];
    assert(RAND_bytes(noise, rand_len) == 1);

    unsigned char to_encrypt[max_message_len];
    memcpy(to_encrypt, plaintext, plaintext_len);
    memcpy(to_encrypt + plaintext_len, noise, rand_len);

    unsigned char *ciphertext = NULL;
    int ciphertext_len, len;
    ciphertext = malloc(max_message_len + EVP_MAX_BLOCK_LENGTH);
    if (ciphertext == NULL) {
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }

    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, to_encrypt, max_message_len)) {
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }

    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }

    ciphertext_len += len;

    unsigned char iv_cipher[16 + ciphertext_len];
    memcpy(iv_cipher, iv, 16);
    memcpy(iv_cipher + 16, ciphertext, ciphertext_len);

    unsigned char *mac = NULL;
    unsigned int mac_len = 0;
    mac = HMAC(EVP_sha256(), s_key, sizeof(s_key), iv_cipher, 16 + ciphertext_len, NULL, &mac_len);
    if (mac == NULL) return NULL; // MAC Failure

    size_t message_len = 16 + ciphertext_len + mac_len;
    unsigned char *message = (unsigned char *) malloc(message_len);
    memcpy(message, iv, 16);
    memcpy(message + 16, ciphertext, ciphertext_len);
    memcpy(message + 16 + ciphertext_len, mac, mac_len);

    if (output_len != NULL) {
        *output_len = message_len;
    }
    EVP_CIPHER_CTX_free(ctx);
    free(ciphertext);

    return message;
}

unsigned char *decrypt(unsigned char *s_key, unsigned char *ciphertext, unsigned char *seqno, size_t *message_len) {
    unsigned char iv[16];
    memcpy(iv, ciphertext, 16);

    int cipher_len = 352 - 16 - 32;
    unsigned char cipher[cipher_len];
    memcpy(cipher, ciphertext + 16, cipher_len);

    unsigned char iv_cipher[16 + cipher_len];
    memcpy(iv_cipher, ciphertext, 16);
    memcpy(iv_cipher + 16, ciphertext + 16, cipher_len);

    unsigned char mac[32];
    memcpy(mac, ciphertext + 320, 32);

    unsigned int new_mac_len = 0;
    unsigned char *computed_mac = HMAC(EVP_sha256(), s_key, sizeof(s_key), iv_cipher, 16 + cipher_len, NULL, &new_mac_len);
    assert(computed_mac != NULL);

    if (CRYPTO_memcmp(mac, computed_mac, 32) != 0) {
        return NULL; // Integrity Failure => Drop Packet
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    assert(ctx != NULL);

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, s_key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }

    unsigned char *plaintext = malloc(cipher_len);
    int plaintext_len, len;
    if (!plaintext) {
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }

    if (EVP_DecryptUpdate(ctx, plaintext, &len, cipher, cipher_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }

    plaintext_len = len;

    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }

    snprintf(seqno, 11, "%s", plaintext);
    unsigned char data_len[5];
    snprintf(data_len, 5, "%s", plaintext + 10);
    size_t msg_len = strtoul(data_len, NULL, 10);

    if (message_len != NULL)
        *message_len = msg_len;

    unsigned char *message = (unsigned char *) malloc(msg_len + 1);
    snprintf(message, msg_len + 1, "%s", plaintext + 14);

    return message;
}
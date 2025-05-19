#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <stddef.h>

#ifndef __HELPER_H__
#define __HELPER_H__

void remove_whitespace(char *input);
unsigned char* hash_input(unsigned char *input, size_t input_len);
unsigned char *encrypt_and_mac(unsigned char *s_key, unsigned char *input, 
                                    size_t input_len, unsigned long seqno, size_t *output_len);
unsigned char *decrypt(unsigned char *s_key, unsigned char *ciphertext, unsigned char *seqno, size_t *message_len);
unsigned char *parse_plaintext(unsigned char *plaintext, unsigned char *seqno, size_t *msg_len);
#endif
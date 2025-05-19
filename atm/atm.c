#include "atm.h"
#include "ports.h"
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <helpers.h>
#include <regex.h>
#include <assert.h>
#include <list.h>

#define MAX_RECV_LEN 352
#define SEQNO_LEN 10

ATM* atm_create()
{
    ATM *atm = (ATM*) malloc(sizeof(ATM));
    if(atm == NULL)
    {
        perror("Could not allocate ATM");
        exit(1);
    }

    // Set up the network state
    atm->sockfd=socket(AF_INET,SOCK_DGRAM,0);

    bzero(&atm->rtr_addr,sizeof(atm->rtr_addr));
    atm->rtr_addr.sin_family = AF_INET;
    atm->rtr_addr.sin_addr.s_addr=inet_addr("127.0.0.1");
    atm->rtr_addr.sin_port=htons(ROUTER_PORT);

    bzero(&atm->atm_addr, sizeof(atm->atm_addr));
    atm->atm_addr.sin_family = AF_INET;
    atm->atm_addr.sin_addr.s_addr=inet_addr("127.0.0.1");
    atm->atm_addr.sin_port = htons(ATM_PORT);
    bind(atm->sockfd,(struct sockaddr *)&atm->atm_addr,sizeof(atm->atm_addr));

    // Set up the protocol state
    // TODO set up more, as needed
    atm->attempts = list_create();
    return atm;
}

void atm_free(ATM *atm)
{
    if(atm != NULL)
    {
        close(atm->sockfd);
        free(atm);
    }
}

ssize_t atm_send(ATM *atm, unsigned char *data, size_t data_len)
{
    // Returns the number of bytes sent; negative on error
    return sendto(atm->sockfd, data, data_len, 0,
                  (struct sockaddr*) &atm->rtr_addr, sizeof(atm->rtr_addr));
}

ssize_t atm_recv(ATM *atm, unsigned char *data, size_t max_data_len)
{
    // Returns the number of bytes received; negative on error
    return recvfrom(atm->sockfd, data, max_data_len, 0, NULL, NULL);
}

void atm_process_command(ATM *atm, char *command) {

    regex_t regex_begin, regex_pin, regex_withdraw;
    regmatch_t matches[2];
    memset(matches, 0, sizeof(matches));

    const char *pattern_begin = "^begin-session ([a-zA-Z]+)$";
    const char *pattern_pin = "^([0-9][0-9][0-9][0-9])$";
    const char *pattern_withdraw = "^withdraw ([0-9]+)$";

    regcomp(&regex_begin, pattern_begin, REG_EXTENDED);
    regcomp(&regex_pin, pattern_pin, REG_EXTENDED);
    regcomp(&regex_withdraw, pattern_withdraw, REG_EXTENDED);

    char *instruction = strtok(strdup(command), " ");
    remove_whitespace(instruction);
    remove_whitespace(command);

    if (strcmp(instruction, "begin-session") == 0) {
        if (regexec(&regex_begin, command, 2, matches, 0) == 0) {
            if (atm -> curr_user != NULL) {
                printf("A user is already logged in\n");
                return;
            }

            int start = matches[1].rm_so;
            int end = matches[1].rm_eo;
            int name_len = end - start;
    
            if (name_len > 250) { // Invalid Arguments
                printf("Usage: begin-session <user-name>\n");
                return;
            }
    
            char name[name_len + 1];
            snprintf(name, name_len + 1, "%s", command + start);
            name[name_len] = '\0';

            size_t init_msg_len = 0;
            unsigned char *init_msg = encrypt_and_mac(atm->s_key, (unsigned char *) command, strlen(command), (atm -> seqno)++, &init_msg_len);
            atm_send(atm, init_msg, init_msg_len);

            int check = 0;
            size_t recv_hash_len = 0;
            unsigned char *received_hash;
            do {
                unsigned char recv_buf[MAX_RECV_LEN + 1];
                int n = atm_recv(atm, recv_buf, MAX_RECV_LEN);
                // printf("N: %d\n", n);
                recv_buf[MAX_RECV_LEN] = '\0';
                if (n != MAX_RECV_LEN)
                    check = 1;
    
                unsigned char seqno_buf[SEQNO_LEN + 1];
                // size_t recv_hash_len = 0;
                received_hash = decrypt(atm->s_key, recv_buf, seqno_buf, &recv_hash_len);
                seqno_buf[SEQNO_LEN] = '\0';
                if (atm->seqno != strtoul(seqno_buf, NULL, 10)) {
                    check = 1;

                } else {
                    atm->seqno += 1;
                }
                // assert(atm->seqno++ == seqno);
                // printf("Check: %d\n", check);
            } while (check == 1);
            
            
            if (memcmp(received_hash, "No user found", recv_hash_len) == 0) {
                printf("No such user\n");
                size_t filler_len = 0;
                unsigned char *filler = encrypt_and_mac(atm->s_key, "Not authorized", strlen("Not authorized"), (atm->seqno)++, &filler_len);
                atm_send(atm, filler, filler_len);
                return;
            }

            int card_len = name_len + 5;
            char card_file[card_len + 1];
            snprintf(card_file, card_len + 1, "%s.card", name);
            card_file[card_len] = '\0';
    
            FILE *card_fp = fopen(card_file, "rb");
            if (card_fp == NULL) {
                printf("Unable to access %s's card\n", name);
                size_t filler_len = 0;
                unsigned char *filler = encrypt_and_mac(atm->s_key, "Not authorized", strlen("Not authorized"), (atm->seqno)++, &filler_len);
                atm_send(atm, filler, filler_len);
                return;
            }

            size_t salt_len = 32;
            unsigned char salt[salt_len];
            fread(salt, 1, salt_len, card_fp);
            fclose(card_fp);

            printf("PIN? ");
            fflush(stdout);
            
            // Read STDIN
            int i = 0;
            int pin_len = 4;
            char pin[pin_len + 1];
            char c;
            while ((c = getchar()) != '\n' && c != EOF) {
                if (i < 4) {
                    pin[i++] = c;
                }
            }
            pin[pin_len] = '\0';

            // Compute Hash of pin || name || salt
            size_t input_len = name_len + pin_len + salt_len;
            unsigned char *plaintext = malloc(input_len);
            if (plaintext == NULL) {
                printf("Error creating card file for user <user-name>\n");
                size_t filler_len = 0;
                unsigned char *filler = encrypt_and_mac(atm->s_key, "Not authorized", strlen("Not authorized"), (atm->seqno)++, &filler_len);
                atm_send(atm, filler, filler_len);
                return;
            }
            memcpy(plaintext, pin, pin_len);
            memcpy(plaintext + pin_len, name, name_len);
            memcpy(plaintext + pin_len + name_len, salt, salt_len);

            unsigned char *hash = hash_input(plaintext, input_len);
            if (i == 4 && CRYPTO_memcmp(received_hash, hash, recv_hash_len) == 0) {
                ListElem *user = list_find(atm->attempts, name);
                if (user == NULL) {
                    list_add(atm->attempts, name, NULL, 0);
                } else {
                    user->val = 0;
                }
                printf("Authorized\n");
                atm -> curr_user = malloc(name_len + 1);
                assert(atm -> curr_user != NULL);
                snprintf(atm -> curr_user, name_len + 1, "%s", name);
                
                size_t reply_len = 0;
                unsigned char *reply = encrypt_and_mac(atm->s_key, "Authorized", strlen("Authorized"), (atm->seqno)++, &reply_len);
                atm_send(atm, reply, reply_len);
            }  else { // Could be Incorrect Input or Card Forgery
                ListElem *user = list_find(atm->attempts, name);
                if (user == NULL) {
                    list_add(atm->attempts, name, NULL, 1);
                    user = list_find(atm->attempts, name);
                } else {
                    user -> val += 1;
                }
                printf("Not authorized\n");
                
                size_t filler_len = 0;
                unsigned char *filler = encrypt_and_mac(atm->s_key, "Not authorized", strlen("Not authorized"), (atm->seqno)++, &filler_len);
                atm_send(atm, filler, filler_len);
                
                if (user->val > 5) {
                    sleep(10 * 60); // 10 Minute Sleep if incorrect more than 5 times in a row
                } else {
                    unsigned int temp = 1;
                    for (int i = 0; i < user->val - 1; i++) {
                        temp *= 2;
                    }
                    sleep(temp * 15);
                }
            }
        } else {
            printf("Usage: begin-session <user-name>\n");
            return;
        }
    } else if (strcmp(instruction, "withdraw") == 0) {
        if (regexec(&regex_withdraw, command, 2, matches, 0) == 0) {
            if (atm->curr_user == NULL) {
                printf("No user logged in\n");
                return;
            }
    
            int start = matches[1].rm_so;
            int end = matches[1].rm_eo;
            int amt_len = end - start;
            char amt[amt_len + 1];
            snprintf(amt, amt_len + 1, "%s", command + start);
            amt[amt_len] = '\0';
    
            if (strtoul(amt, NULL, 10) > UINT_MAX) { // Invalid Inputs
                printf("Usage: withdraw <amt>\n");
                return;
            }
    
            size_t message_len = 0;
            unsigned char *message = encrypt_and_mac(atm->s_key, (unsigned char *) command, strlen(command), (atm->seqno)++, &message_len);
            assert(message_len == MAX_RECV_LEN);
            atm_send(atm, message, message_len);

            int check = 0;
            unsigned char *reply;
            do {
                unsigned char recv_buf[MAX_RECV_LEN + 1];
                int n = atm_recv(atm, recv_buf, MAX_RECV_LEN);
                recv_buf[MAX_RECV_LEN] = '\0';
                if (n != MAX_RECV_LEN)
                    check = 1;
    
                unsigned char seqno_buf[SEQNO_LEN + 1];
                reply = decrypt(atm->s_key, recv_buf, seqno_buf, NULL);
                seqno_buf[SEQNO_LEN] = '\0';
                if (atm->seqno != strtoul(seqno_buf, NULL, 10)) {
                    check = 1;
                } else {
                    atm->seqno += 1;
                }
                // assert(atm->seqno++ == strtoul(seqno_buf, NULL, 10));
            } while (check == 1);
            
            if (strcmp(reply, "Authorized") == 0) {
                printf("$%s dispensed\n", amt);
            } else if (strcmp(reply, "Not authorized") == 0) {
                printf("Insufficient funds\n");
            } else {
                // Who are you
            }
        } else {
            printf("Usage: withdraw <amt>\n");
            return;
        }
    } else if (strcmp(command, "balance") == 0) {
        if (atm -> curr_user == NULL) {
            printf("No user logged in\n");
            return;
        }

        printf("Balance\n");
        size_t message_len = 0;
        unsigned char *message = encrypt_and_mac(atm->s_key, (unsigned char *) command, strlen(command), (atm->seqno)++, &message_len);
        assert(message_len == MAX_RECV_LEN);
        atm_send(atm, message, message_len);

        int check = 0;
        unsigned char *reply;
        do {
            unsigned char recv_buf[MAX_RECV_LEN + 1];
            int n = atm_recv(atm, recv_buf, MAX_RECV_LEN);
            recv_buf[MAX_RECV_LEN] = '\0';
            if (n != MAX_RECV_LEN)
                    check = 1;
            // assert(n == MAX_RECV_LEN);
    
            unsigned char seqno_buf[SEQNO_LEN + 1];
            reply = decrypt(atm->s_key, recv_buf, seqno_buf, NULL);
            seqno_buf[SEQNO_LEN] = '\0';
            if (atm->seqno != strtoul(seqno_buf, NULL, 10)) {
                check = 1;
            } else {
                atm->seqno += 1;
            }
            // assert(atm->seqno++ == strtoul(seqno_buf, NULL, 10));
        } while (check == 1);
        
        printf("$%lu\n", strtoul(reply, NULL, 10));
    } else if (strcmp(command, "end-session") == 0) {
        if (atm -> curr_user == NULL) {
            printf("No user logged in\n");
            return;
        }

        size_t message_len = 0;
        unsigned char *message = encrypt_and_mac(atm->s_key, (unsigned char *) command, strlen(command), (atm->seqno)++, &message_len);
        atm_send(atm,  message, message_len);

        int check = 0;
        unsigned char *reply;
        do {
            unsigned char recv_buf[MAX_RECV_LEN + 1];
            int n = atm_recv(atm, recv_buf, MAX_RECV_LEN);
            recv_buf[MAX_RECV_LEN] = '\0';
            if (n != MAX_RECV_LEN)
                check = 1;
            // assert(n == MAX_RECV_LEN);
    
            unsigned char seqno_buf[SEQNO_LEN + 1];
            reply = decrypt(atm->s_key, recv_buf, seqno_buf, NULL);
            seqno_buf[SEQNO_LEN] = '\0';
            if (atm->seqno != strtoul(seqno_buf, NULL, 10)) {
                check = 1;
            } else {
                atm->seqno += 1;
            }
            // assert(atm->seqno++ == strtoul(seqno_buf, NULL, 10));
        } while (check == 1);
        
        if (strcmp(reply, "Ending Session") == 0) {
            free(atm->curr_user);
            atm -> curr_user = NULL;
            printf("User logged out\n");
        }
        // assert(strcmp(reply, "Ending Session") == 0);
    } else {
        printf("Invalid command\n");
    }
}
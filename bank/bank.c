#include "bank.h"
#include "ports.h"
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <regex.h>
#include <assert.h>
#include <helpers.h>
#include <openssl/rand.h>

#define MAX_RECV_LEN 352
#define SEQNO_LEN 10

Bank* bank_create()
{
    Bank *bank = (Bank*) malloc(sizeof(Bank));
    if(bank == NULL)
    {
        perror("Could not allocate Bank");
        exit(1);
    }

    // Set up the network state
    bank->sockfd=socket(AF_INET,SOCK_DGRAM,0);

    bzero(&bank->rtr_addr,sizeof(bank->rtr_addr));
    bank->rtr_addr.sin_family = AF_INET;
    bank->rtr_addr.sin_addr.s_addr=inet_addr("127.0.0.1");
    bank->rtr_addr.sin_port=htons(ROUTER_PORT);

    bzero(&bank->bank_addr, sizeof(bank->bank_addr));
    bank->bank_addr.sin_family = AF_INET;
    bank->bank_addr.sin_addr.s_addr=inet_addr("127.0.0.1");
    bank->bank_addr.sin_port = htons(BANK_PORT);
    bind(bank->sockfd,(struct sockaddr *)&bank->bank_addr,sizeof(bank->bank_addr));

    // Set up the protocol state
    // TODO set up more, as needed
    bank -> users = list_create();

    return bank;
}

void bank_free(Bank *bank)
{
    if(bank != NULL)
    {
        close(bank->sockfd);
        free(bank);
    }
}

ssize_t bank_send(Bank *bank, unsigned char *data, size_t data_len)
{
    // Returns the number of bytes sent; negative on error
    return sendto(bank->sockfd, data, data_len, 0,
                  (struct sockaddr*) &bank->rtr_addr, sizeof(bank->rtr_addr));
}

ssize_t bank_recv(Bank *bank, unsigned char *data, size_t max_data_len)
{
    // Returns the number of bytes received; negative on error
    return recvfrom(bank->sockfd, data, max_data_len, 0, NULL, NULL);
}

void bank_process_local_command(Bank *bank, unsigned char *command, size_t len) {

    regex_t regex_create, regex_deposit, regex_balance;
    regmatch_t matches[4];
    memset(matches, 0, sizeof(matches));
    
    const char *pattern_create = "^create-user ([a-zA-Z]+) ([0-9][0-9][0-9][0-9]) ([0-9]+)$";
    const char *pattern_deposit = "^deposit ([a-zA-Z]+) ([0-9]+)$";
    const char *pattern_balance = "^balance ([a-zA-Z]+)$";

    regcomp(&regex_create, pattern_create, REG_EXTENDED);
    regcomp(&regex_deposit, pattern_deposit, REG_EXTENDED);
    regcomp(&regex_balance, pattern_balance, REG_EXTENDED);

    char *instruction = strtok(strdup(command), " "); // Get the first word of the command
    remove_whitespace(instruction);
    remove_whitespace(command);

    if (strcmp(instruction, "create-user") == 0) {
        if (regexec(&regex_create, command, 4, matches, 0) == 0) {
            int name_start = matches[1].rm_so;
            int name_end = matches[1].rm_eo;
            int name_len = name_end - name_start;

            int pin_start = matches[2].rm_so;
            int pin_end = matches[2].rm_eo;
            int pin_len = pin_end - pin_start;

            int balance_start = matches[3].rm_so;
            int balance_end = matches[3].rm_eo;
            int balance_len = balance_end - balance_start;
            
            char balance[balance_len + 1];
            snprintf(balance, balance_len + 1, "%s", command + balance_start);
            balance[balance_len] = '\0';
            unsigned long val = strtoul(balance, NULL, 10);

            if (name_len > 250 || pin_len != 4 || val > UINT_MAX) {
                printf("Usage:  create-user <user-name> <pin> <balance>\n");
                return;
            }

            char name[name_len + 1];
            snprintf(name, name_len + 1, "%s", command + name_start);
            name[name_len] = '\0';

            char pin[pin_len + 1];
            snprintf(pin, pin_len + 1, "%s", command + pin_start);
            pin[pin_len] = '\0';
            
            if (list_find(bank->users, name) != NULL) {
                printf("Error:  user %s already exists\n", name);
                return;
            }

            int card_len = name_len + 5;
            char card_file[card_len + 1];
            snprintf(card_file, card_len + 1, "%s.card", name);
            card_file[card_len] = '\0';

            FILE *card = fopen(card_file, "wb");
            if (card == NULL) {
                printf("Error creating card file for user <user-name>\n");
                return;
            }

            size_t salt_len = 32;
            unsigned char salt[salt_len];
            if (RAND_bytes(salt, sizeof(salt)) != 1) {
                printf("Error creating card file for user <user-name>\n");
                return;
            }

            size_t input_len = name_len + pin_len + salt_len;
            unsigned char *plaintext = malloc(input_len);
            if (plaintext == NULL) {
                printf("Error creating card file for user <user-name>\n");
                return;
            }
            memcpy(plaintext, pin, pin_len);
            memcpy(plaintext + pin_len, name, name_len);
            memcpy(plaintext + pin_len + name_len, salt, salt_len);

            unsigned char *hash = hash_input(plaintext, input_len);
            list_add(bank->users, name, hash, (unsigned int) val);
            fwrite(salt, 1, salt_len, card);
            fclose(card);
            free(plaintext);
            
            printf("Created user %s\n", name);
        } else {
            printf("Usage:  create-user <user-name> <pin> <balance>\n");
            return;
        }
    } else if (strcmp(instruction, "deposit") == 0) {
        if (regexec(&regex_deposit, command, 3, matches, 0) == 0) {
            int name_start = matches[1].rm_so;
            int name_end = matches[1].rm_eo;
            int name_len = name_end - name_start;

            int amt_start = matches[2].rm_so;
            int amt_end = matches[2].rm_eo;
            int amt_len = amt_end - amt_start;
            char amt[amt_len + 1];
            snprintf(amt, amt_len + 1, "%s", command + amt_start);

            unsigned long val = strtoul(amt, NULL, 10);
            if (name_len > 250 || val > UINT_MAX) {
                printf("Usage:  deposit <user-name> <amt>\n");
                return;
            }

            char name[name_len + 1];
            snprintf(name, name_len + 1, "%s", command + name_start);
            name[name_len] = '\0';

            ListElem *user = list_find(bank->users, name);
            if (user == NULL) {
                printf("No such user\n");
                return;
            }

            unsigned int curr_balance = user -> val;
            if (curr_balance > UINT_MAX - (unsigned int) val) {
                printf("Too rich for this program\n");
            } else {
                user->val = curr_balance + (unsigned int) val;
                printf("$%u added to %s's account\n", (unsigned int) val, name);
            }
        } else {
            printf("Usage:  deposit <user-name> <amt>\n");
            return;
        }
    } else if (strcmp(instruction, "balance") == 0) {
        if (regexec(&regex_balance, command, 2, matches, 0) == 0) {
            int name_start = matches[1].rm_so;
            int name_end = matches[1].rm_eo;
            int name_len = name_end - name_start;

            if (name_len > 250) {
                printf("Usage:  balance <user-name>\n");
                return;
            }
            
            char name[name_len + 1];
            snprintf(name, name_len + 1, "%s", command + name_start);
            name[name_len] = '\0';

            ListElem *user = list_find(bank->users, name);
            if (user == NULL) {
                printf("No such user\n");
                return;
            }

            printf("$%u\n", user->val);
        } else {
            printf("Usage:  balance <user-name>\n");
            return;
        }
    } else {
        printf("Invalid command\n");
    }
}

void bank_process_remote_command(Bank *bank, unsigned char *command, size_t len) {

    // All legitimate packets should be 352 bytes
    // Drop all other packets
    if (len != 352) {
        return;
    }
    unsigned char ciphertext[MAX_RECV_LEN + 1];
    memcpy(ciphertext, command, MAX_RECV_LEN);
    ciphertext[MAX_RECV_LEN] = '\0';

    unsigned char seqno_buf[SEQNO_LEN + 1];
    unsigned char *message = decrypt(bank->s_key, ciphertext, seqno_buf, NULL);
    seqno_buf[SEQNO_LEN] = '\0';
    if (bank->seqno != strtoul(seqno_buf, NULL, 10)) {
        return; // Invalid packet --> Drop
    }
    bank->seqno += 1;
    // assert(bank->seqno++ == strtoul(seqno_buf, NULL, 10));

    char *instruction = strtok(strdup(message), " ");
    remove_whitespace(instruction);
    remove_whitespace(message);

    regex_t regex_begin, regex_withdraw;
    regmatch_t matches[2];

    const char *pattern_begin = "^begin-session ([a-zA-Z]+)$";
    const char *pattern_withdraw = "^withdraw ([0-9]+)$";

    regcomp(&regex_begin, pattern_begin, REG_EXTENDED);
    regcomp(&regex_withdraw, pattern_withdraw, REG_EXTENDED);

    if (strcmp(instruction, "begin-session") == 0) {
        if (regexec(&regex_begin, message, 2, matches, 0) == 0) {
            int start = matches[1].rm_so;
            int end = matches[1].rm_eo;
            int name_len = end - start;

            char name[name_len + 1];
            snprintf(name, name_len + 1, "%s", message + start);
            name[name_len] = '\0';

            ListElem *user = list_find(bank -> users, name);
            unsigned char *hash;
            size_t msg_len = 0;
            if (user == NULL) {
                char msg[] = "No user found";
                msg_len = strlen(msg);
                hash = (unsigned char *) malloc(msg_len + 1);
                snprintf(hash, msg_len + 1, "%s", msg);
            } else {
                hash = user -> hash;
                msg_len = 32;
            }
            
            size_t to_send_len = 0;
            unsigned char *to_send = encrypt_and_mac(bank->s_key, hash, msg_len, (bank->seqno)++, &to_send_len);
            bank_send(bank, to_send, to_send_len);

            unsigned char recv_buf[MAX_RECV_LEN + 1];
            unsigned char *resp_msg; 
            int check = 0;
            do {
                int n = bank_recv(bank, recv_buf, MAX_RECV_LEN);
                recv_buf[MAX_RECV_LEN] = '\0';
                if (n != MAX_RECV_LEN)
                    check = 1; // check failed
                // assert(n == MAX_RECV_LEN);
    
                unsigned char resp_seqno[SEQNO_LEN + 1];
                resp_msg = decrypt(bank->s_key, recv_buf, resp_seqno, NULL);
                resp_seqno[SEQNO_LEN] = '\0';
                if (bank->seqno != strtoul(resp_seqno, NULL, 10)) {
                    check = 1;
                } else {
                    bank->seqno += 1;
                }
                // assert(bank->seqno++ == strtoul(resp_seqno, NULL, 10));
            } while (check == 1);
            

            if (strcmp(resp_msg, "Authorized") == 0) {
                bank->session_user = malloc(name_len + 1);
                assert(bank->session_user != NULL);
                snprintf(bank->session_user, name_len + 1, "%s", name);
            } else {
                // Do not establish the connection 
            }
        }
    } else if (strcmp(instruction, "withdraw") == 0) {
        assert(bank->session_user != NULL);
        if (regexec(&regex_withdraw, message, 2, matches, 0) == 0) {
            int start = matches[1].rm_so;
            int end = matches[1].rm_eo;
            int amt_len = end - start;

            unsigned char amt[amt_len + 1];
            snprintf(amt, amt_len + 1, "%s", message + start);
            amt[amt_len] = '\0';

            unsigned long withdraw_amt = strtoul(amt, NULL, 10);

            ListElem *user = list_find(bank->users, bank->session_user);
            assert(user != NULL);

            unsigned int remaining;
            size_t to_send_len = 0;
            unsigned char *to_send;
            if (withdraw_amt > user->val) {
                to_send = encrypt_and_mac(bank->s_key, "Not authorized", strlen("Not authorized"), (bank->seqno)++, &to_send_len);
            } else {
                to_send = encrypt_and_mac(bank->s_key, "Authorized", strlen("Authorized"), (bank->seqno)++, &to_send_len);
                user->val -= withdraw_amt;
            }

            bank_send(bank, to_send, to_send_len);
       }
    } else if (strcmp(message, "balance") == 0) {
        assert(bank->session_user != NULL);
        ListElem *user = list_find(bank->users, bank->session_user);
        assert(user != NULL);

        unsigned char balance[11];
        snprintf(balance, sizeof(balance), "%010u", user->val);
        balance[10] = '\0';

        size_t to_send_len = 0;
        unsigned char *to_send = encrypt_and_mac(bank->s_key, balance, sizeof(balance), (bank->seqno)++, &to_send_len);
        assert(to_send_len == 352);

        bank_send(bank, to_send, to_send_len);
    } else if (strcmp(message, "end-session") == 0) {
        assert(bank->session_user != NULL);
        unsigned char reply[] = "Ending Session";

        size_t to_send_len = 0;
        unsigned char *to_send = encrypt_and_mac(bank->s_key, reply, sizeof(reply), (bank->seqno)++, &to_send_len);
        bank_send(bank, to_send, to_send_len);

        free(bank->session_user);
        bank->session_user = NULL;
    } else {
        // Ignore
    }
}

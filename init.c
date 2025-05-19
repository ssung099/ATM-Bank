#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libgen.h>
#include <sys/stat.h>
#include <errno.h>
#include <unistd.h>
#include <openssl/rand.h>

int main(int argc, char* argv[]) {
    if (argc != 2) {
        printf("Usage:  init <filename>\n");
        return 62;
    }

    int file_len = strlen(argv[1]);
    if (argv[1][0] == '/') {
        file_len += 1; // add . before the file path
    } 

    int atm_len = file_len + 4;
    char atm_file[atm_len + 1];

    int bank_len = file_len + 5;
    char bank_file[bank_len + 1];

    char input_1[file_len + 1];
    if (argv[1][0] == '/') {
        snprintf(input_1, file_len + 1, ".%s", argv[1]);

        snprintf(atm_file, atm_len + 1, ".%s.atm", argv[1]);
        snprintf(bank_file, bank_len + 1, ".%s.bank", argv[1]);
    } else {
        snprintf(input_1, file_len + 1, "%s", argv[1]);
        snprintf(atm_file, atm_len + 1, "%s.atm", argv[1]);
        snprintf(bank_file, bank_len + 1, "%s.bank", argv[1]);
    }

    char *directory = dirname(input_1);

    if (mkdir(directory, 0777) == -1 && errno != EEXIST) {
        perror("mkdir failed");
        return 1;
    }

    if (access(atm_file, F_OK) == 0 || access(bank_file, F_OK) == 0) {
        printf("Error: one of the files already exists\n");
        return 63;
    }

    unsigned char s_key[32]; // symmetric key
    unsigned int seqno = 0;
    if (RAND_bytes(s_key, sizeof(s_key)) != 1 || RAND_bytes((unsigned char*)&seqno, sizeof(seqno)) != 1) {
        printf("Error creating initialization files\n");
        return 64;
    }
    
    FILE *atm = fopen(atm_file, "wb");
    if (!atm) {
        printf("Error creating initialization files\n");
        return 64;
    }
    fwrite(s_key, sizeof(char), 32, atm);
    fwrite(&seqno, sizeof(seqno), 1, atm);

    fclose(atm);

    FILE *bank = fopen(bank_file, "wb");
    if (!bank) {
        printf("Error creating initialization files\n");
        return 64;
    }
    fwrite(s_key, sizeof(char), 32, bank);
    fwrite(&seqno, sizeof(seqno), 1, bank);
    fclose(bank);


    printf("Successfully initialized bank state\n");
    return 0;
}
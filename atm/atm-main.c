/* 
 * The main program for the ATM.
 *
 * You are free to change this as necessary.
 */

 #include "atm.h"
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <assert.h>
 
 static char prompt[] = "ATM: ";
 
 int main(int argc, char**argv) {
     char user_input[1000 + 1];
     memset(user_input, '\0', sizeof(user_input));
 
     ATM *atm = atm_create();
     size_t file_len = strlen(argv[1]);
     if (argv[1][0] == '/') {
         file_len += 1; // add . before the file path
     } 
 
     char file_path[file_len + 1];
     if (argv[1][0] == '/') {
         snprintf(file_path, file_len + 1, ".%s", argv[1]);
     } else {
         snprintf(file_path, file_len + 1, "%s", argv[1]);
     }
 
     FILE *fp = fopen(file_path, "rb");
     if (fp == NULL) {
         printf("Error opening ATM initialization file\n");
         return 64;
     }
 
     atm -> curr_user = NULL;
     atm -> s_key = (unsigned char *) malloc(32); // Key is 32 bytes;
     assert(atm->s_key != NULL);
     // read in symmetric key
     fread(atm->s_key, 1, 32, fp);
     fread(&atm->seqno, sizeof(atm->seqno), 1, fp);
 
     printf("%s", prompt);
     fflush(stdout);
 
     while (fgets(user_input, 1000,stdin) != NULL)
     {
         // printf("SEQNO: %u\n", atm->seqno);
         atm_process_command(atm, user_input);
         if (atm -> curr_user != NULL) {
             int user_prompt_len = strlen(atm -> curr_user);
             char user_prompt[user_prompt_len + 9];
             snprintf(user_prompt, user_prompt_len + 9, "ATM (%s):  ", atm->curr_user);
             printf("%s", user_prompt);
         } else {
             printf("%s", prompt);
         }
         fflush(stdout);
     }
     return EXIT_SUCCESS;
 }
 
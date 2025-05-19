/* 
 * The main program for the Bank.
 *
 * You are free to change this as necessary.
 */

 #include <string.h>
 #include <sys/select.h>
 #include <stdio.h>
 #include <stdlib.h>
 #include "bank.h"
 #include "ports.h"
 #include <list.h>
 #include <assert.h>
 
 static const char prompt[] = "BANK: ";
 
 int main(int argc, char**argv) {
     int n;
     unsigned char sendline[1000 + 1];
     memset(sendline, '\0', sizeof(sendline));
     unsigned char recvline[1000 + 1];
     memset(recvline, '\0', sizeof(recvline));
 
     Bank *bank = bank_create();
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
         printf("Error opening bank initialization file\n");
         return 64;
     }
     bank -> s_key = (unsigned char *) malloc(32); // Key is 32 bytes;
     assert(bank->s_key != NULL);
 
     fread(bank->s_key, 1, 32, fp);
     fread(&bank->seqno, sizeof(bank->seqno), 1, fp);
     fclose(fp);
 
     printf("%s", prompt);
     fflush(stdout);
 
     while(1)
     {
         fd_set fds;
         FD_ZERO(&fds);
         FD_SET(0, &fds);
         FD_SET(bank->sockfd, &fds);
         select(bank->sockfd+1, &fds, NULL, NULL, NULL);
         if(FD_ISSET(0, &fds))
         {
             fgets(sendline, 1000,stdin);
             bank_process_local_command(bank, sendline, strlen(sendline));
             printf("%s", prompt);
             fflush(stdout);
         }
         else if(FD_ISSET(bank->sockfd, &fds))
         {
             n = bank_recv(bank, recvline, 1000);
             bank_process_remote_command(bank, recvline, n);
         }
     }
 
     return EXIT_SUCCESS;
 }
 
#include <asm/unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <string.h>
#include "syscall_struct.h"
#include<stdbool.h>
#ifndef __NR_cryptocopy
#error cryptocopy system call not defined
#endif

#define HELP_MSG(program_name, ret_code) do { \
fprintf(stderr, "USAGE: %s %s\n", program_name, \
"[-h] -e|-d|-c [-p PASSWD] INPUT_FILE OUTPUT_FILE\n" \
"   -h        Help: displays help menu.\n" \
"   -e        Encrypt: Encrypts the input file.\n" \
"   -d        Decrypt: Decrypts the input file.\n" \
" INPUT_FILE  Input file name or path.\n" \
" OUTPUT FILE Output file name or path.\n" \
"            Optional additional parameter for both -d and -e:\n" \
"               -p PASSWD    Password which should be more than 6 characters long\n"); \
exit(ret_code); \
} while(0)

#define INVALID_OPTION(op) do { \
fprintf(stderr, "Invalid Option: %s\n", op); \
} while(0)


/*
Flag:	
-e to encrypt;
-d to decrypt
-c to copy (without any encryption)
flag: -C ARG to specify the type of cipher (as a string name)
Note: this flag is mainly for the extra credit part
flag: -p ARG to specify the encryption/decryption key if needed
flag: -h to provide a helpful usage message
input file name
output file name
any other options you see fit.

You can process options using getopt(3).  (Note that specifying the password on the command line is highly insecure, but it'd make grading easier.  In reality, one would use getpass(3) to input a password.)  You should be able to execute the following command:

./test_cryptocopy -p "this is my password" -e infile outfile

*/

int check_cipher(char* cipher){
	
	if ((cipher == NULL) | (strlen(cipher) < 6)){
		return -1;
	}
	return 0;
}

void encrypt_password(char* password, unsigned char* buf)
{
	// TODO: pass argument for type of encrpt algo
	MD5_CTX md5_context;
	MD5_Init(&md5_context);
	MD5_Update(&md5_context, password, strlen(password));
	MD5_Final(buf, &md5_context);
}

int validargs(int argc, char** argv, struct sysargs* args){
	// e|d|c - required
	// -p (not needed if -c is provided)
	// -h (help)
	// -C (extra credit)
	//input file - required
	// output file - required 

	if ((argc > 6) | (argc < 4)){
		return -1;
	}

	int option;
	bool is_encrypt = false;
	bool is_decrypt = false; 
	bool is_copy = false;

	while ((option = getopt(argc, argv, "dehp:c")) != -1){
		switch(option){
			case 'e':	
				if (is_copy | is_decrypt){
					INVALID_OPTION("e");
					return -1;
				}
				args->flag = (unsigned char)0x1;
				is_encrypt = true;
				break;

			case 'd':
				if (is_encrypt | is_copy){
					INVALID_OPTION("d");
					return -1;
				}
				args->flag = (unsigned char)0x2;
				is_decrypt = true;
				break;

			case 'c':
			    if (is_decrypt | is_encrypt){
					INVALID_OPTION("c");
					return -1;
				}
				args->flag = (unsigned char)0x4;
				is_copy = true;
				break;

			case 'h':
				HELP_MSG(*argv, 0);
				return -1;
			
			case 'p':
				 args->cipher = optarg;
				 if (check_cipher(args->cipher) == -1){
					 fprintf(stderr, "Passphrase must be atleast six characters long \n");
					 return -1;
				 }

				unsigned char buf[16];
				encrypt_password(args->cipher, buf);
				args->cipher = malloc(16);
				memcpy(args->cipher, (void*) buf, 16);
				break;
			
			case '?':
				return -1;

		}

	}
  
  if ((is_encrypt | is_decrypt) && (args->cipher == NULL)){
	  fprintf(stderr, "Missing Passphrase \n");
	  return -1;
  }
  
  
  int index = optind;

  if (index < argc && index + 1 < argc){
	  args->infile = argv[index];
	  args->outfile = argv[index + 1];
	  return 0;
  } 

  fprintf(stderr, "Missing filename arguments \n");
  return -1;

}


int main(int argc, const char *argv[])
{
	int rc = 0; // remove 0

	//void *dummy = (void *) argv[1];

	struct sysargs* args = (struct sysargs*) malloc(sizeof(struct sysargs)); 
	args->cipher_len = (unsigned int)MD5_CIPHER_LEN;

	if (validargs(argc, (char**)argv, args) == -1){
		free(args);
		HELP_MSG(*argv, -1);
	}
	
  	rc = syscall(__NR_cryptocopy, (void*)args);
	
	if (rc == 0)
		printf("syscall returned %d\n", rc);
	else
		printf("syscall returned %d (errno=%d)\n", rc, errno);
	
	free(args->cipher);
	free(args);
	exit(rc);
}
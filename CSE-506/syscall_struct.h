struct sysargs{
		unsigned char flag;
		void* cipher;	
		unsigned int cipher_len;
		char* infile;
		char* outfile;
};

#define MD5_CIPHER_LEN 16
#define SHA256_LEN 32

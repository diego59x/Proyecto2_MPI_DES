#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/des.h>

/* Print Encrypted and Decrypted data packets */
void print_data(const char *tittle, const void* data, int len);

int main()
{
	/* Input data to encrypt */
	unsigned char input_data[] = "Esta es una prueba de proyecto 2";
	
	/* Init vector */
	DES_cblock iv = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	DES_set_odd_parity(&iv);

	long the_key = 18014398509481983L;
	/* Triple DES key for Encryption and Decryption */
	DES_key_schedule SchKey;
  	//set parity of key and do encrypt
	long k = 0;
	for(int i=0; i<8; ++i){
		the_key <<= 1;
		k += (the_key & (0xFE << i*8));
	}
	printf("k: %ld\n", k);
	/* k to string */
	char *str = malloc(sizeof(char)*8);
	sprintf(str, "%ld", k);
	printf("str: %s\n", str);
	/* str to DES_cblock */
	DES_cblock Key2;
	for(int i=0; i<8; ++i){
		Key2[i] = str[i];
	}
	print_data("\n Modified Key ",Key2, sizeof(Key2));
	/* Set the parity of the key */
	DES_set_odd_parity(&Key2);
	
	/* Check for Weak key generation */
	if ( -2 == (DES_set_key_checked(&Key2, &SchKey)))
	{
		printf(" Weak key ....\n");
		return 1;
	}
	
	/* Buffers for Encryption and Decryption */
	unsigned char* cipher[sizeof(input_data)];
	unsigned char* text[sizeof(input_data)];
	
	/* Triple-DES CBC Encryption */
	DES_ncbc_encrypt((unsigned char*)input_data, (unsigned char*)cipher, sizeof(input_data), &SchKey, &iv, DES_ENCRYPT);
	//DES_ncbc_encrypt((unsigned char*) plaintext, (unsigned char*) ciphertext, plaintext_len, &schedule, &iv, DES_ENCRYPT);

	/* Triple-DES CBC Decryption */
	memset(iv,0,sizeof(DES_cblock)); // You need to start with the same iv value
	DES_set_odd_parity(&iv);
	DES_ncbc_encrypt((unsigned char*)cipher, (unsigned char*)text, sizeof(input_data),&SchKey,&iv,DES_DECRYPT);
	
	/* Printing and Verifying */
	print_data("\n Original ",input_data,sizeof(input_data));
	print_data("\n Encrypted",cipher,sizeof(input_data));
	print_data("\n Decrypted",text,sizeof(input_data));
	
	return 0;
}
void print_data(const char *tittle, const void* data, int len)
{
	printf("%s : ",tittle);
	const unsigned char * p = (const unsigned char*)data;
	int i = 0;
	
	for (; i<len;++i)
		printf("%02X ", *p++);
	
	printf("\n");
}
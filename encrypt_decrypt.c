#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/des.h>

/* Triple DES key for Encryption and Decryption */
DES_cblock Key = { 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11 };
DES_key_schedule SchKey;

/* Print Encrypted and Decrypted data packets */
void print_data(const char *tittle, const void* data, int len);

int main()
{
	/* Input data to encrypt */
	unsigned char input_data[] = "This is a top secret yoooop";
	
	/* Init vector */
	DES_cblock iv = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	DES_set_odd_parity(&iv);
	
	/* Check for Weak key generation */
	if ( -2 == (DES_set_key_checked(&Key, &SchKey)))
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
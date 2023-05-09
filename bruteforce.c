#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mpi.h>
#include <openssl/des.h>

/* Print Encrypted and Decrypted data packets */
void print_data(const char *tittle, const void *data, int len);

int tryKey(long key, char *ciph, int len, DES_cblock *iv);

void decrypt(long key, char *ciph, int len, DES_cblock *iv, unsigned char* text);

/* Input data to encrypt */
unsigned char input_data[] = "test2";

int main()
{
	/* Init vector */
	DES_cblock iv = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	DES_set_odd_parity(&iv);

	long the_key = 33550000L;
	/* Triple DES key for Encryption and Decryption */
	DES_key_schedule SchKey;
	// set parity of key and do encrypt
	long k = 0;
	for (int i = 0; i < 8; ++i)
	{
		the_key <<= 1;
		k += (the_key & (0xFE << i * 8));
	}
	printf("k: %ld\n", k);
	/* k to string */
	char *str = malloc(sizeof(char) * 8);
	sprintf(str, "%ld", k);
	/* str to DES_cblock */
	DES_cblock Key2;
	for (int i = 0; i < 8; ++i)
	{
		Key2[i] = str[i];
	}
	/* Set the parity of the key */
	DES_set_odd_parity(&Key2);
	print_data("\n Original Key ", Key2, sizeof(Key2));

	/* Check for Weak key generation */
	if (-2 == (DES_set_key_checked(&Key2, &SchKey)))
	{
		printf(" Weak key ....\n");
		return 1;
	}

	/* Buffers for Encryption and Decryption */
	unsigned char *cipher[sizeof(input_data)];

	/* Triple-DES CBC Encryption */
	DES_ncbc_encrypt((unsigned char *)input_data, (unsigned char *)cipher, sizeof(input_data), &SchKey, &iv, DES_ENCRYPT);
	// DES_ncbc_encrypt((unsigned char*) plaintext, (unsigned char*) ciphertext, plaintext_len, &schedule, &iv, DES_ENCRYPT);

	print_data("\n Original ", input_data, sizeof(input_data));
	print_data("\n Encrypted", cipher, sizeof(input_data));


	unsigned char *text[sizeof(input_data)];
    /* Triple DES key for Encryption and Decryption */
	DES_key_schedule SchKey2;
	print_data("\n try Key ", Key2, sizeof(Key2));

	/* Check for Weak key generation */
	if (-2 == (DES_set_key_checked(&Key2, &SchKey2)))
	{
		printf(" Weak key ....\n");
	}
    memset(iv,0,sizeof(DES_cblock)); // You need to start with the same iv value
	DES_set_odd_parity(&iv);
	DES_ncbc_encrypt((unsigned char *)cipher, (unsigned char *)text, sizeof(input_data), &SchKey2, &iv, DES_DECRYPT);
    print_data("\n Decrypted original", text, sizeof(input_data));

	/* fuerza bruta */
	double tstart, tend;
	int N, id;
	long upper = (1L << 25); // upper bound DES keys 2^56
	long mylower, myupper;
	MPI_Status st;
	MPI_Request req;

	int ciphlen = strlen(input_data);
	MPI_Comm comm = MPI_COMM_WORLD;


	// INIT MPI
	MPI_Init(NULL, NULL);
	MPI_Comm_size(comm, &N);
	MPI_Comm_rank(comm, &id);

	tstart = MPI_Wtime();

	long found = 0L;
	int ready = 0;

	// distribuir trabajo de forma naive
	long range_per_node = upper / N;
	mylower = range_per_node * id;
	myupper = range_per_node * (id + 1) - 1;
	if (id == N - 1)
	{
		// compensar residuo
		myupper = upper;
	}
	printf("Process %d lower %ld upper %ld\n", id, mylower, myupper);

	// non blocking receive, revisar en el for si alguien ya encontro
	MPI_Irecv(&found, 1, MPI_LONG, MPI_ANY_SOURCE, MPI_ANY_TAG, comm, &req);

	for (long i = 12; i < myupper; ++i)
	{
		MPI_Test(&req, &ready, MPI_STATUS_IGNORE);
		if (ready)
			break; // ya encontraron, salir

		if (tryKey(i, (char *)cipher, ciphlen, &iv))
		{
			found = i;
			printf("Process %d found the key\n", id);
			for (int node = 0; node < N; node++)
			{
				MPI_Send(&found, 1, MPI_LONG, node, 0, comm); // avisar a otros
			}
			break;
		}
	}

	tend = MPI_Wtime();
	
	//wait y luego imprimir el texto
	if(id==0){
		MPI_Wait(&req, &st);
		unsigned char text[sizeof(input_data)];
        decrypt(found, (char *)cipher, ciphlen, &iv, text);
		printf("Key = %li\n\n", found);
		printf("%s\n", (char *)cipher);
		printf("\n\nTook %f ms to run\n", (tend-tstart));
	}
	printf("Process %d exiting\n", id);

	//FIN entorno MPI
	MPI_Finalize();

	return 0;
}

void long_to_str(long num, char* str) {
    if (num < 0) {
        *str++ = '-';
        num = -num;
    }
    if (num == 0) {
        *str++ = '0';
    } else {
        char buffer[20];
        int i = 0;
        while (num > 0) {
            buffer[i++] = (num % 10) + '0';
            num /= 10;
        }
        while (--i >= 0) {
            *str++ = buffer[i];
        }
    }
    *str = '\0';
}

void decrypt(long key, char *ciph, int len, DES_cblock *iv, unsigned char* text) {
    /* Init vector */
	DES_cblock iv2 = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	DES_set_odd_parity(&iv2);
    /* Triple DES key for Encryption and Decryption */
	DES_key_schedule SchKey2;
	// set parity of key and do encrypt
	long k = 0;
	for (int i = 0; i < 8; ++i)
	{
		key <<= 1;
		k += (key & (0xFE << i * 8));
	}
	//printf("try k: %ld\n", k);
	/* k to string */
	char str2[8] = {0};
    long_to_str(k, str2);
	/* str to DES_cblock */
	DES_cblock Key2;
	for (int i = 0; i < 8; ++i)
	{
        //printf("%c", str2[i]);
		Key2[i] = str2[i];
	}
	/* Set the parity of the key */
	DES_set_odd_parity(&Key2);
	//print_data("\n try Key ", Key2, sizeof(Key2));

	/* Check for Weak key generation */
	if (-2 == (DES_set_key_checked(&Key2, &SchKey2)))
	{
		//printf(" Weak key ....\n");
	}
    
    memset(iv2,0,sizeof(DES_cblock)); // You need to start with the same iv value
	DES_set_odd_parity(&iv2);
	DES_ncbc_encrypt((unsigned char *)ciph, (unsigned char *)text, sizeof(input_data), &SchKey2, &iv2, DES_DECRYPT);
}

int compare_texts(unsigned char *c1, unsigned char *c2) {
    for (int i = 0; i < sizeof(input_data); ++i)
    {
        if (c1[i] != c2[i])
        {
            return 0;
        }
    }
    return 1;
}

int tryKey(long key, char *ciph, int len, DES_cblock *iv)
{
    unsigned char text[sizeof(input_data)];
    decrypt(key, ciph, len, iv, text);
    //print_data("\n Decrypted try", text, sizeof(input_data));
    //print_data("\n Original try", input_data, sizeof(input_data));
	return compare_texts(text, input_data);
}

void print_data(const char *tittle, const void *data, int len)
{
	printf("%s : ", tittle);
	const unsigned char *p = (const unsigned char *)data;
	int i = 0;

	for (; i < len; ++i)
		printf("%02X ", *p++);

	printf("\n");
}
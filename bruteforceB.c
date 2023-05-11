#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mpi.h>
#include <openssl/des.h>
#include "des_crypt.h"

void print_result(const char *header, const void* data, int datalen);

int tryKey(long key, char *ciph, int len, DES_cblock *iv, int datalen);

void decrypt(long key, char *ciph, int len, DES_cblock *iv, unsigned char* text, int datalen);

void set_key(long key, DES_key_schedule *SchKey, int original);

int main()
{
	/* Init vector */
	DES_cblock iv = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	DES_set_odd_parity(&iv);
    /* Llave original */
	long the_key = 36028797019963968L;
	DES_key_schedule SchKey;
    /* Chequea paridad de la llave y la setea en SchKey */
	set_key(the_key, &SchKey, 1);
    /* lee el archivo text.txt para obtener el mensaje */
    FILE *fp;
    char input_data[1000];
    fp = fopen("text.txt", "r");
    fgets(input_data, 1000, fp);
    fclose(fp);
    /* Tamaño del mensaje y del cifrado */
    int datalen = strlen(input_data);
	/* Buffer para guardar el texto encriptado */
	unsigned char *cipher[datalen];
	/* Encriptación DES con modo CBC */
	DES_ncbc_encrypt((unsigned char *)input_data, (unsigned char *)cipher, datalen, &SchKey, &iv, DES_ENCRYPT);

	/* fuerza bruta */
	double tstart, tend; // cálculo de tiempo
	int N, id; // comm size and rank
    /* upper es el máximo Long a comprobar,
    la llave original tiene que ser menor a este número */
	long upper = (1L << 56); // upper bound DES keys 2^56
	long mylower, myupper; // local lower and upper bounds
	MPI_Status st;
	MPI_Request req;
	MPI_Comm comm = MPI_COMM_WORLD;

	// INIT MPI
	MPI_Init(NULL, NULL);
	MPI_Comm_size(comm, &N);
	MPI_Comm_rank(comm, &id);

    if (id == 0) {
        print_result("\n Original ", input_data, datalen);
        print_result("\n Encrypted", cipher, datalen);
        printf("\n");
    }
    // para esperar y que los prints salngan siempre al inicio
    MPI_Barrier(comm);

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
	printf("Process %d:\tlower %ld - upper %ld\n", id, mylower, myupper);

	// non blocking receive, revisar en el for si alguien ya encontro
	MPI_Irecv(&found, 1, MPI_LONG, MPI_ANY_SOURCE, 0, comm, &req);

	for (long i = mylower; i < myupper; ++i)
	{
        // revisa si ya termino el MPI_Irecv de arriba (si alguien ya encontro)
		MPI_Test(&req, &ready, MPI_STATUS_IGNORE);
		if (ready)
			break; // ya encontraron, salir

		if (tryKey(i, (char *)cipher, datalen, &iv, datalen))
		{
			found = i;
			printf("El proceso %d encontró la key\n", id);
			for (int node = 0; node < N; node++)
			{
                if (node == id) {
                    MPI_Cancel(&req);
                    continue;
                }
				MPI_Send(&found, 1, MPI_LONG, node, 0, comm); // avisar a otros
			}
			break;
		}
	}
	
	//wait y luego imprimir el texto
	if(id==0){
        tend = MPI_Wtime();
		unsigned char text[datalen];
        decrypt(found, (char *)cipher, datalen, &iv, text, datalen);
		printf("\nKey Found = %li\n", found);
        print_result("\n Decrypted", text, datalen);
		printf("\nDuración: %f s\n", (tend-tstart));
	}

	//FIN entorno MPI
	MPI_Finalize();

	return 0;
}

void set_key(long key, DES_key_schedule *SchKey, int original) {
    // set parity of key and do encrypt
	long k = 0;
	for (int i = 0; i < 8; ++i)
	{
		key <<= 1;
		k += (key & (0xFE << i * 8));
	}
	/* des_setparity de la libreria des/des_crypt.h */
	des_setparity((char *)&k);
	/* Pasar el numero a la llave de tipo DES_cblock */
	DES_cblock Key;
	memcpy(Key, &k, 8);
	/* Set the parity of the key */
	DES_set_odd_parity(&Key);
	/* Check for Weak key generation */
	DES_set_key_checked(&Key, SchKey);
	/* Check for Weak key generation */
	if (DES_set_key_checked(&Key, SchKey) == -2 && original)
	{
		printf("La llave %li es una weak key\n", key);
	}
}

void decrypt(long key, char *ciph, int len, DES_cblock *iv, unsigned char* text, int datalen) {
    /* Init vector */
	DES_cblock iv2 = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    memset(iv2,0,sizeof(DES_cblock)); // You need to start with the same iv value
	DES_set_odd_parity(&iv2);
    /* Triple DES key for Encryption and Decryption */
	DES_key_schedule SchKey2;
	// set parity of key and do encrypt
	set_key(key, &SchKey2, 0);
	DES_ncbc_encrypt((unsigned char *)ciph, (unsigned char *)text, datalen, &SchKey2, &iv2, DES_DECRYPT);
}

int tryKey(long key, char *ciph, int len, DES_cblock *iv, int datalen)
{
    char search_text[] = "una prueba de";
    unsigned char text[datalen];
    decrypt(key, ciph, len, iv, text, datalen);
	return strstr(text, search_text) != NULL;
}

void print_result(const char *header, const void* data, int datalen) {
	/* print original data */
	printf("%s : ", header);
	const unsigned char *p = (const unsigned char *)data;
	int i = 0;
	for (; i < datalen; ++i)
		printf("%02X ", *p++);
    /* print the ascii values */
    p = (const unsigned char *)data;
	printf("%s : ", header);
    for (i = 0; i < datalen; ++i)
        printf("%c", *p++);
	printf("\n");
}
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <mpi.h>
#include <openssl/des.h>
#include "des_crypt.h"

// Structure to represent a task
typedef struct {
    long lower;
    long upper;
} Range;

void print_result(const char *header, const void* data, int datalen);

int tryKey(long key, char *ciph, int len);

void decrypt(long key, char *ciph, int len, unsigned char* text);

void set_key(long key, DES_key_schedule *SchKey, int original);

void test_range(Range range, char *ciph, int len, int id, int N, MPI_Comm comm, MPI_Request *req, int *ready);
{
    long randKey = range.lower + (rand() % (range.upper - range.lower));
    if (tryKey(randKey, (char *)ciph, len))
    {
        printf("El proceso %d encontró la key\n", id);
        for (int node = 0; node < N; node++)
        {
            if (node == id) {
                MPI_Cancel(req);
                continue;
            }
            MPI_Send(&randKey, 1, MPI_LONG, node, 0, comm); // avisar a otros
        }
        break;
    }
    /* si lower y upper son iguales, se setea el proceso como libre y se avisa a los demas */
    if (range.lower == range.upper)
    {
        isProcessXbusy[id] = 0;
        for (int node = 0; node < N; node++)
        {
            if (node != id) {
                MPI_Send(&id, 1, MPI_INT, node, 2, comm);
            }
        }
        printf("Proceso %d ya no tiene nada que probar, avisa a los demas que esta libre\n", id);
        continue;
    }
    /* Se revisa si randKey es igual a los limites del rango */
    if (randKey == localRange.lower || randKey == localRange.upper)
    {
        /* si lo es, se crea el nuevo rango y continua */
        if (randKey == localRange.lower)
        {
            localRange.lower = randKey + 1;
        }
        else
        {
            localRange.upper = randKey - 1;
        }
        continue;
    }
    /* si el rango se puede dividir en dos, se cambia el rango, se crea uno nuevo y se envia a un proceso libre */
    else {
    Range rangeLeft = {range.lower, randKey - 1};
    Range rangeRight = {randKey + 1, range.upper};
}

int main()
{
	/* Init vector */
	DES_cblock iv = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	DES_set_odd_parity(&iv);
    /* Llave original */
	//long the_key = 36028797019963968L;
	long the_key = 120L;
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
	long upper = (1L << 8); // upper bound DES keys 2^56
	//MPI_Status st;
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

    
	long found = 0L;
	int ready = 0;
    Range initialRange;

	tstart = MPI_Wtime();

	// distribuir trabajo de forma naive
	long range_per_node = upper / N;
	initialRange.lower = range_per_node * id;
	initialRange.upper = range_per_node * (id + 1) - 1;
	if (id == N - 1)
	{
		// compensar residuo
		initialRange.upper = upper;
	}
	printf("Process %d:\tlower %ld - upper %ld\n", id, mylower, myupper);

	// non blocking receive, revisar si alguien ya encontro
	MPI_Irecv(&found, 1, MPI_LONG, MPI_ANY_SOURCE, 1, comm, &req);

    /* do shit */
    test_range(initialRange, &cipher, datalen, id, N, comm, &req, &ready);

	//wait y luego imprimir el texto
	if(id==0){
        tend = MPI_Wtime();
		unsigned char text[datalen];
        decrypt(found, (char *)cipher, datalen, text);
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

void decrypt(long key, char *ciph, int len, unsigned char* text) {
    /* Init vector */
	DES_cblock iv = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    memset(iv,0,sizeof(DES_cblock)); // You need to start with the same iv value
	DES_set_odd_parity(&iv);
    /* Triple DES key for Encryption and Decryption */
	DES_key_schedule SchKey2;
	// set parity of key and do encrypt
	set_key(key, &SchKey2, 0);
	DES_ncbc_encrypt((unsigned char *)ciph, (unsigned char *)text, len, &SchKey2, &iv, DES_DECRYPT);
}

int tryKey(long key, char *ciph, int len)
{
    char search_text[] = "una prueba de";
    unsigned char text[len];
    decrypt(key, ciph, len, text);
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
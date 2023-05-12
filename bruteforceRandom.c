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
	long randKey = 0L;
	int ready = 0;
	int isProcessXbusy[N];
	MPI_Request busyReq[N];
	for (int i = 0; i < N; ++i)
	{
		isProcessXbusy[i] = 0;
	}
	Range localRange;
	Range newRange;

	// el proceso 0 empieza, se setea como ocupado
	isProcessXbusy[0] = 1;

	// el proceso 0 setea su rango local inicial
	if (id == 0) {
		localRange.lower = 0L;
		localRange.upper = upper;
	}

	// non blocking receive, revisar si alguien ya encontro
	MPI_Irecv(&found, 1, MPI_LONG, MPI_ANY_SOURCE, 1, comm, &req);

	// mientras no se haya encontrado la llave
	do
	{
		// revisa si ya termino el MPI_Irecv de arriba (si alguien ya encontro)
		MPI_Test(&req, &ready, MPI_STATUS_IGNORE);
		printf("revisando si el proeso %d ya recibió la key\n", id);
		if (ready)
		{
			printf("El proceso %d recibió la key %ld\n", id, found);
			break;
		}
		/* si el proceso esta ocupado, prueba una llave random en su rango */
		if (isProcessXbusy[id])
		{
			printf("Proceso %d probando range %ld - %ld\n", id, localRange.lower, localRange.upper);
			if (localRange.lower == localRange.upper)
			{
				randKey = localRange.lower;
			} 
			else 
			{
				randKey = localRange.lower + (rand() % (localRange.upper - localRange.lower));
			}
			printf("Proceso %d probando llave %ld\n", id, randKey);
			/* si la llave es correcta, se envia a todos los procesos */
			if (tryKey(randKey, (char *)cipher, datalen))
			{
				found = randKey;
				printf("El proceso %d encontró la key\n", id);
				for (int node = 0; node < N; node++)
				{
					if (node == id) {
						MPI_Cancel(&req);
						continue;
					}
					MPI_Send(&found, 1, MPI_LONG, node, 1, comm); // avisar a otros
					printf("El proceso %d envió la key al proceso %d\n", id, node);
					/* envia un rango vacio para que los procesos libres ya no se queden esperando */
					localRange.lower = 0L;
					localRange.upper = 0L;
					MPI_Send(&localRange, sizeof(Range), MPI_BYTE, node, 0, comm);
					printf("El proceso %d desbloqueó al proceso %d\n", id, node);
				}
				break;
			}
			/* si no es correcta, se dividen los nuevos rangos */
			else
			{
				/* si lower y upper son iguales, se setea el proceso como libre y se avisa a los demas */
				if (localRange.lower == localRange.upper)
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
					newRange.lower = randKey + 1;
					newRange.upper = localRange.upper;
					localRange.upper = randKey - 1;
					printf("Proceso %d dividiendo rango\n", id);
					/* se busca un proceso libre */
					int freeNode = 0;
					for (int node = 0; node < N; node++)
					{
						/* cancela la recepcion de busy */
						/*if (node != id && busyReq[node] != 0) {
							printf("busyReq[%d]: %d\n", node, busyReq[node]);
							MPI_Cancel(&busyReq[node]);
						}*/
						/* actualiza los procesos libres */
						if (node != id) {
							MPI_Irecv(&isProcessXbusy[node], 1, MPI_INT, node, 2, comm, &busyReq[node]);
						}
						if (isProcessXbusy[node] == 0)
						{
							printf("Proceso %d enviando rango %ld - %ld a proceso %d\n", id, newRange.lower, newRange.upper, node);
							/* se envia el nuevo rango */
							MPI_Send(&newRange, sizeof(Range), MPI_BYTE, node, 0, comm);
							/* se setea el proceso como ocupado */
							isProcessXbusy[node] = 1;
							freeNode = 1;
							break;
						}
					}
					if (freeNode == 0) {
						printf("El proceso %d no encontró un proceso libre\n", id);
					}
				}
			}
		/* si el proceso esta libre, se queda esperando un nuevo rango */
		} else {
			printf("El proceso %d está esperando un nuevo rango\n", id);
			MPI_Recv(&localRange, sizeof(Range), MPI_BYTE, MPI_ANY_SOURCE, 0, comm, &st);
			printf("El proceso %d recibió el rango %ld - %ld\n", id, localRange.lower, localRange.upper);
			// revisa si ya termino el MPI_Irecv de arriba (si alguien ya encontro)
			MPI_Test(&req, &ready, MPI_STATUS_IGNORE);
			if (ready)
			{
				printf("El proceso %d recibió la key %ld\n", id, found);
				break;
			}
			/* al recibir un nuevo rango, se setea como ocupado y avisa a los demas */
			isProcessXbusy[id] = 1;
			for (int node = 0; node < N; node++)
			{
				if (node != id) {
					MPI_Send(&isProcessXbusy[id], 1, MPI_INT, node, 2, comm); // avisar a otros
				}
			}
		}
	} while (ready == 0);
	printf("Proceso %d terminó\n", id);

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
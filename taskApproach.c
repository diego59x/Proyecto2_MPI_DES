#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <mpi.h>
#include <string.h>
#include <openssl/des.h>
#include "des_crypt.h"

// Structure to represent a task
typedef struct {
    long lower;
    long upper;
} Task;

void print_result(const char *header, const void* data, int datalen);

int tryKey(long key, char *ciph, int len, DES_cblock *iv, int datalen);

void decrypt(long key, char *ciph, int len, unsigned char* text);

void set_key(long key, DES_key_schedule *SchKey, int original);

void processTask(Task task, int id, long *found, int *flag, char *ciph, int len, DES_cblock *iv, int datalen, MPI_Request *req);

int main() {
    int rank, size; // comm rank and size
    Task localTask;

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
    printf("Tamaño del mensaje: %d\n", datalen);
	/* Buffer para guardar el texto encriptado */
	unsigned char *cipher[datalen];
    
	/* Encriptación DES con modo CBC */
	DES_ncbc_encrypt((unsigned char *)input_data, (unsigned char *)cipher, datalen, &SchKey, &iv, DES_ENCRYPT);

	double tstart, tend; // cálculo de tiempo
    
	long upper = (1L << 56); // upper bound DES keys 2^56
	MPI_Status st;
	MPI_Request req;
    MPI_Comm comm = MPI_COMM_WORLD;

	// INIT MPI
	MPI_Init(NULL, NULL);
    MPI_Comm_rank(comm, &rank);
    MPI_Comm_size(comm, &size);

    if (rank == 0) {
        /* upper es el máximo Long a comprobar,
        la llave original tiene que ser menor a este número */
        long range_per_node = upper / size;
        long remainder = upper % size;
        long currentLower = 0;

        for (int i = 0; i < size; i++) {
            localTask.lower = currentLower;
            localTask.upper = currentLower + range_per_node - 1;

            if (i < remainder) {
                localTask.upper++;
            }

            MPI_Send(&localTask, sizeof(Task), MPI_BYTE, i, 0, comm);
            currentLower = localTask.upper + 1;
        }
    }

    MPI_Recv(&localTask, sizeof(Task), MPI_BYTE, 0, 0, comm, MPI_STATUS_IGNORE);

    // Process tasks
	long found = 0L;
    int stopFlag = 0;
    processTask(localTask, rank, &found, &stopFlag, (char *)cipher, datalen, &iv, datalen, &req);

    MPI_Bcast(&stopFlag, 1, MPI_INT, 0, MPI_COMM_WORLD);

    if (stopFlag != 0) {
        printf("Termino \n");
        MPI_Finalize();
    }

    //wait y luego imprimir el texto
	if(rank==0) {
        tend = MPI_Wtime();
		unsigned char text[datalen];
        decrypt(found, (char *)cipher, datalen, text);
		printf("\nKey Found = %li\n", found);
        print_result("\n Decrypted", text, datalen);
		printf("\nDuración: %f s\n", (tend-tstart));
	}

    MPI_Finalize();
    return 0;
}

// Function to simulate processing a task
void processTask(Task task, int id, long *found, int *flag, char *ciph, int len, DES_cblock *iv, int datalen, MPI_Request *req) {
    printf("Node %d processing task: [%li - %li]\n", id, task.lower, task.upper);
    // Perform the actual processing of the task here
    int ready = 0;
    MPI_Request req_recv = MPI_REQUEST_NULL;
    
    // non blocking receive, revisar en el for si alguien ya encontro
    MPI_Irecv(found, 1, MPI_LONG, MPI_ANY_SOURCE, 0, MPI_COMM_WORLD, &req_recv);

    for (long i = task.lower; i < task.upper; ++i)
    {
        // revisa si ya termino el MPI_Irecv de arriba (si alguien ya encontro)
        MPI_Test(&req_recv, &ready, MPI_STATUS_IGNORE);
        if (ready)
            break; // ya encontraron, salir

        if (tryKey(i, (char *)ciph, datalen, iv, datalen))
        {
            (*found) = i;
            printf("El proceso %d encontró la key %li\n", id, i);
            MPI_Cancel(&req_recv);
            MPI_Request_free(&req_recv);
            (*flag) = 1;
            break;
        }
    }

    MPI_Request_free(&req_recv);
    req[id] = MPI_REQUEST_NULL;
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
	DES_cblock iv2 = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    memset(iv2,0,sizeof(DES_cblock)); // You need to start with the same iv value
	DES_set_odd_parity(&iv2);
    /* Triple DES key for Encryption and Decryption */
	DES_key_schedule SchKey2;
	// set parity of key and do encrypt
	set_key(key, &SchKey2, 0);
	DES_ncbc_encrypt((unsigned char *)ciph, (unsigned char *)text, len, &SchKey2, &iv2, DES_DECRYPT);
}

int tryKey(long key, char *ciph, int len, DES_cblock *iv, int datalen)
{
    char search_text[] = "una prueba de";
    unsigned char text[datalen];
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
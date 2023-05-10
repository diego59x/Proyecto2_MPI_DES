#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mpi.h>
#include <openssl/des.h>

/* Print Encrypted and Decrypted data packets */
void print_data(const char *tittle, const void *data, int len);

int tryKey(long key, char *ciph, int len, DES_cblock *iv);

void decrypt(long key, char *ciph, int len, DES_cblock *iv, unsigned char* text);

void long_to_str(long num, char* str);

void set_key(long key, DES_key_schedule *SchKey, int original);

/* Input data to encrypt */
unsigned char input_data[] = "Prueba de proyecto 2";

/* Tamaño del mensaje y del cifrado */
int datalen = sizeof(input_data);

/*
 * Table giving odd parity in the low bit for ASCII characters
 */
static const char partab[128] =
{
  0x01, 0x01, 0x02, 0x02, 0x04, 0x04, 0x07, 0x07,
  0x08, 0x08, 0x0b, 0x0b, 0x0d, 0x0d, 0x0e, 0x0e,
  0x10, 0x10, 0x13, 0x13, 0x15, 0x15, 0x16, 0x16,
  0x19, 0x19, 0x1a, 0x1a, 0x1c, 0x1c, 0x1f, 0x1f,
  0x20, 0x20, 0x23, 0x23, 0x25, 0x25, 0x26, 0x26,
  0x29, 0x29, 0x2a, 0x2a, 0x2c, 0x2c, 0x2f, 0x2f,
  0x31, 0x31, 0x32, 0x32, 0x34, 0x34, 0x37, 0x37,
  0x38, 0x38, 0x3b, 0x3b, 0x3d, 0x3d, 0x3e, 0x3e,
  0x40, 0x40, 0x43, 0x43, 0x45, 0x45, 0x46, 0x46,
  0x49, 0x49, 0x4a, 0x4a, 0x4c, 0x4c, 0x4f, 0x4f,
  0x51, 0x51, 0x52, 0x52, 0x54, 0x54, 0x57, 0x57,
  0x58, 0x58, 0x5b, 0x5b, 0x5d, 0x5d, 0x5e, 0x5e,
  0x61, 0x61, 0x62, 0x62, 0x64, 0x64, 0x67, 0x67,
  0x68, 0x68, 0x6b, 0x6b, 0x6d, 0x6d, 0x6e, 0x6e,
  0x70, 0x70, 0x73, 0x73, 0x75, 0x75, 0x76, 0x76,
  0x79, 0x79, 0x7a, 0x7a, 0x7c, 0x7c, 0x7f, 0x7f,
};

/*
 * Add odd parity to low bit of 8 byte key
 */
void
des_setparity (char *p)
{
  int i;

  for (i = 0; i < 8; i++)
    {
      *p = partab[*p & 0x7f];
      p++;
    }
}

int main()
{
	/* Init vector */
	DES_cblock iv = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	DES_set_odd_parity(&iv);

    /* Llave original */
	long the_key = 18015398519481984L;
	DES_key_schedule SchKey;
    /* Chequea paridad de la llave y la setea en SchKey */
	set_key(the_key, &SchKey, 1);

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
        print_data("\n Original ", input_data, datalen);
        print_data("\n Encrypted", cipher, datalen);
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

		if (tryKey(i, (char *)cipher, datalen, &iv))
		{
			found = i;
			printf("Process %d found the key\n", id);
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
        decrypt(found, (char *)cipher, datalen, &iv, text);
		printf("\nKey = %li\n", found);
        print_data("\n Decrypted", text, datalen);
		printf("\nTook %f ms to run\n", (tend-tstart));
	}

	//FIN entorno MPI
	MPI_Finalize();

	return 0;
}

void set_key(long key, DES_key_schedule *SchKey, int original) {
    // copy of key
    long keycopy = key;
    // set parity of key and do encrypt
	long k = 0;
	for (int i = 0; i < 8; ++i)
	{
		key <<= 1;
		k += (key & (0xFE << i * 8));
	}
	des_setparity((char *)&k);
	/* k to string */
	//char *str = malloc(sizeof(char) * 8);
	//sprintf(str, "%ld", k);
	/* str to DES_cblock */
	DES_cblock Key;
	DES_cblock Key2;
	//for (int i = 0; i < 8; ++i)
	//{
	//	Key[i] = str[i];
    //    Key2[i] = str[i];
	//}
	memcpy(Key, &k, 8);
	memcpy(Key2, &k, 8);
	/* Set the parity of the key */
	DES_set_odd_parity(&Key);
	/* Check for Weak key generation */
	if (-2 == (DES_set_key_checked(&Key, SchKey)))
	{
		//printf("The key %ld is a weak key!\n", k);
	}
    if (original || keycopy == 122345L) {
        if (original) {
            printf("Original key:\n");
            printf("key copy: %ld\n", keycopy);
            //printf("key string: %s\n", str);
            print_data("key cblock sin parity", Key2, 8);
            print_data("key cblock", Key, 8);
        } else {
            printf("Key found:\n");
            printf("key copy: %ld\n", keycopy);
            //printf("key string: %s\n", str);
            print_data("key cblock sin parity", Key2, 8);
            print_data("key cblock", Key, 8);
        }
    }
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
	set_key(key, &SchKey2, 0);
    
    memset(iv2,0,sizeof(DES_cblock)); // You need to start with the same iv value
	DES_set_odd_parity(&iv2);
	DES_ncbc_encrypt((unsigned char *)ciph, (unsigned char *)text, datalen, &SchKey2, &iv2, DES_DECRYPT);
}

int tryKey(long key, char *ciph, int len, DES_cblock *iv)
{
    unsigned char text[datalen];
    decrypt(key, ciph, len, iv, text);
	return strstr(text, input_data) != NULL;
}

void print_data(const char *tittle, const void *data, int len)
{
	printf("%s : ", tittle);
	const unsigned char *p = (const unsigned char *)data;
	int i = 0;

	for (; i < len; ++i)
		printf("%02X ", *p++);

    /* print the ascii values */
    p = (const unsigned char *)data;
	printf("%s : ", tittle);
    for (i = 0; i < len; ++i)
        printf("%c", *p++);
	printf("\n");
}
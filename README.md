# Proyecto2_MPI_DES
Cifrar y descifrar textos en paralelo usando MPI

mpicc -o encrypt_decrypt encrypt_decrypt.c des_soft.c -lssl -lcrypto
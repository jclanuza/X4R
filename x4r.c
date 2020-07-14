/* 
	Cifrado PCBC-X4R-128 / LAST MODIFICATION ON JUN 7 - 2020
	---------------------------------------------------------------------------------------------
	Juan Carlos Lanuza L. BSc. | ATLAS Laboratories - Cryptography Research Laboratory
	SEP 4 - 2017 MGA-NI | RPAN: 054-5856-000017 ENC -- EXPERIMENTAL NOT RECOMENDED FOR THE USAGE

	X4R = { Experimental for Rotational - 128 (Key Block Size, Matrix 4x4) }
	
	
	Applied for: 	PCBC-X4R-128 (Propagation Main Mode) or CBC-X4R-128
	Probably Modes:	 OFB-X4R-128 or ECB-X4R-128 not recommended
*/ 

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <windows.h>

/* Error codes */
#define ERR_PWD -1
#define	ERRF_SF -2
#define ERRF_DF -3
#define msleep(x) usleep(x * 1000) // only for debbug 

/* Experimental IVs -- Long Matrix */
static unsigned char iv[] = {
"\xfc\xe8\x89\x00\x00\x00\x60\x89\xe5\x31\xd2\x64\x8b\x52" 
"\x30\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7\x4a\x26" 
"\x31\xff\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d" 
"\x01\xc7\xe2\xf0\x52\x57\x8b\x52\x10\x8b\x42\x3c\x01\xd0" 
"\x8b\x40\x78\x85\xc0\x74\x4a\x01\xd0\x50\x8b\x48\x18\x8b" 
"\x58\x20\x01\xd3\xe3\x3c\x49\x8b\x34\x8b\x01\xd6\x31\xff" 
"\x31\xc0\xac\xc1\xcf\x0d\x01\xc7\x38\xe0\x75\xf4\x03\x7d" 
"\xf8\x3b\x7d\x24\x75\xe2\x58\x8b\x58\x24\x01\xd3\x66\x8b" 
"\x0c\x4b\x8b\x58\x1c\x01\xd3\x8b\x04\x8b\x01\xd0\x89\x44" 
"\x24\x24\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x58\x5f\x5a\x8b" 
"\x12\xeb\x86\x5d\x68\x33\x32\x00\x00\x68\x77\x73\x32\x5f" 
"\x54\x68\x4c\x77\x26\x07\xff\xd5\xb8\x90\x01\x00\x00\x29" 
"\xc4\x54\x50\x68\x29\x80\x6b\x00\xff\xd5\x50\x50\x50\x50" 
"\x40\x50\x40\x50\x68\xea\x0f\xdf\xe0\xff\xd5\x89\xc7\x31" 
"\xdb\x53\x68\x02\x00\x11\x5c\x89\xe6\x6a\x10\x56\x57\x68" 
"\xc2\xdb\x37\x67\xff\xd5\x53\x57\x68\xb7\xe9\x38\xff\xff" 
"\xd5\x53\x53\x57\x68\x74\xec\x3b\xe1\xff\xd5\x57\x89\xc7" 
"\x68\x75\x6e\x4d\x61\xff\xd5\x68\x63\x6d\x64\x00\x89\xe3" 
"\x57\x57\x57\x31\xf6\x6a\x12\x59\x56\xe2\xfd\x66\xc7\x44" 
"\x24\x3c\x01\x01\x8d\x44\x24\x10\xc6\x00\x44\x54\x50\x56" 
"\x56\x56\x46\x56\x4e\x56\x56\x53\x56\x68\x79\xcc\x3f\x86" 
"\xff\xd5\x89\xe0\x4e\x56\x46\xff\x30\x68\x08\x87\x1d\x60" 
"\xff\xd5\xbb\xf0\xb5\xa2\x56\x68\xa6\x95\xbd\x9d\xff\xd5" 
"\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb\x47\x13\x72\x6f" 
"\x6a\x00\x53\xff\xd5"	};


uint32_t init_vector  = 0x3D; // Teorical IV-Const
static uint32_t k[16] = {0xFF, 0xFE, 0x23, 0x7C, 0x22, 0xCE, 0x01, 0x00, 
				  0xEA, 0xFF, 0x97, 0x14, 0xB2, 0x6D, 0x5E, 0x0A};
						 
static void cipher(unsigned char*__source_file, unsigned char*__ciphered_file);
static void decipher(unsigned char*__ciphered_file, unsigned char*__deciphered_file);

static unsigned int rotl(uint32_t x, uint32_t r) { return ((x << r) | (x >> 64 - r)); }
static unsigned int rotr(uint32_t x, uint32_t r) { return ((x >> r) | (x << 64 - r)); }

unsigned int main(int argc, char *argv[])
{
	unsigned int opc = 0;
	unsigned char sfile[100], dfile[100];
	
	fprintf(stdout,"(1) Cifrar | (2) Decifrar : "); fscanf(stdin,"%d",&opc);
	switch(opc)
	{
		case 1:
		{ 
			fflush(stdout); fflush(stdin);
			fprintf(stdout,"Archivo a Cifrar: "); gets(sfile);
			fprintf(stdout,"Archivo Cifrado: "); gets(dfile);
			for(short int i = 0;i < (strlen(sfile) + 18);i++) printf("-"); puts("");
			cipher(sfile,dfile);		
			break; 
		}
		case 2:
		{
			fflush(stdout); fflush(stdin);
			fprintf(stdout,"Archivo a Decifrar: "); gets(sfile);
			fprintf(stdout,"Archivo Decifrado: "); gets(dfile);
			for(short int i = 0;i < (strlen(sfile) + 18);i++) printf("-"); puts("");
			decipher(sfile,dfile);
			break;				
		}
		default: { fprintf(stderr,"No option detected\n"); exit(EXIT_FAILURE); }
	}
	getchar();
	exit(-1);
}

static void cipher(unsigned char *src_file, unsigned char *dst_file)
{	
	FILE *udata, *cdata;
	if(k == '\0') { fprintf(stderr,"Es necesaria una clave\n"); exit(ERR_PWD); }
	else if((udata = fopen(src_file, "rb")) == NULL) { fprintf(stderr,"\n\n%s : ERR :: %d\n\a",src_file,ERRF_SF); exit(ERRF_SF); }
	else if((cdata = fopen(dst_file, "wb")) == NULL) { fprintf(stderr,"\n\n%s : ERR :: %d\n\a",dst_file,ERRF_SF); exit(ERRF_DF); }	
	

	static char unencrypted, encrypted;
	for(uint8_t op = 1; (unencrypted = getc(udata)) != EOF; op++)
	{
		
		/* Vector de Inicializacion Unica CBC-Mode*/
		//unencrypted ^= init_vector;		
		
		/* Ruptura de la clave */
		static uint32_t ks[16];
		ks[ 0] = k[ 3]; ks[ 1] = k[ 2]; ks[ 2] = k[ 0]; ks [3] = k[ 1]; // 1 - 4 Blocks Mixing Process
		ks[ 4] = k[ 6]; ks[ 5] = k[ 4]; ks[ 6] = k[ 7]; ks[ 7] = k[ 5]; // 2 - 4 Blocks Mixing Process
		ks[ 8] = k[ 9]; ks[ 9] = k[10]; ks[10] = k[11]; ks[11] = k[ 8]; // 3 - 4 Blocks Mixing Process
		ks[12] = k[15]; ks[13] = k[14]; ks[14] = k[13]; ks[15] = k[12]; // 4 - 4 Blocks Mixing Process
		for(uint8_t i = 0;i <= 15;i++) { k[i] = ks[i]; }
		
		// ROT-MATRIX --> Only Rotational Matrix
		ks[0] = k[1]; ks[1] = k[2]; ks[2] = k[3]; ks[3] = k[0];
		ks[4] = k[6]; ks[5] = k[7]; ks[6] = k[4]; ks[7]  = k[5];
		ks[8] = k[10]; ks[9] = k[11]; ks[10] = k[8]; ks[11] = k[9];		
		ks[12] = k[13];	ks[13] = k[14]; ks[14] = k[15]; ks[15] = k[12];	
		for(uint8_t i = 0;i <= 15;i++) { k[i] = ks[i]; }
		
		switch(op) /* ROTATORY DATA OPERATION */
		{
			case 1:
				{		
					// OP-1 cifrado
					encrypted = (((unencrypted ^ init_vector) ^ k[0]) + k[1]) ^ (k[2] ^ rotl(k[3], 3)); 	
					
					//PCBC Operation 
					init_vector = encrypted ^ unencrypted;
					//CBC Operation
					//init_vector = encrypted;
						
					// ROT-MATRIX --> Only Rotational Matrix
					ks[0] = k[1]; ks[1] = k[2]; ks[2] = k[3]; ks[3] = k[0];
					ks[4] = k[6]; ks[5] = k[7]; ks[6] = k[4]; ks[7]  = k[5];
					ks[8] = k[10]; ks[9] = k[11]; ks[10] = k[8]; ks[11] = k[9];		
					ks[12] = k[13];	ks[13] = k[14]; ks[14] = k[15]; ks[15] = k[12];	
					for(uint8_t i = 0;i <= 15;i++) { k[i] = ks[i]; }
					
					putc(encrypted, cdata);		
					break;		
				}
			case 2:
				{	
					// OP-2 difusion
					encrypted = (((((unencrypted ^ init_vector) ^ k[4]) ^ rotl(k[5], 2)) ^ k[6]) ^ k[7]);
					
					//PCBC Operation 
					init_vector = encrypted ^ unencrypted;
					//CBC Operation
					//init_vector = encrypted;
						
					// ROT-MATRIX --> Only Rotational Matrix
					ks[0] = k[1]; ks[1] = k[2]; ks[2] = k[3]; ks[3] = k[0];
					ks[4] = k[6]; ks[5] = k[7]; ks[6] = k[4]; ks[7]  = k[5];
					ks[8] = k[10]; ks[9] = k[11]; ks[10] = k[8]; ks[11] = k[9];		
					ks[12] = k[13];	ks[13] = k[14]; ks[14] = k[15]; ks[15] = k[12];	
					for(uint8_t i = 0;i <= 15;i++) { k[i] = ks[i]; }
					
					putc(encrypted, cdata);	
					break;
				}
			case 3:
				{
					// OP-3 cifrado		
					encrypted = (((unencrypted ^ init_vector) + rotr(k[12], 3)) ^ k[15]) ^ (k[13] ^ k[14]); 
					
					//PCBC Operation 
					init_vector = encrypted ^ unencrypted;
					//CBC Operation
					//init_vector = encrypted;
					
					// ROT-MATRIX --> Only Rotational Matrix
					ks[0] = k[1]; ks[1] = k[2]; ks[2] = k[3]; ks[3] = k[0];
					ks[4] = k[6]; ks[5] = k[7]; ks[6] = k[4]; ks[7]  = k[5];
					ks[8] = k[10]; ks[9] = k[11]; ks[10] = k[8]; ks[11] = k[9];		
					ks[12] = k[13];	ks[13] = k[14]; ks[14] = k[15]; ks[15] = k[12];	
					for(uint8_t i = 0;i <= 15;i++) { k[i] = ks[i]; }					
					
					putc(encrypted, cdata);
					break;
				}
			case 4:
				{
					// OP-4 difusion
					encrypted = (rotl(((rotl(k[9], 3) + k[10]) - (k[8] ^ rotr(k[11], 5))), 7) ^ (unencrypted ^ init_vector));
					
					//PCBC Operation 
					init_vector = encrypted ^ unencrypted;
					//CBC Operation
					//init_vector = encrypted;
					
					// ROT-MATRIX --> Only Rotational Matrix
					ks[0] = k[1]; ks[1] = k[2]; ks[2] = k[3]; ks[3] = k[0];
					ks[4] = k[6]; ks[5] = k[7]; ks[6] = k[4]; ks[7]  = k[5];
					ks[8] = k[10]; ks[9] = k[11]; ks[10] = k[8]; ks[11] = k[9];		
					ks[12] = k[13];	ks[13] = k[14]; ks[14] = k[15]; ks[15] = k[12];	
					for(uint8_t i = 0;i <= 15;i++) { k[i] = ks[i]; }					
					
					putc(encrypted, cdata);
					break;
				}	 			
		}
	
		// Wide Matrix Mixing 
		ks[ 0] = k[12];		ks[5] ^= k[9];		ks[10] ^= k[ 2];	ks[3] ^= k[15];
		for(uint8_t i = 0;i <= 15;i++) { k[i] = ks[i]; }
		
		if(op == 4) { op = 0;} /* DIAL COUNTER CONTROLLER */
	}	
	if(fclose(udata) != 0) { printf("Error en cierre de archivo de texto plano\n"); } 
	else puts("Cierre Exitoso");
	if(fclose(cdata) != 0) { printf("Error en cierre de archivo cifrado \n"); } 
	else puts("Cierre Exitoso");
	printf("Used Key: %X\n",k[0]);
	exit(EXIT_SUCCESS);
}

static void decipher(unsigned char *src_file, unsigned char *dst_file)
{
	FILE *udata, *cdata;
	
	if(k == '\0') { fprintf(stderr,"Es necesaria una clave\n"); exit(ERR_PWD); }
	else if((cdata = fopen(src_file, "rb")) == NULL) { fprintf(stderr,"\n\n%s : ERR :: %d\n\a",src_file,ERRF_SF); exit(ERRF_SF); }
	else if((udata = fopen(dst_file, "wb")) == NULL) { fprintf(stderr,"\n\n%s : ERR :: %d\n\a",dst_file,ERRF_SF); exit(ERRF_DF); }	
	

	static uint32_t unencrypted = 0, encrypted = 0;
	for(uint8_t op = 1;(encrypted = getc(cdata)) != EOF;op++)
	{
		
		/* Ruptura de la clave */
		static uint32_t ks[16];
		ks[ 0] = k[ 3]; ks[ 1] = k[ 2]; ks[ 2] = k[ 0]; ks [3] = k[ 1]; // 1 - 4 Blocks Mixing Process
		ks[ 4] = k[ 6]; ks[ 5] = k[ 4]; ks[ 6] = k[ 7]; ks[ 7] = k[ 5]; // 2 - 4 Blocks Mixing Process
		ks[ 8] = k[ 9]; ks[ 9] = k[10]; ks[10] = k[11]; ks[11] = k[ 8]; // 3 - 4 Blocks Mixing Process
		ks[12] = k[15]; ks[13] = k[14]; ks[14] = k[13]; ks[15] = k[12]; // 4 - 4 Blocks Mixing Process
		for(uint8_t i = 0;i <= 15;i++) { k[i] = ks[i]; }
		
		// ROT-MATRIX --> Only Rotational Matrix
		ks[0] = k[1]; ks[1] = k[2]; ks[2] = k[3]; ks[3] = k[0];
		ks[4] = k[6]; ks[5] = k[7]; ks[6] = k[4]; ks[7]  = k[5];
		ks[8] = k[10]; ks[9] = k[11]; ks[10] = k[8]; ks[11] = k[9];		
		ks[12] = k[13];	ks[13] = k[14]; ks[14] = k[15]; ks[15] = k[12];	
		for(uint8_t i = 0;i <= 15;i++) { k[i] = ks[i]; }
		
		switch(op)
		{
			case 1:
				{
					// OP-1-R cifrado INV
					unencrypted = ((((((k[2] ^ rotl(k[3], 3)))) ^ encrypted) - k[1]) ^ k[0]);
					
					/* PCBC Mode Operation */
					/* Vector de Inicializacion Unica (Invertida) */
					unencrypted ^= init_vector;
					init_vector  = encrypted ^ unencrypted;
					
					
					/* CBC Mode Operation */
					/* Vector de Inicializacion Unica (Invertida) */
					//unencrypted ^= init_vector; 
					//init_vector = encrypted; // Asignar valor de cadena
					
					// ROT-MATRIX --> Only Rotational Matrix
					ks[0] = k[1]; ks[1] = k[2]; ks[2] = k[3]; ks[3] = k[0];
					ks[4] = k[6]; ks[5] = k[7]; ks[6] = k[4]; ks[7]  = k[5];
					ks[8] = k[10]; ks[9] = k[11]; ks[10] = k[8]; ks[11] = k[9];		
					ks[12] = k[13];	ks[13] = k[14]; ks[14] = k[15]; ks[15] = k[12];	
					for(uint8_t i = 0;i <= 15;i++) { k[i] = ks[i]; }
					
					putc(unencrypted, udata);
					break;
				}
			case 2:
				{
					// OP-2-R difusion INV
					unencrypted = (((encrypted ^ k[7]) ^ k[6]) ^ rotl(k[5], 2) ^ k[4]);	
					
					/* PCBC Mode Operation */
					/* Vector de Inicializacion Unica (Invertida) */
					unencrypted ^= init_vector;
					init_vector  = encrypted ^ unencrypted;
					
					
					/* CBC Mode Operation */
					/* Vector de Inicializacion Unica (Invertida) */
					//unencrypted ^= init_vector; 
					//init_vector = encrypted; // Asignar valor de cadena
												
					// ROT-MATRIX --> Only Rotational Matrix
					ks[0] = k[1]; ks[1] = k[2]; ks[2] = k[3]; ks[3] = k[0];
					ks[4] = k[6]; ks[5] = k[7]; ks[6] = k[4]; ks[7]  = k[5];
					ks[8] = k[10]; ks[9] = k[11]; ks[10] = k[8]; ks[11] = k[9];		
					ks[12] = k[13];	ks[13] = k[14]; ks[14] = k[15]; ks[15] = k[12];	
					for(uint8_t i = 0;i <= 15;i++) { k[i] = ks[i]; }				
					
					putc(unencrypted, udata);
					break;
				}
			case 3:
				{
					// OP-3-R cifrado INV
					unencrypted	= ((((k[13] ^ k[14]) ^ encrypted) ^ k[15]) - rotr(k[12], 3));
						
					/* PCBC Mode Operation */
					/* Vector de Inicializacion Unica (Invertida) */
					unencrypted ^= init_vector;
					init_vector  = encrypted ^ unencrypted;
					
					
					/* CBC Mode Operation */
					/* Vector de Inicializacion Unica (Invertida) */
					//unencrypted ^= init_vector; 
					//init_vector = encrypted; // Asignar valor de cadena
						
					// ROT-MATRIX --> Only Rotational Matrix
					ks[0] = k[1]; ks[1] = k[2]; ks[2] = k[3]; ks[3] = k[0];
					ks[4] = k[6]; ks[5] = k[7]; ks[6] = k[4]; ks[7]  = k[5];
					ks[8] = k[10]; ks[9] = k[11]; ks[10] = k[8]; ks[11] = k[9];		
					ks[12] = k[13];	ks[13] = k[14]; ks[14] = k[15]; ks[15] = k[12];	
					for(uint8_t i = 0;i <= 15;i++) { k[i] = ks[i]; }					
					
					putc(unencrypted, udata);
					break;
				}
			case 4:
				{
					// OP-4-R difusion INV
					unencrypted	= (rotl(((rotl(k[9], 3) + k[10]) - ((k[8]) ^ rotr(k[11], 5))), 7) ^ encrypted);	
						
					/* PCBC Mode Operation */
					/* Vector de Inicializacion Unica (Invertida) */
					unencrypted ^= init_vector;
					init_vector  = encrypted ^ unencrypted;
					
					
					/* CBC Mode Operation */
					/* Vector de Inicializacion Unica (Invertida) */
					//unencrypted ^= init_vector; 
					//init_vector = encrypted; // Asignar valor de cadena
						
					// ROT-MATRIX --> Only Rotational Matrix
					ks[0] = k[1]; ks[1] = k[2]; ks[2] = k[3]; ks[3] = k[0];
					ks[4] = k[6]; ks[5] = k[7]; ks[6] = k[4]; ks[7]  = k[5];
					ks[8] = k[10]; ks[9] = k[11]; ks[10] = k[8]; ks[11] = k[9];		
					ks[12] = k[13];	ks[13] = k[14]; ks[14] = k[15]; ks[15] = k[12];	
					for(uint8_t i = 0;i <= 15;i++) { k[i] = ks[i]; }					
		
					putc(unencrypted, udata);
					break;
				}
		}
		// Wide Matrix Mixing
		ks[ 0] = k[12];		ks[5] ^= k[9];		ks[10] ^= k[ 2];		ks[3] ^= k[15];
		for(uint8_t i = 0;i <= 15;i++) { k[i] = ks[i]; }	
		
		if(op == 4) { op = 0;} /* DIAL COUNTER CONTROLLER */
	}	
	
	fclose(cdata);
	fclose(udata);	
	exit(EXIT_SUCCESS);
}
/* END guys :) */

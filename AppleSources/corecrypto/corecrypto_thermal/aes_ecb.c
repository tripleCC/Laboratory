/* Copyright (c) (2016,2017,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */


#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <zlib.h>
#include <corecrypto/ccaes.h>
#include <Accelerate/ClockServices.h>

// extern void ccdigest_update(const struct ccdigest_info *di, ccdigest_ctx_t ctx, size_t len, const void *data);

typedef struct
{
    const struct ccmode_ecb *ecb;
	const void *key;
	size_t nblocks;
	const void *dataIn;
	void *dataOut;
} Parameters;


// this templtae works for both encrypt and decrypt
static void BlockECB(const Parameters *parameters)
{
	parameters->ecb->ecb(parameters->key, parameters->nblocks, parameters->dataIn, parameters->dataOut);
}


static void Driver(unsigned int iterations, void *parameters)
{
    Parameters *p = (Parameters *) parameters;
    while (iterations--) {
        BlockECB(p);
	}
}

extern uint32_t	single_test;

void thermalAES_ECB(uint32_t    ITERATIONS, uint32_t    data_size);

void thermalAES_ECB(uint32_t    ITERATIONS, uint32_t    data_size)
{


	char	*dataIn, *dataEncrypted, *dataDecrypted;
	uint32_t		i;
	double TotalETime = 0;
	double TotalDTime = 0;
    uint32_t    NUM_BLOCKS = data_size/16;
    if ((NUM_BLOCKS*16)!=data_size) {
        data_size = 16*NUM_BLOCKS;
        fprintf(stderr,"warning : adjusted data_size to %d\n", data_size);
    }

	const struct ccmode_ecb *encrypt = ccaes_ecb_encrypt_mode();
    const struct ccmode_ecb *decrypt = ccaes_ecb_decrypt_mode();
	unsigned int		keyLen=16;
	uint8_t 	gkey[32];

if (!single_test)
	for (i=0;i<32;i++) gkey[i] = (uint8_t)arc4random();

	ccecb_ctx_decl(encrypt->size, ekey);
	encrypt->init(encrypt, ekey, keyLen, (const uint8_t *) gkey);

	ccecb_ctx_decl(decrypt->size, dkey);
	decrypt->init(decrypt, dkey, keyLen, (const uint8_t *) gkey);

	if (!(dataIn = calloc(data_size,1))) {
		fprintf(stderr,"error : calloc dataIn %d \n", data_size);
		exit(1);
	}
	if (!(dataEncrypted = calloc(data_size,1))) {
		fprintf(stderr,"error : calloc dataEncrypted %d \n", data_size);
		exit(1);
	}
	if (!(dataDecrypted = calloc(data_size,1))) {
		fprintf(stderr,"error : calloc dataDecrypted %d \n", data_size);
		exit(1);
	}

if (!single_test) {
	for (i=0;i<data_size;i++) { 
			dataIn[i] = (char)arc4random();
			dataEncrypted[i] = dataDecrypted[i] = 0;
	}

	// Encrypted
    {
            Parameters parameters =
            {
                .ecb = encrypt,
				.key = ekey,
				.nblocks = data_size/16,
				.dataIn = dataIn,
				.dataOut = dataEncrypted,
            };
            TotalETime += MeasureNetTimeInCPUCycles(Driver, ITERATIONS, &parameters, 1);

    }
}

	// Decrypted
    {
            Parameters parameters =
            {
                .ecb = decrypt,
				.key = dkey,
				.nblocks = data_size/16,
				.dataIn = dataEncrypted,
				.dataOut = dataDecrypted,
            };
            TotalDTime += MeasureNetTimeInCPUCycles(Driver, ITERATIONS, &parameters, 1);

    }

if (!single_test) {
	for (i=0;i<data_size;i++) if (dataIn[i]!=dataDecrypted[i]) {
			fprintf(stderr, "error at i = %d, %6d %6d %6d\n", i, dataIn[i], dataEncrypted[i], dataDecrypted[i]);
			break;
	}
}

	printf("  aes-ecb : %.2f/%.2f\n", (TotalETime/data_size), (TotalDTime/data_size));

	free(dataIn);
	free(dataEncrypted);
	free(dataDecrypted);

}

/*
    function that tests corner cases (various number of input blocks) with known constants in the key and data
*/
#define Dsize   4096
#define nBlocks (Dsize/16)

uint32_t validate_ecb_checksum[] = { 0xecdfb631, 0xd39bf0fa, 0xc5bb6dbc };

void validateAES_ECB(void);

void validateAES_ECB(void)
{


	unsigned char	dataIn[Dsize], dataEncrypted[Dsize], dataDecrypted[Dsize];
	size_t i, j;

	const struct ccmode_ecb *encrypt = ccaes_ecb_encrypt_mode();
    const struct ccmode_ecb *decrypt = ccaes_ecb_decrypt_mode();
    ccecb_ctx_decl(encrypt->size, ekey);
	ccecb_ctx_decl(decrypt->size, dkey);

	unsigned int		keyLen;
	uint8_t 	        gkey[32];
    for (i=0;i<32;i++) gkey[i] = (uint8_t)i;
	for (i=0;i<Dsize;i++) dataIn[i] = (unsigned char)i; 
    bzero(dataEncrypted,Dsize);
    bzero(dataDecrypted,Dsize);

    for (keyLen=16;keyLen<=32;keyLen+=8) {  /* aes-128/aes-192/aes-224 */

        encrypt->init(encrypt, ekey, keyLen, (const uint8_t *) gkey);
	    decrypt->init(decrypt, dkey, keyLen, (const uint8_t *) gkey);
  
        /* encrypt in nblocks of 1,2,...,10,(256-55) */ 
        j=0; 
        for (i=1;i<=10;i++) { 
            encrypt->ecb(ekey, i, &dataIn[j], &dataEncrypted[j]);
            j+=(i<<4);
        }
        i = (4096-j)>>4;
        encrypt->ecb(ekey, i, &dataIn[j], &dataEncrypted[j]);

        /* decrypt in nblocks of 1,2,...,10,(256-55) */ 
        j=0; 
        for (i=1;i<=10;i++) { 
            decrypt->ecb(dkey, i, &dataEncrypted[j], &dataDecrypted[j]);
            j+=(i<<4);
        }
        i = (4096-j)>>4;
        decrypt->ecb(dkey, i, &dataEncrypted[j], &dataDecrypted[j]);

        /* check whether dataIn == dataDecrypted */
        for (i=0;i<Dsize;i++) {
            if (dataIn[i] != dataDecrypted[i]) {
                fprintf(stderr, "error : ECB mode AES-%d error (mismatched at byte %zu\n", keyLen*8, i);
                exit(1);
            }
        }

        /* check crc32 of encrypted data */
        uint32_t    checksum = (uint32_t) (crc32(0, dataEncrypted, Dsize) ^ adler32(0, dataEncrypted, Dsize));
        if (checksum!=validate_ecb_checksum[keyLen/8-2]) {
                fprintf(stderr, "error : encrypted data checksum (crc32^adler32) failed\n");
                exit(2);
        }
    }
    fprintf(stderr, "AES-ECB validated\n");
}

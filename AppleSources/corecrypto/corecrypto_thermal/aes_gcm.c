/* Copyright (c) (2016,2017,2018,2019) Apple Inc. All rights reserved.
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
#include <string.h>
#include <corecrypto/ccaes.h>
#include <corecrypto/ccmode.h>
#include "thermalCrypto.h"
#include <Accelerate/ClockServices.h>

// extern void ccdigest_update(const struct ccdigest_info *di, ccdigest_ctx_t ctx, size_t len, const void *data);

typedef struct
{
    const struct ccmode_gcm *mode;
	void *ctx;
	void *Mac;
	size_t len;
	const void *dataIn;
	void *dataOut;
} Parameters;


// this template works for both encrypt and decrypt
static void Blockgcm(const Parameters *parameters)
{
    ccgcm_init(parameters->mode, (ccgcm_ctx *) parameters->ctx, 16, "261B72350558F2E9DCF613070383EDBF");
    ccgcm_set_iv(parameters->mode, (ccgcm_ctx *) parameters->ctx, 11, "66E69A111892584FB5ED52");
    ccgcm_aad(parameters->mode, (ccgcm_ctx *) parameters->ctx, 32, "66E69A111892584FB5ED524A744DA3EE87000000000001001100001400E40800");
    ccgcm_update(parameters->mode, (ccgcm_ctx *) parameters->ctx, parameters->len, parameters->dataIn, parameters->dataOut);
    ccgcm_finalize(parameters->mode, (ccgcm_ctx *) parameters->ctx, 16, parameters->Mac); 
}

static void Driver(unsigned int iterations, void *parameters)
{
    Parameters *p = (Parameters *) parameters;
    while (iterations--) {
        Blockgcm(p);
	}
}

extern uint32_t single_test;

void thermalAES_GCM(uint32_t ITERATIONS, uint32_t data_size)
{


	char	*dataIn, *dataEncrypted, *dataDecrypted;
    uint8_t   EncMac[16], DecMac[16];
	uint32_t		i;
	double TotalETime = 0;
	double TotalDTime = 0;

    bzero(EncMac,16);
    bzero(DecMac,16);

	const struct ccmode_gcm *encrypt = ccaes_gcm_encrypt_mode();
    const struct ccmode_gcm *decrypt = ccaes_gcm_decrypt_mode();

	ccgcm_ctx_decl(encrypt->size, ectx);
	ccgcm_ctx_decl(decrypt->size, dctx);

	if (!(dataIn = calloc(data_size, 1))) {
		fprintf(stderr,"error : calloc dataIn %d \n", data_size);
		exit(1);
	}
	if (!(dataEncrypted = calloc(data_size, 1))) {
		fprintf(stderr,"error : calloc dataEncrypted %d \n", data_size);
		exit(1);
	}
	if (!(dataDecrypted = calloc(data_size, 1))) {
		fprintf(stderr,"error : calloc dataDecrypted %d \n", data_size);
		exit(1);
	}

	for (i=0;i<data_size;i++) { 
			dataIn[i] = (char)arc4random();
			dataEncrypted[i] = dataDecrypted[i] = 0;
	}

if (!single_test) {
	// Encrypted
    {
            Parameters parameters =
            {
                .mode = encrypt,
				.ctx = ectx,
				.Mac = EncMac,
				.len = data_size,
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
                .mode = decrypt,
				.ctx = dctx,
				.Mac = DecMac,
				.len = data_size,
				.dataIn = dataEncrypted,
				.dataOut = dataDecrypted,
            };
            TotalDTime += MeasureNetTimeInCPUCycles(Driver, ITERATIONS, &parameters, 1);
    }

if (!single_test) {
	for (i=0;i<data_size;i++) if (dataIn[i]!=dataDecrypted[i]) {
			printf("error at i = %d, %6d %6d %6d\n", i, dataIn[i], dataEncrypted[i], dataDecrypted[i]);
			break;
	}

    for (i=0;i<16;i++) if (EncMac[i]!=DecMac[i]) {
            printf("Mac error at i = %d, %d, %d\n", i, EncMac[i], DecMac[i]);
            break;
    }
}

	printf("  aes-gcm : %.2f/%.2f", (TotalETime/data_size),(TotalDTime/data_size));
#if 0
	if (data_size*originalITERATIONS> (1 << 24)) {
		printf("    *** maximum data_size*iterations = 1<<24, modified iterations to %d\n", ITERATIONS); 
	}
#endif
	printf("\n");


	free(dataIn);
	free(dataEncrypted);
	free(dataDecrypted);

}


#include <zlib.h>

/*
    function that tests corner cases (various number of input blocks) with known constants in the key and data
*/
#define Dsize   4096
#define nBlocks (Dsize/16)

uint32_t validate_checksum[] = { 0x353c3921, 0x4c0285d8, 0xe1ca52b7 };

void validateAES_GCM(void);

void validateAES_GCM(void)
{
	uint8_t	dataIn[Dsize], dataEncrypted[Dsize], dataDecrypted[Dsize];
    uint8_t   EncMac[16], DecMac[16];
	size_t i, j;

	const struct ccmode_gcm *encrypt = ccaes_gcm_encrypt_mode();
    const struct ccmode_gcm *decrypt = ccaes_gcm_decrypt_mode();

	ccgcm_ctx_decl(encrypt->size, ectx);
	ccgcm_ctx_decl(decrypt->size, dctx);

	unsigned int keyLen;
    uint8_t gkey[32];
    uint8_t iv[CCGCM_IV_NBYTES];
    for (i = 0; i < 32; i++) gkey[i] = (uint8_t)i;
    for (i = 0; i < CCGCM_IV_NBYTES; i++) iv[i] = (uint8_t)i;
	for (i = 0; i < Dsize; i++) dataIn[i] = (uint8_t)i;
    bzero(dataEncrypted,Dsize);
    bzero(dataDecrypted,Dsize);

    for (keyLen=16;keyLen<=32;keyLen+=8) {  /* aes-128/aes-192/aes-224 */

        ccgcm_init(encrypt, ectx, keyLen, gkey);
        ccgcm_set_iv(encrypt, ectx, CCGCM_IV_NBYTES, iv);
        ccgcm_aad(encrypt, ectx, 0, NULL);


        ccgcm_init(decrypt, dctx, keyLen, gkey);
        ccgcm_set_iv(decrypt, dctx, CCGCM_IV_NBYTES, iv);
        ccgcm_aad(decrypt, dctx, 0, NULL);

  
        /* encrypt in nblocks of 1,2,...,10,(256-55) */ 
        j=0; 
        for (i=1;i<=10;i++) { 
            ccgcm_update(encrypt, ectx, i<<4, &dataIn[j], &dataEncrypted[j]);
            j+=(i<<4);
        }
        i = (4096-j)>>4;
        ccgcm_update(encrypt, ectx, i<<4, &dataIn[j], &dataEncrypted[j]);
        ccgcm_finalize(encrypt, ectx, 16, EncMac); 

        /* decrypt in nblocks of 1,2,...,10,(256-55) */ 
        j=0; 
        for (i=1;i<=10;i++) { 
            ccgcm_update(decrypt, dctx, i<<4, &dataEncrypted[j], &dataDecrypted[j]);
            j+=(i<<4);
        }
        i = (4096-j)>>4;
        ccgcm_update(decrypt, dctx, i<<4, &dataEncrypted[j], &dataDecrypted[j]);
        ccgcm_finalize(decrypt, dctx, 16, DecMac); 

        /* check whether dataIn == dataDecrypted */
        for (i=0;i<Dsize;i++) {
            if (dataIn[i] != dataDecrypted[i]) {
                fprintf(stderr, "error : GCM mode AES-%d error (mismatched at byte %zu\n", keyLen*8, i);
                exit(1);
            }
        }

        /* check Mac */
        if (memcmp(EncMac, DecMac, 16)) {
                fprintf(stderr, "error : GCM mode encrypt and decrypt Mac Mismatch\n");
                exit(2);
        }

        /* check crc32 of encrypted data */
        uint32_t    checksum = (uint32_t) (crc32(0, dataEncrypted, Dsize) ^ adler32(0, dataEncrypted, Dsize));
        if (checksum!=validate_checksum[keyLen/8-2]) {
                fprintf(stderr, "error : encrypted data checksum (crc32^adler32) failed\n");
                exit(3);
        }
    }
    fprintf(stderr, "AES-GCM validated\n");
}

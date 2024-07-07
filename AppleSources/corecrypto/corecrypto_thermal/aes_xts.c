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
#include <corecrypto/ccaes.h>
#include <zlib.h>
#include "thermalCrypto.h"
#include <Accelerate/ClockServices.h>

// extern void ccdigest_update(const struct ccdigest_info *di, ccdigest_ctx_t ctx, size_t len, const void *data);

typedef struct
{
    const struct ccmode_xts *mode;
	const void *ctx;
	ccxts_tweak *tweak;
	size_t nblocks;
	const void *dataIn;
	void *dataOut;
} Parameters;


// this template works for both encrypt and decrypt
static void Blockxts(const Parameters *parameters)
{
    parameters->mode->xts(parameters->ctx, parameters->tweak, parameters->nblocks, parameters->dataIn, parameters->dataOut);
}

static void Driver(unsigned int iterations, void *parameters)
{
    Parameters *p = (Parameters *) parameters;
    while (iterations--) {
        Blockxts(p);
	}
}

extern uint32_t single_test;

void thermalAES_XTS(uint32_t ITERATIONS, uint32_t data_size)
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

	const struct ccmode_xts *encrypt = ccaes_xts_encrypt_mode();
    const struct ccmode_xts *decrypt = ccaes_xts_decrypt_mode();
	unsigned int		keyLen=16;
	uint8_t 	key[32], *key2=key+16;
	uint8_t 	tweak_buffer[16];

if (!single_test) {
	for (i=0;i<32;i++) key[i] = (uint8_t)arc4random();
	for (i=0;i<16;i++) tweak_buffer[i] = (uint8_t)arc4random();
}

	ccxts_ctx_decl(encrypt->size, ectx);
    ccxts_tweak_decl(encrypt->tweak_size, etweak);
    encrypt->init(encrypt, ectx, keyLen, key, key2);
    encrypt->set_tweak(ectx, etweak, tweak_buffer);

	ccxts_ctx_decl(decrypt->size, dctx);
    ccxts_tweak_decl(decrypt->tweak_size, dtweak);
    decrypt->init(decrypt, dctx, keyLen, key, key2);
    decrypt->set_tweak(dctx, dtweak, tweak_buffer);

	if (!(dataIn = malloc(data_size))) {
		fprintf(stderr,"error : malloc dataIn %d \n", data_size);
		exit(1);
	}
	if (!(dataEncrypted = malloc(data_size))) {
		fprintf(stderr,"error : malloc dataEncrypted %d \n", data_size);
		exit(1);
	}
	if (!(dataDecrypted = malloc(data_size))) {
		fprintf(stderr,"error : malloc dataDecrypted %d \n", data_size);
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
				.tweak = etweak,
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
                .mode = decrypt,
				.ctx = dctx,
				.tweak = dtweak,
				.nblocks = data_size/16,
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
}

	printf("  aes-xts : %.2f/%.2f", (TotalETime/data_size),(TotalDTime/data_size));
	printf("\n");


	free(dataIn);
	free(dataEncrypted);
	free(dataDecrypted);

}

/*
    function that tests corner cases (various number of input blocks) with known constants in the key and data
*/
#define Dsize   4096
#define nBlocks (Dsize/16)

uint32_t validate_xts_checksum[] = { 0x24b775a5, 0x1c61df21, 0xcba2437c };

void validateAES_XTS(void);

void validateAES_XTS(void)
{


	unsigned char	dataIn[Dsize], dataEncrypted[Dsize], dataDecrypted[Dsize];
	uint8_t 	tweak_buffer[16];
	size_t i, j;

	const struct ccmode_xts *encrypt = ccaes_xts_encrypt_mode();
    const struct ccmode_xts *decrypt = ccaes_xts_decrypt_mode();
	ccxts_ctx_decl(encrypt->size, ectx);
    ccxts_tweak_decl(encrypt->tweak_size, etweak);

	ccxts_ctx_decl(decrypt->size, dctx);
    ccxts_tweak_decl(decrypt->tweak_size, dtweak);

	unsigned int		keyLen;
	uint8_t 	        key[32*2], *key2=key+32;
    for (i=0;i<32*2;i++) key[i] = (uint8_t)i;
	for (i=0;i<Dsize;i++) dataIn[i] = (unsigned char)i; 
    bzero(dataEncrypted,Dsize);
    bzero(dataDecrypted,Dsize);
    bzero(tweak_buffer,16);

    for (keyLen=16;keyLen<=32;keyLen+=8) {  /* aes-128/aes-192/aes-224 */

        encrypt->init(encrypt, ectx, keyLen, key, key2);
        encrypt->set_tweak(ectx, etweak, tweak_buffer);

        decrypt->init(decrypt, dctx, keyLen, key, key2);
        decrypt->set_tweak(dctx, dtweak, tweak_buffer);

        /* encrypt in nblocks of 1,2,...,10,(256-55) */ 
        j=0; 
        for (i=1;i<=10;i++) { 
            encrypt->xts(ectx, etweak, i, &dataIn[j], &dataEncrypted[j]);
            j+=(i<<4);
        }
        i = (4096-j)>>4;
        encrypt->xts(ectx, etweak, i, &dataIn[j], &dataEncrypted[j]);

        /* decrypt in nblocks of 1,2,...,10,(256-55) */ 
        j=0; 
        for (i=1;i<=10;i++) { 
            decrypt->xts(dctx, dtweak, i, &dataEncrypted[j], &dataDecrypted[j]);
            j+=(i<<4);
        }
        i = (4096-j)>>4;
        decrypt->xts(dctx, dtweak, i, &dataEncrypted[j], &dataDecrypted[j]);

        /* check whether dataIn == dataDecrypted */
        for (i=0;i<Dsize;i++) {
            if (dataIn[i] != dataDecrypted[i]) {
                fprintf(stderr, "error : XTS mode AES-%d error (mismatched at byte %zu\n", keyLen*8, i);
                exit(1);
            }
        }

        /* check crc32 of encrypted data */
        uint32_t    checksum = (uint32_t) (crc32(0, dataEncrypted, Dsize) ^ adler32(0, dataEncrypted, Dsize));
        if (checksum!=validate_xts_checksum[keyLen/8-2]) {
                fprintf(stderr, "error : encrypted data checksum (crc32^adler32) failed\n");
                exit(2);
        }
    }
    fprintf(stderr, "AES-XTS validated\n");
}

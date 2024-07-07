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
#include "thermalCrypto.h"
#include <Accelerate/ClockServices.h>

// extern void ccdigest_update(const struct ccdigest_info *di, ccdigest_ctx_t ctx, size_t len, const void *data);

typedef struct
{
    const struct ccmode_cfb *cfb;
	void *key;
	size_t nblocks;
	void *dataIn;
	void *dataOut;
} Parameters;


void BlockCFB(Parameters *parameters);

// this templtae works for both encrypt and decrypt
void BlockCFB(Parameters *parameters)
{
	cccfb_update(parameters->cfb, (cccfb_ctx *) parameters->key, parameters->nblocks, parameters->dataIn, parameters->dataOut);

}


static void Driver(unsigned int iterations, void *parameters)
{
    Parameters *p = (Parameters *) parameters;
    while (iterations--) {
        BlockCFB(p);
	}
}

extern uint32_t	single_test;

void thermalAES_CFB(uint32_t    ITERATIONS, uint32_t    data_size)
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

	const struct ccmode_cfb *encrypt = ccaes_cfb_encrypt_mode();
    const struct ccmode_cfb *decrypt = ccaes_cfb_decrypt_mode();
	unsigned int		keyLen=16;
	uint8_t 	gkey[32];
	uint8_t 	iv[16];

if (!single_test) {
	for (i=0;i<32;i++) gkey[i] = (uint8_t)arc4random();
}
	for (i=0;i<16;i++) iv[i] = (uint8_t)i;

	cccfb_ctx_decl(encrypt->size, ekey);
	cccfb_init(encrypt, ekey, keyLen, (const uint8_t *) gkey, iv);

	cccfb_ctx_decl(decrypt->size, dkey);
	cccfb_init(decrypt, dkey, keyLen, (const uint8_t *) gkey, iv);

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

if (!single_test) {
	for (i=0;i<data_size;i++) { 
			dataIn[i] = (char)arc4random();
			dataEncrypted[i] = dataDecrypted[i] = 0;
	}

	// Encrypted
    {
            Parameters parameters =
            {
                .cfb = encrypt,
				.key = ekey,
				.nblocks = data_size,
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
                .cfb = decrypt,
				.key = dkey,
				.nblocks = data_size,
				.dataIn = dataEncrypted,
				.dataOut = dataDecrypted,
            };
            TotalDTime += MeasureNetTimeInCPUCycles(Driver, ITERATIONS, &parameters, 1);

    }

if (!single_test) {
	for (i=16;i<data_size;i++) if (dataIn[i]!=dataDecrypted[i]) {
			fprintf(stderr,"error at i = %d, %6d %6d %6d\n", i, dataIn[i], dataEncrypted[i], dataDecrypted[i]);
			break;
	}
}

	printf("  aes-cfb : %.2f/%.2f\n", (TotalETime/data_size),(TotalDTime/data_size));


	free(dataIn);
	free(dataEncrypted);
	free(dataDecrypted);

}

#include <zlib.h>
#define Dsize   4096

uint32_t validate_cfb_checksum[] = { 0x5fa7c57e, 0xfcfc7065, 0xbdf49f4a};

void validateAES_CFB(void);

void validateAES_CFB(void)
{


    unsigned char   dataIn[Dsize], dataEncrypted[Dsize], dataDecrypted[Dsize];
    size_t i, j;
	uint8_t 	iv[16];
	for (i=0;i<16;i++) iv[i] = (uint8_t)i;

	const struct ccmode_cfb *encrypt = ccaes_cfb_encrypt_mode();
    const struct ccmode_cfb *decrypt = ccaes_cfb_decrypt_mode();
    cccfb_ctx_decl(encrypt->size, ekey);
    cccfb_ctx_decl(decrypt->size, dkey);

    unsigned int        keyLen;
    uint8_t             gkey[32];
    for (i=0;i<32;i++) gkey[i] = (uint8_t)i;
    for (i=0;i<Dsize;i++) dataIn[i] = (unsigned char)i;
    bzero(dataEncrypted,Dsize);
    bzero(dataDecrypted,Dsize);

    for (keyLen=16;keyLen<=32;keyLen+=8) {  /* aes-128/aes-192/aes-224 */

	    cccfb_init(encrypt, ekey, keyLen, (const uint8_t *) gkey, iv);
	    cccfb_init(decrypt, dkey, keyLen, (const uint8_t *) gkey, iv);

        /* encrypt in nblocks of 1,2,...,10,(256-55) */
        j=0;
        for (i=1;i<=10;i++) {
	        cccfb_update(encrypt, ekey, i<<4, &dataIn[j], &dataEncrypted[j]);
            j+=(i<<4);
        }
        i = (4096-j)>>4;
	    cccfb_update(encrypt, ekey, i<<4, &dataIn[j], &dataEncrypted[j]);

        /* decrypt in nblocks of 1,2,...,10,(256-55) */
        j=0;
        for (i=1;i<=10;i++) {
            cccfb_update(decrypt, dkey, i<<4, &dataEncrypted[j], &dataDecrypted[j]);
            j+=(i<<4);
        }
        i = (4096-j)>>4;
        cccfb_update(decrypt, dkey, i<<4, &dataEncrypted[j], &dataDecrypted[j]);

        /* check whether dataIn == dataDecrypted */
        for (i=0;i<Dsize;i++) {
            if (dataIn[i] != dataDecrypted[i]) {
                fprintf(stderr, "error : CFB mode AES-%d error (mismatched at byte %zu)\n", keyLen*8, i);
                exit(1);
            }
        }

        /* check crc32 of encrypted data */
        uint32_t    checksum = (uint32_t) (crc32(0, dataEncrypted, Dsize) ^ adler32(0, dataEncrypted, Dsize));
        if (checksum!=validate_cfb_checksum[keyLen/8-2]) {
                fprintf(stderr, "error : encrypted data checksum (crc32^adler32) failed\n");
                exit(2);
        }
    }
    fprintf(stderr, "AES-CFB validated\n");
}


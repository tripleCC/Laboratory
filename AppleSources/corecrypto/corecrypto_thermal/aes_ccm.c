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
#include <corecrypto/ccaes.h>
#include <corecrypto/ccmode.h>
#include "thermalCrypto.h"
#include <Accelerate/ClockServices.h>

// extern void ccdigest_update(const struct ccdigest_info *di, ccdigest_ctx_t ctx, size_t len, const void *data);

typedef struct
{
    const struct ccmode_ccm *mode;
	void *ctx;
	void *ccm_nonce;
	void *Mac;
	size_t len;
	const void *dataIn;
	void *dataOut;
} Parameters;

void Blockccm(const Parameters *parameters);

// this template works for both encrypt and decrypt
void Blockccm(const Parameters *parameters)
{
    ccccm_init(parameters->mode, (ccccm_ctx *) parameters->ctx, 16, "261B72350558F2E9DCF613070383EDBF");
    ccccm_set_iv(parameters->mode, (ccccm_ctx *) parameters->ctx, (ccccm_nonce *) parameters->ccm_nonce, 11, "66E69A111892584FB5ED52", 16, 0, parameters->len );
    ccccm_cbcmac(parameters->mode, (ccccm_ctx *) parameters->ctx, (ccccm_nonce *) parameters->ccm_nonce, 32, "66E69A111892584FB5ED524A744DA3EE87000000000001001100001400E40800");
    ccccm_update(parameters->mode, (ccccm_ctx *) parameters->ctx, (ccccm_nonce *) parameters->ccm_nonce, parameters->len, parameters->dataIn, parameters->dataOut);
    ccccm_finalize(parameters->mode, (ccccm_ctx *) parameters->ctx, (ccccm_nonce *) parameters->ccm_nonce, parameters->Mac); 
}

static void Driver(unsigned int iterations, void *parameters)
{
    Parameters *p = (Parameters *) parameters;
    while (iterations--) {
        Blockccm(p);
	}
}

extern uint32_t single_test;

void thermalAES_CCM(uint32_t ITERATIONS, uint32_t data_size)
{


	char	*dataIn, *dataEncrypted, *dataDecrypted;
    uint8_t   EncMac[16], DecMac[16];
	uint32_t		i;
	double TotalETime = 0;
	double TotalDTime = 0;

	const struct ccmode_ccm *encrypt = ccaes_ccm_encrypt_mode();
    const struct ccmode_ccm *decrypt = ccaes_ccm_decrypt_mode();

    bzero(EncMac, 16);
    bzero(DecMac, 16);

	ccccm_ctx_decl(encrypt->size, ectx);
    ccccm_nonce_decl(encrypt->nonce_size, eccm_nonce);
	ccccm_ctx_decl(decrypt->size, dctx);
    ccccm_nonce_decl(decrypt->nonce_size, dccm_nonce);

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
				.ccm_nonce = eccm_nonce,
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
				.ccm_nonce = dccm_nonce,
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

	printf("  aes-ccm : %.2f/%.2f", (TotalETime/data_size),(TotalDTime/data_size));
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

    uint32_t validate_ccm_checksum[] = { 
0x6131545e,
0x2a598918,
0x64385d28,
0x44cedf2d,
0x5563ba1d,
0x3e977a25,
0x8ff99933,
0x364f80f2,
0x95fc336d,
0xe9e41916,
0x3a7e0b0f,
0xc37fd332,
0xfdb9e7d4,
0x213164e0,
0xd9b80772,
0x989b16e8,
0x7227d516,
0xa8aa053f,
0x5a9675bb,
0xba0dce03,
0x1e9d4e83 };

void validateAES_CCM(void);

void validateAES_CCM(void)
{


    unsigned char   dataIn[Dsize], dataEncrypted[Dsize], dataDecrypted[Dsize];
    uint8_t   EncMac[16], DecMac[16];
    size_t i, j;

    const struct ccmode_ccm *encrypt = ccaes_ccm_encrypt_mode();
    const struct ccmode_ccm *decrypt = ccaes_ccm_decrypt_mode();

    ccccm_ctx_decl(encrypt->size, ectx);
    ccccm_ctx_decl(decrypt->size, dctx);
    ccccm_nonce_decl(encrypt->nonce_size, eccm_nonce);
    ccccm_nonce_decl(decrypt->nonce_size, dccm_nonce);

    unsigned int        keyLen;
    unsigned int        ctrLen;
    uint8_t             gkey[32];
    for (i=0;i<32;i++) gkey[i] = (uint8_t)i;
    for (i=0;i<Dsize;i++) dataIn[i] = (unsigned char)i;
    bzero(dataEncrypted,Dsize);
    bzero(dataDecrypted,Dsize);

    for (ctrLen=7;ctrLen<=13;ctrLen++) {    // range through all kinds of ctr length

    for (keyLen=16;keyLen<=32;keyLen+=8) {  /* aes-128/aes-192/aes-224 */

        ccccm_init(encrypt, ectx, keyLen, gkey);
        ccccm_set_iv(encrypt, ectx, eccm_nonce, ctrLen, "66E69A111892584FB5ED524A744DA3EE87000000000001001100001400E40800", 16, 0, Dsize);
        ccccm_cbcmac(encrypt, ectx, eccm_nonce, 32, "66E69A111892584FB5ED524A744DA3EE87000000000001001100001400E40800");

        ccccm_init(decrypt, dctx, keyLen, gkey);
        ccccm_set_iv(decrypt, dctx, dccm_nonce, ctrLen, "66E69A111892584FB5ED524A744DA3EE87000000000001001100001400E40800", 16, 0, Dsize);
        ccccm_cbcmac(decrypt, dctx, dccm_nonce, 32, "66E69A111892584FB5ED524A744DA3EE87000000000001001100001400E40800");


        /* encrypt in nblocks of 1,2,...,10,(256-55) */
        j=0;
        for (i=1;i<=10;i++) {
            ccccm_update(encrypt, ectx, eccm_nonce, i<<4, &dataIn[j], &dataEncrypted[j]);
            j+=(i<<4);
        }
        i = (4096-j)>>4;
        ccccm_update(encrypt, ectx, eccm_nonce, i<<4, &dataIn[j], &dataEncrypted[j]);
        ccccm_finalize(encrypt, ectx, eccm_nonce, EncMac);

        /* decrypt in nblocks of 1,2,...,10,(256-55) */
        j=0;
        for (i=1;i<=10;i++) {
            ccccm_update(decrypt, dctx, dccm_nonce, i<<4, &dataEncrypted[j], &dataDecrypted[j]);
            j+=(i<<4);
        }
        i = (4096-j)>>4;
        ccccm_update(decrypt, dctx, dccm_nonce, i<<4, &dataEncrypted[j], &dataDecrypted[j]);
        ccccm_finalize(decrypt, dctx, dccm_nonce, DecMac);

        /* check whether dataIn == dataDecrypted */
        for (i=0;i<Dsize;i++) {
            if (dataIn[i] != dataDecrypted[i]) {
                fprintf(stderr, "error : CCM mode AES-%d error (mismatched at byte %zu)\n", keyLen*8, i);
                exit(1);
            }
        }

        /* check Mac */
        if (memcmp(EncMac, DecMac, 16)) {
                fprintf(stderr, "error : CCM mode encrypt and decrypt Mac Mismatch\n");
                exit(2);
        }

        /* check crc32 of encrypted data */
        uint32_t    checksum = (uint32_t) (crc32(0, dataEncrypted, Dsize) ^ adler32(0, dataEncrypted, Dsize));
        if (checksum!=validate_ccm_checksum[3*(ctrLen-7)+(keyLen/8-2)]) {
                fprintf(stderr, "error : encrypted data checksum (crc32^adler32) failed ctrLen = %d\n", 15-ctrLen);
                exit(3);
        }
    }
    }
    fprintf(stderr, "AES-CCM validated\n");
}


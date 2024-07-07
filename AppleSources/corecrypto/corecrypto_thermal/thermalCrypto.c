/* Copyright (c) (2016,2019,2020) Apple Inc. All rights reserved.
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
#include <stdint.h>
#include <string.h>
#include "thermalCrypto.h"

static void usage(char *filename)
{
    fprintf(stderr," usage : %s [-h | -v | -s test | [-i iterations] [-d data_size]]\n", filename);
    fprintf(stderr," default : iterations=1000, data_size=4096\n");
    exit(1);
}

uint32_t	single_test = 0;

int main(int argc, char **argv)
{

	char	*filename, test[100] = { 0 };
    uint32_t    ITERATIONS = 1000;
    uint32_t    data_size = 4096;

	filename = *argv++; argc--;
    while (argc>0) {
        if (!(strcmp(*argv,"-h"))) {
			usage(filename);
        } else if (!(strcmp(*argv,"-v"))) {
			fprintf(stderr, "\nThermal Screen thermalCrypto, version %d\n", thermalCryptoVersion);
			return 0;
		} else if (!(strcmp(*argv,"-s"))) {
            if (argc<2) usage(filename);
			single_test = 1;
            stpcpy(test, argv[1]);
            argc-=2; argv+=2;
		} else if (!(strcmp(*argv,"-i"))) {
            if (argc<2) usage(filename);
            ITERATIONS = (uint32_t)atoi(argv[1]);
            argc-=2; argv+=2;
        } else if (!(strcmp(*argv,"-d"))) {
            if (argc<2) usage(filename);
            data_size = (uint32_t)atoi(argv[1]);
            argc-=2; argv+=2;
        } else {
            usage(filename);
        }
    }


	if (single_test) {
		if (!strcmp(test,"sha1")) thermalSHA1(ITERATIONS,data_size);
		else if (!strcmp(test,"sha224")) thermalSHA224(ITERATIONS,data_size);
		else if (!strcmp(test,"sha256")) thermalSHA256(ITERATIONS,data_size);
		else if (!strcmp(test,"sha384")) thermalSHA384(ITERATIONS,data_size);
		else if (!strcmp(test,"sha512")) thermalSHA512(ITERATIONS,data_size);
		else if (!strcmp(test,"ecb")) thermalAES_ECB(ITERATIONS,data_size);
		else if (!strcmp(test,"cbc")) thermalAES_CBC(ITERATIONS,data_size);
		else if (!strcmp(test,"xts")) thermalAES_XTS(ITERATIONS,data_size);
		else if (!strcmp(test,"gcm")) thermalAES_GCM(ITERATIONS,data_size);
		else if (!strcmp(test,"ctr")) thermalAES_CTR(ITERATIONS,data_size);
		else if (!strcmp(test,"ccm")) thermalAES_CCM(ITERATIONS,data_size);
		else if (!strcmp(test,"cfb")) thermalAES_CFB(ITERATIONS,data_size);
		else if (!strcmp(test,"ofb")) thermalAES_OFB(ITERATIONS,data_size);
		else if (!strcmp(test,"crc32")) thermalCRC32(ITERATIONS,data_size);
		else if (!strcmp(test,"adler32")) thermalAdler32(ITERATIONS,data_size);
		else {
			fprintf(stderr," supported single test : sha1/sha224/sha256/sha384/sha512/cbc/ecb/xts/gcm/ctr/ccm/cfb/ofb/crc32/adler32\n");
		}

	} else {
        /* 1st-line basic validation */
        validateAES_ECB();
        validateAES_CBC();
        validateAES_XTS();
        validateAES_GCM();
        validateAES_CTR();
        validateAES_CCM();
        validateAES_CFB();
        validateAES_OFB();

		printf("\n peak performance in cycles/byte:\n\n");

		thermalSHA1(ITERATIONS,data_size);
		thermalSHA224(ITERATIONS,data_size);
		thermalSHA256(ITERATIONS,data_size);
		thermalSHA384(ITERATIONS,data_size);
		thermalSHA512(ITERATIONS,data_size);

		printf("\n");

		thermalAES_ECB(ITERATIONS,data_size);
		thermalAES_CBC(ITERATIONS,data_size);
		thermalAES_XTS(ITERATIONS,data_size);
		thermalAES_GCM(ITERATIONS,data_size);
		thermalAES_CTR(ITERATIONS,data_size);
		thermalAES_CCM(ITERATIONS,data_size);
		thermalAES_CFB(ITERATIONS,data_size);
		thermalAES_OFB(ITERATIONS,data_size);

	
		printf("\n");

		thermalCRC32(ITERATIONS,data_size);
		thermalAdler32(ITERATIONS,data_size);

		printf("\n");
	}

	return 0;
}

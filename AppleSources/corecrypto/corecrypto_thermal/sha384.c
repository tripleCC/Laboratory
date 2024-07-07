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
#include <corecrypto/ccsha2.h>
#include "thermalCrypto.h"
#include <Accelerate/ClockServices.h>

// extern void ccdigest_update(const struct ccdigest_info *di, ccdigest_ctx_t ctx, size_t len, const void *data);

typedef struct
{
    const struct ccdigest_info * di;
	ccdigest_ctx_t ctx;
	size_t len;
	const void *data;
} Parameters;

static void BlockSHA384(const Parameters *parameters)
{
	ccdigest_update(parameters->di, parameters->ctx, parameters->len, parameters->data);
}


static void Driver(unsigned int iterations, void *parameters)
{
    Parameters *p = (Parameters *) parameters;
    while (iterations--)
        BlockSHA384(p);
}

extern uint32_t single_test;

void thermalSHA384(uint32_t ITERATIONS, uint32_t data_size)
{

	char	*msg;
	uint32_t		checksum=0;
	uint32_t		i;
	double TotalTime = 0;
    int TotalPages = 0;

	// default simulation configuration
    uint32_t    NUM_BLOCKS = data_size/64;

    if ((NUM_BLOCKS*64)!=data_size) {
        data_size = 64*NUM_BLOCKS;
        fprintf(stderr,"warning : adjusted data_size to %d\n", data_size);
    }

	if (!(msg = calloc(data_size,1))) {
		fprintf(stderr,"error : calloc %d \n", data_size);
		exit(1);
	}

	// sha384 di declaration and initialization
	ccdigest_di_decl(ccsha384_di(), dc);
   	ccdigest_init(ccsha384_di(), dc);

if (!single_test) 
	for (i=0;i<data_size;i++) msg[i] = (char)arc4random();

    if ((ITERATIONS==1000)&&(data_size==4096))
        for (i=0;i<data_size;i++) msg[i] = (char)i;


	// Check for tag used to mark uncompressed blocks.
    {
            Parameters parameters =
            {
                .di = ccsha384_di(),
				.ctx = dc,
				.len = data_size,
				.data = msg,
            };


            TotalTime += MeasureNetTimeInCPUCycles(Driver, ITERATIONS, &parameters, 1);
            TotalPages ++;

    }

if (!single_test) {
	if ((ITERATIONS==1000)&&(data_size==4096)) {
	    int *sha2out = (int*) &dc;
	    for (i=0;i<16;i++) checksum ^= (uint32_t)sha2out[i];
        if (checksum!=0xe405cb2a) fprintf(stderr,"error : sha384 computation is wrong\n");
    }
}

	printf("   sha384 : %.2f\n", (TotalTime/TotalPages/data_size));

	free(msg);

}

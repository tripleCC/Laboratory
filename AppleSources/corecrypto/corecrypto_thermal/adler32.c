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
#include <stdint.h>
#include <zlib.h>
#include "thermalCrypto.h"
#include <Accelerate/ClockServices.h>

// extern void ccdigest_update(const struct ccdigest_info *di, ccdigest_ctx_t ctx, size_t len, const void *data);

typedef struct
{
    unsigned int adler;
    unsigned char *InputBuffer;
    unsigned int length;
} Parameters;

static void Driver(unsigned int iterations, void *parameters)
{
    Parameters *p = (Parameters *) parameters;
    while (iterations--) {
        p -> adler = (unsigned int) adler32(p->adler, p->InputBuffer, p->length);
    }
}

extern uint32_t single_test; 

void thermalAdler32(uint32_t    ITERATIONS, uint32_t data_size)
{

	uint32_t		i;
	double TotalTime = 0;
	unsigned int adler = 1;
	uint8_t	*msg;

	if (!(msg = malloc(data_size))) {
		fprintf(stderr,"error : malloc %d \n", data_size);
		exit(1);
	}

if (!single_test)
	for (i=0;i<data_size;i++) msg[i] = (uint8_t)arc4random();

    if ((ITERATIONS==1000)&&(data_size==4096))
        for (i=0;i<data_size;i++) msg[i] = (uint8_t)i;


	// Check for tag used to mark uncompressed blocks.
    {
            Parameters parameters =
            {
                .adler = adler,
				.InputBuffer = msg,
                .length = data_size,
            };


            TotalTime += MeasureNetTimeInCPUCycles(Driver, ITERATIONS, &parameters, 1);

			adler = parameters.adler;
    }

if (!single_test) {
	if ((ITERATIONS==1000)&&(data_size==4096)) {
		if (adler!=0xed486d57) fprintf(stderr,"error : adler32 computation is wrong\n");
	}
}

	printf("  adler32 : %.2f\n", (TotalTime/data_size));

	free(msg);

}

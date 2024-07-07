/* Copyright (c) (2010-2016,2018,2019,2021,2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "cc_internal.h"
#include "ccn_internal.h"
#include <corecrypto/ccpbkdf2.h>
#include <corecrypto/ccdigest_priv.h>
#include <corecrypto/cchmac.h>
#include <corecrypto/cc.h>
#include <corecrypto/cc_priv.h>

/* Will write hLen bytes into dataPtr according to PKCS #5 2.0 spec.
   See: ../docs/pkcs5v2_1.pdf for details (cached copy of RSA's PKCS5v2)
*/
static void
F (const struct ccdigest_info *di,
   cchmac_ctx_t hc,
   const cc_unit *istate,
   size_t saltLen, const void *salt,
   size_t iterationCount,
   size_t blockNumber,
   size_t dataLen,
   void *data)
{
    uint8_t *inBlock = cchmac_data(di, hc);
	/* Set up inBlock to contain Salt || INT (blockNumber). */
    uint32_t bn;

    ccdigest_copy_state(di, cchmac_istate32(di, hc), istate);
    cchmac_nbits(di, hc) = di->block_size * 8;
    cchmac_num(di, hc)=0;
    ccdigest_update(di, cchmac_digest_ctx(di, hc), saltLen, salt);

    cc_store32_be((uint32_t)blockNumber, (uint8_t *) &bn);
    ccdigest_update(di, cchmac_digest_ctx(di, hc), 4, &bn);

    /* Caculate U1 (result goes to outBlock) and copy it to resultBlockPtr. */
	cchmac_final(di,  hc, inBlock);

	cc_memcpy(data, inBlock, dataLen);

    /* Calculate U2 though UiterationCount. */
	for (size_t iteration = 2; iteration <= iterationCount; iteration++)
	{
        /* Now inBlock conatins Uiteration-1.  Calculate Uiteration into outBlock. */
        ccdigest_copy_state(di, cchmac_istate32(di, hc), istate);
        cchmac_nbits(di, hc) = di->block_size * 8;
        cchmac_num(di, hc) = (uint32_t)di->output_size;
        cchmac_final(di,  hc, inBlock);

        /* Xor data in dataPtr (U1 \xor U2 \xor ... \xor Uiteration-1) with
		   outBlock (Uiteration). */
		cc_xor(dataLen, data, data, inBlock);
    }
}


int ccpbkdf2_hmac(const struct ccdigest_info *di,
                   size_t passwordLen, const void *password,
                   size_t saltLen, const void *salt,
                   size_t iterations,
                   size_t dkLen, void *dk)
{
    CC_ENSURE_DIT_ENABLED

	// FIPS required check
    //  Specification is If dkLen > (2^32 – 1) × hLen, output “derived key too long” and stop.
    //  (^) is not "power of" in C.  It is in spec-speak.  Really this is a max uint32 number
    //  as the limit.
	if ((dkLen / di->output_size) > UINT32_MAX)
	{
		return -1;
	}
	
    cchmac_di_decl(di, hc);
    cc_unit istate[ccn_nof_size(MAX_DIGEST_STATE_SIZE)];
    cchmac_init(di, hc, passwordLen, password);
    ccdigest_copy_state(di, istate, cchmac_istate32(di, hc));

    const size_t hLen = di->output_size;

	size_t completeBlocks = dkLen / hLen;
	size_t partialBlock_nbytes = dkLen % hLen;

	/* First calculate all the complete hLen sized blocks required. */
	size_t blockNumber = 1;
	uint8_t *dataPtr = dk;
	
	// For FIPS the output needs to be concatenated not just xor'd
	for (; blockNumber <= completeBlocks; blockNumber++, dataPtr += hLen)
	{
		F (di, hc, istate, saltLen, salt, iterations, blockNumber, hLen, dataPtr);
    }

    /* Finally if the requested output size was not an even multiple of hLen,
       calculate the final block and copy the first partialBlock_nbytes bytes of
       it to the output. */
	if (partialBlock_nbytes > 0)
	{
		F (di, hc, istate, saltLen, salt, iterations, blockNumber, partialBlock_nbytes, dataPtr);
	}

	cchmac_di_clear(di, hc);
	ccn_clear(ccn_nof_size(di->state_size), istate);
	return 0;
}

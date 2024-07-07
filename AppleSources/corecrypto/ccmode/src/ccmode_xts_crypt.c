/* Copyright (c) (2011,2012,2014,2015,2016,2018,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "ccmode_internal.h"

void *ccmode_xts_crypt(const ccxts_ctx *ctx, ccxts_tweak *tweak,
                       size_t nblocks, const void *in, void *out) 
{
	size_t numBlocks = CCMODE_XTS_TWEAK_BLOCK_PROCESSED(tweak);
	numBlocks += nblocks;
	if (numBlocks > (1 << 20))
	{
		return NULL;
	}
	CCMODE_XTS_TWEAK_BLOCK_PROCESSED(tweak) = numBlocks;
    const struct ccmode_ecb *ecb = ccmode_xts_key_ecb(ctx);
    cc_unit *t=CCMODE_XTS_TWEAK_VALUE(tweak);
    const cc_unit *input = in;
    cc_unit *output = out;
    while (nblocks) {
        ccn_xor(ccn_nof_size(16), output, input, t);
        ecb->ecb(ccmode_xts_key_data_key(ctx), 1, output, output);
        ccn_xor(ccn_nof_size(16), output, output, t);
        ccmode_xts_mult_alpha(t);
        --nblocks;
        input += ccn_nof_size(16);
        output += ccn_nof_size(16);
    }
    return t;
}


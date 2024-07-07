/* Copyright (c) (2011,2012,2015,2016,2018,2019,2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/cccast.h>
#include "cast.h"

static int cccast_ecb_decrypt(const ccecb_ctx *skey, size_t nblocks, const void *inp, void *outp)
{
	CAST_LONG d[2];
    const CAST_KEY *ks=(const CAST_KEY *)skey;
    const unsigned char *in=inp;
    unsigned char *out=outp;

    while(nblocks--) {
        d[0] = cc_load32_be(in);
        d[1] = cc_load32_be(in + 4);
        
        CAST_decrypt(d,ks);
        
        cc_store32_be(d[0], out);
        cc_store32_be(d[1], out + 4);

        in += 8;
        out += 8;
    }
    
    return CCERR_OK;
}

const struct ccmode_ecb cccast_eay_ecb_decrypt_mode = {
    .size = sizeof(CAST_KEY),
    .block_size = CCCAST_BLOCK_SIZE,
    .init = cccast_setup,
    .ecb = cccast_ecb_decrypt
};

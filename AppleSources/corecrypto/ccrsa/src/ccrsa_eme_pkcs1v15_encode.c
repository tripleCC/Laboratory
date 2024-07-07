/* Copyright (c) (2011-2015,2018,2019,2021,2022) Apple Inc. All rights reserved.
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
#include "ccrng_internal.h"
#include <corecrypto/ccrsa_priv.h>

/*
 The r_size argument is really meant to be a size_t rather than a cc_size.  It's the size
 in bytes of the key for which this encoding is being done.  'r' on the other hand is a
 cc_unit array large enough to contain the blocksize of the key.  We need to build up the
 encoding "right justified" within r for r_size bytes.  We'll zero-pad the front and then
 at the end of this routine we'll use ccn_swap() to make it a big number.
 */


int ccrsa_eme_pkcs1v15_encode(struct ccrng_state *rng,
                              size_t r_size, cc_unit *r,
                              size_t s_size, const uint8_t *s)

{
    CC_ENSURE_DIT_ENABLED

    cc_size n = ccrsa_n_from_size(r_size);
    uint8_t *out = ccrsa_block_start(r_size, r, 1);
    uint8_t *pad;
    size_t padlen;
    size_t i;
    
    for(uint8_t *p = (uint8_t *) r; p < out; p++) *p = 0;

    pad = out + 2;
    if ((r_size < 11) || ((r_size - 11) < s_size)) { // 3 bytes for prefix + 8 bytes of minimum padding length
        return CCRSA_INVALID_INPUT;
    }
    padlen = r_size - s_size - 3;

    int result = ccrng_generate_fips(rng, padlen, pad);
	if (result) {
		return result;
	}
	
    for(i=0; i<padlen; i++) { // pad can't have zero bytes
        while(pad[i] == 0)
            if((result = ccrng_generate_fips(rng, 1, &pad[i])) != 0) return result;
    }
    out[0] = 0x00;
    out[1] = 0x02;
    out[2+padlen] = 0x00;
    cc_memcpy(out+3+padlen, s, s_size);
    ccn_swap(n, r);

    return 0;
}

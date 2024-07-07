/* Copyright (c) (2011,2012,2014,2015,2018,2019,2021) Apple Inc. All rights reserved.
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
#include <corecrypto/ccrsa_priv.h>

// Seed is di->output_size bytes
int ccmgf(const struct ccdigest_info *di, size_t r_nbytes, void *r, size_t seed_nbytes, const void *seed)
{
    CC_ENSURE_DIT_ENABLED

    uint8_t *cur = r;
    uint32_t ctr = 0;
    uint8_t be_counter[sizeof(uint32_t)];
    ccdigest_di_decl(di, ctx);
    uint8_t hash[MAX_DIGEST_OUTPUT_SIZE];

    ctr = (uint32_t)(r_nbytes / di->output_size);
    size_t tail = r_nbytes - (ctr * di->output_size);
    cur += r_nbytes - tail;
    if (tail != 0) {
        ccdigest_init(di, ctx);
        ccdigest_update(di, ctx, seed_nbytes, seed);

        cc_store32_be(ctr, be_counter);
        ccdigest_update(di, ctx, sizeof(be_counter), &be_counter);
        ccdigest_final(di, ctx, hash);
        cc_memmove(cur, hash, tail);
    }

    while (ctr-- != 0) {
        cur -= di->output_size;
        ccdigest_init(di, ctx);
        ccdigest_update(di, ctx, seed_nbytes, seed);
        cc_store32_be(ctr, be_counter);
        ccdigest_update(di, ctx, sizeof(be_counter), &be_counter);
        ccdigest_final(di, ctx, cur);
    }
    ccdigest_di_clear(di, ctx); // Clear context important for encryption
    cc_clear(sizeof(hash), hash);
    return 0;
}

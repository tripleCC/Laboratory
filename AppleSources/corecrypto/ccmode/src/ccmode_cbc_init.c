/* Copyright (c) (2010,2011,2012,2015,2016,2019) Apple Inc. All rights reserved.
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

int ccmode_cbc_init(const struct ccmode_cbc *cbc, cccbc_ctx *key,
                    size_t rawkey_len, const void *rawkey) {
    /* We made key sizeof(intptr_t) / CCN_UNIT_SIZE units longer, so we
       consume the first units from key.  Note that this leaves the rest of
       the key potentially unaligned on cache lines, so perhaps a better
       strategy is to have a cache line sized prefix on the ccecb_ctx.
       Alternatively a fast ecb mode implementation could reserve
       cc_cache_line_n() - 1 extra space for the key, and always round up the
       key pointer to the nearest cache line if it's discovered this
       matters. */
    const struct ccmode_ecb *ecb = cbc->custom;
    CCMODE_CBC_KEY_ECB(key) = ecb;

    return ecb->init(ecb, CCMODE_CBC_KEY_ECB_KEY(key), rawkey_len, rawkey);
}

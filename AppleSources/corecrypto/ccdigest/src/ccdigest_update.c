/* Copyright (c) (2010,2011,2014-2016,2018,2019,2021) Apple Inc. All rights reserved.
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
#include <corecrypto/ccdigest.h>
#include <corecrypto/cc_priv.h>

void ccdigest_update(const struct ccdigest_info *di, ccdigest_ctx_t ctx, size_t len, const void *data)
{
    CC_ENSURE_DIT_ENABLED

    const char * data_ptr = data;
    size_t nblocks, nbytes;

    // Sanity check to recover from ctx corruptions.
    if (ccdigest_num(di, ctx) >= di->block_size) {
        ccdigest_num(di, ctx) = 0;
    }

    while (len > 0) {
        if (ccdigest_num(di, ctx) == 0 && len > di->block_size) {
            if(di->block_size == 1<<6 ){ // md5 & sha1 & sha256
                nblocks = len >> 6;
                nbytes = nblocks << 6;
            }else if(di->block_size == 1<<7 ){ // sha384 & sha512
                nblocks = len >> 7;
                nbytes = nblocks << 7;
            }else {
                nblocks = len / di->block_size;
                nbytes = nblocks * di->block_size;
            }

            di->compress(ccdigest_state(di, ctx), nblocks, data_ptr);
            len -= nbytes;
            data_ptr += nbytes;
            ccdigest_nbits(di, ctx) += (uint64_t) (nbytes) * 8;
        } else {
            size_t n = CC_MIN(di->block_size - ccdigest_num(di, ctx), len);
            cc_memcpy(ccdigest_data(di, ctx) + ccdigest_num(di, ctx), data_ptr, n);
            /* typecast: less than block size, will always fit into an int */
            ccdigest_num(di, ctx) += (unsigned int)n;
            len -= n;
            data_ptr += n;
            if (ccdigest_num(di, ctx) == di->block_size) {
                di->compress(ccdigest_state(di, ctx), 1, ccdigest_data(di, ctx));
                ccdigest_nbits(di, ctx) += ccdigest_num(di, ctx) * 8;
                ccdigest_num(di, ctx) = 0;
            }
        }
    }
}

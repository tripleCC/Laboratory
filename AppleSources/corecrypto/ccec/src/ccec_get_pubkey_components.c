/* Copyright (c) (2011,2012,2014,2015,2019,2021) Apple Inc. All rights reserved.
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
#include <corecrypto/ccec.h>

int
ccec_get_pubkey_components(ccec_pub_ctx_t key, size_t *nbits,
                           uint8_t *x, size_t *xsize,
                           uint8_t *y, size_t *ysize)
{
    CC_ENSURE_DIT_ENABLED

    cc_size n = ccec_ctx_n(key);
    size_t len;

    if((len = ccn_write_uint_size(n, ccec_ctx_x(key))) > *xsize) return -1;
    *xsize = len;
    ccn_write_uint(n, ccec_ctx_x(key), *xsize, x);
    if((len = ccn_write_uint_size(n, ccec_ctx_y(key))) > *ysize) return -1;
    *ysize = len;
    ccn_write_uint(n, ccec_ctx_y(key), *ysize, y);
    *nbits = ccec_ctx_bitlen(key);
    return 0;
}

/* Copyright (c) (2011,2012,2015,2016,2019,2021) Apple Inc. All rights reserved.
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
#include <corecrypto/ccec_priv.h>

int ccec_make_priv(size_t nbits,
                  size_t xlength, const uint8_t *x,
                  size_t ylength, const uint8_t *y,
                  size_t klength, const uint8_t *k,
                  ccec_full_ctx_t key) {
    CC_ENSURE_DIT_ENABLED

    int result;

    ccec_const_cp_t cp = ccec_get_cp(nbits);

    ccec_ctx_init(cp, key);

    if ((result = ccn_read_uint(ccec_cp_n(cp), ccec_ctx_x(key), xlength, x)))
        goto errOut;

    if ((result = ccn_read_uint(ccec_cp_n(cp), ccec_ctx_y(key), ylength, y)))
        goto errOut;

    if ((result = ccn_read_uint(ccec_cp_n(cp), ccec_ctx_k(key), klength, k)))
        goto errOut;

    ccn_seti(ccec_cp_n(cp), ccec_ctx_z(key), 1);

errOut:
    return result;
}

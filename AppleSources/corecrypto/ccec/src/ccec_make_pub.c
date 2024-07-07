/* Copyright (c) (2011,2015,2016,2018,2019,2021) Apple Inc. All rights reserved.
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

int ccec_make_pub(size_t nbits,
                    size_t xlength, const uint8_t *x,
                    size_t ylength, const uint8_t *y,
                    ccec_pub_ctx_t key) {
    CC_ENSURE_DIT_ENABLED

    if (ylength == 0) {
        return CCERR_PARAMETER;
    }
    
    ccec_const_cp_t cp = ccec_get_cp(nbits);
    if (ccec_cp_zp(cp) == NULL) {
        return CCERR_INTERNAL;
    }
    ccec_ctx_init(cp, key);

    if ((0 != ccn_read_uint(ccec_cp_n(cp), ccec_ctx_x(key), xlength, x))) {
        return CCERR_INTERNAL;
    }

    if ((0 != ccn_read_uint(ccec_cp_n(cp), ccec_ctx_y(key), ylength, y))) {
        return CCERR_INTERNAL;
    }

    ccn_seti(ccec_cp_n(cp), ccec_ctx_z(key), 1);
    return CCERR_OK;
}

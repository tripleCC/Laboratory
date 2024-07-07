/* Copyright (c) (2018-2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "ccec_internal.h"

int ccec_diversify_twin_scalars_ws(cc_ws_t ws,
                                   ccec_const_cp_t cp,
                                   cc_unit *u,
                                   cc_unit *v,
                                   size_t entropy_len,
                                   const uint8_t *entropy)
{
    if (entropy_len < 2 * ccec_diversify_min_entropy_len(cp)) {
        return CCERR_PARAMETER;
    }

    if (entropy_len & 1) {
        return CCERR_PARAMETER;
    }

    size_t e_len = entropy_len / 2;

    // Derive u.
    int rv = ccec_generate_scalar_fips_extrabits_ws(ws, cp, e_len, entropy, u);
    if (rv) {
        return rv;
    }

    // Derive v.
    return ccec_generate_scalar_fips_extrabits_ws(ws, cp, e_len, entropy + e_len, v);
}

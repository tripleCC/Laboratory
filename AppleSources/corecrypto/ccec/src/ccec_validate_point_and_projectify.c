/* Copyright (c) (2014-2021,2023) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/ccec_priv.h>
#include "ccec_internal.h"
#include "cc_macros.h"
#include "cc_workspaces.h"

CC_INLINE bool is_in_field(ccec_const_cp_t cp, const cc_unit *t)
{
    cc_size n = ccec_cp_n(cp);
    cczp_const_t zp = ccec_cp_zp(cp);
    return ccn_cmp(n, cczp_prime(zp), t) > 0;
}

int ccec_validate_point_and_projectify_ws(cc_ws_t ws,
                                        ccec_const_cp_t cp,
                                        ccec_projective_point_t r,
                                        ccec_const_affine_point_t public_point,
                                        struct ccrng_state *masking_rng)
{
    int result = -1;

    /* Check that coordinates are compatible with underlying field */
    cc_require(is_in_field(cp, ccec_const_point_x(public_point, cp)), errOut);
    cc_require(is_in_field(cp, ccec_const_point_y(public_point, cp)), errOut);

    /* Point in projective coordinates */
    cc_require((result = ccec_projectify_ws(ws, cp, r, public_point, masking_rng)) == CCERR_OK, errOut);

    /* Check that point is on the curve */
    cc_require_action(ccec_is_point_ws(ws, cp, r), errOut, result = CCERR_PARAMETER);

    result = CCERR_OK; // No error

errOut:
    return result;
}

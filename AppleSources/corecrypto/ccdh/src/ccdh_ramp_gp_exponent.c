/* Copyright (c) (2018,2019,2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/cc_priv.h>
#include "ccdh_internal.h"

// Function take a group exponent bit length l, and a group. If l is bigger than the current groups, it takes l.
// In either case, it will ensure that the length is at least a core-crypto minimum.
void ccdh_ramp_gp_exponent(cc_size l, ccdh_gp_t gp)
{
    // Set to max size exponent, if either group or l has max size.
    if (l == CCDH_MAX_GROUP_EXPONENT_BIT_LENGTH || ccdh_gp_l(gp) == CCDH_MAX_GROUP_EXPONENT_BIT_LENGTH) {
        CCDH_GP_L(gp) = CCDH_MAX_GROUP_EXPONENT_BIT_LENGTH;
        return;
    }

    // Otherwise take the max exponent size
    CCDH_GP_L(gp) = CC_MAX(l, ccdh_gp_l(gp));

    // Finally verify a minimum exponent size.
    if (ccdh_gp_l(gp) < CCDH_MIN_GROUP_EXPONENT_BIT_LENGTH) {
        CCDH_GP_L(gp) = CCDH_MIN_GROUP_EXPONENT_BIT_LENGTH;
    }
}

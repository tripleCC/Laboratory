/* Copyright (c) (2016-2019,2021) Apple Inc. All rights reserved.
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
#include "cc_debug.h"

/* Check that a private scalar is valid (in range [1..q-1]) */
int
ccec_validate_scalar(ccec_const_cp_t cp, const cc_unit* k) {

    int result = -1; // Error
    cczp_const_t zq = ccec_cp_zq(cp);
    cc_require(ccn_cmp(ccec_cp_n(cp),k,cczp_prime(zq))<0,errOut);
    cc_require(!ccn_is_zero(ccec_cp_n(cp),k),errOut);

    result = 0; // No error

errOut:
    return result;
}

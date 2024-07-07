/* Copyright (c) (2013,2015,2017-2022) Apple Inc. All rights reserved.
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
#include <corecrypto/ccdh.h>
#include <corecrypto/cczp.h>
#include <corecrypto/ccder.h>
#include "ccdh_internal.h"

const uint8_t *
ccder_decode_dhparams(ccdh_gp_t gp, const uint8_t *der, const uint8_t *der_end)
{
    const uint8_t *der_opt;
    cc_size n = ccdh_gp_n(gp);
    uint64_t l = 0;
    
    der = ccder_decode_constructed_tl(CCDER_CONSTRUCTED_SEQUENCE, &der_end, der, der_end);
    der = ccder_decode_uint(n, CCDH_GP_PRIME(gp), der, der_end);
    if (der && (cczp_init(CCDH_GP_ZP(gp)) != 0)) { // cczp_init only runs if the prime was decoded
        return NULL; // cczp_init failed, indicate error
    }
    der = ccder_decode_uint(n, CCDH_GP_G(gp), der, der_end);
    
    // Check to see if the prime and generator correspond to a known group.
    ccdh_const_gp_t looked_up_gp = ccdh_lookup_gp(n, CCDH_GP_PRIME(gp), n, CCDH_GP_G(gp));
    
    // Copy any q and l value of looked up group, and then compare to known values.
    if (looked_up_gp) {
        ccdh_copy_gp(gp, looked_up_gp);
    } else {
        ccn_zero(n, CCDH_GP_Q(gp)); // If we don't know sub-group size, zero it.
    }
    
    // Read in minimum exponent length value. If it is larger than any predefined lookup value use it assuming it hits a minimal requirement
    // If we don't have a given length, or it is smaller than the minimal requirement, default to the maximum group length.
    der_opt = ccder_decode_uint64(&l, der, der_end);
    if (der_opt) {
        der=der_opt;
    }
    CCDH_GP_L(gp) = (cc_unit)l; // Set the read in l value, and ramp to larger if necessary.
    ccdh_ramp_gp_exponent((size_t)l, gp);
    return der;
}

cc_size ccder_decode_dhparam_n(const uint8_t *der, const uint8_t *der_end)
{
    cc_size n;
    if((der = ccder_decode_constructed_tl(CCDER_CONSTRUCTED_SEQUENCE, &der_end, der, der_end)) == NULL) return 0;
    if(ccder_decode_uint_n(&n, der, der_end) == NULL) return 0;
    return n;
}

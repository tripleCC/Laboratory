/* Copyright (c) (2011,2015,2016,2017,2018,2019,2020) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */


#include <corecrypto/ccdh.h>
#include "ccdh_internal.h"

int ccdh_init_gp(ccdh_gp_t gp, cc_size n, const cc_unit *p, const cc_unit *g, size_t L)
{
    int status;
    
    /* initialize prime, zp and g */
    CCDH_GP_N(gp) = n;
    ccn_set(n, CCDH_GP_PRIME(gp), p);
    ccn_set(n, CCDH_GP_G(gp), g);
    ccdh_const_gp_t known_group = ccdh_lookup_gp(n, CCDH_GP_PRIME(gp), n, CCDH_GP_G(gp));
    if (known_group != NULL) {
        status = ccdh_copy_gp(gp, known_group);
    } else {
        status = cczp_init(CCDH_GP_ZP(gp)); //on top of gp, there is a zp
        ccn_zero(n, CCDH_GP_Q(gp));
        CCDH_GP_L(gp) = L;
    }
    ccdh_ramp_gp_exponent(L, gp);
    return status;
}

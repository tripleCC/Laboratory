/* Copyright (c) (2011,2015,2016,2017,2019,2020) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "ccdh_internal.h"

int ccdh_init_gp_with_order(ccdh_gp_t gp, cc_size n, const cc_unit *p, const cc_unit *g, const cc_unit *q)
{
    int status;
    /* initialize prime, zp and g */
    CCDH_GP_N(gp) = n;
    ccn_set(n, CCDH_GP_PRIME(gp), p);
    status=cczp_init(CCDH_GP_ZP(gp));
    ccn_set(n, CCDH_GP_G(gp), g);
    ccn_set(n, CCDH_GP_Q(gp), q);
    CCDH_GP_L(gp) = 0;
    return status;
}

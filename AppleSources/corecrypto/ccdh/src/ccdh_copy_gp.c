/* Copyright (c) (2018,2019,2022) Apple Inc. All rights reserved.
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
#include <corecrypto/cc.h>
#include <corecrypto/cc_priv.h>
#include "ccdh_internal.h"

// Function to copy one ccdh_gp structure onto another.
int ccdh_copy_gp(ccdh_gp_t dest, const ccdh_const_gp_t src)
{
    if (CCDH_GP_N(dest) != ccdh_gp_n(src)) {
        return CCDH_DOMAIN_PARAMETER_MISMATCH;
    }
    
    // ccdh_gp_size takes number of bytes to represent group prime, but it is stored in cc_units
    size_t gp_n = ccdh_gp_size(ccdh_gp_n(src) * sizeof(cc_unit));
    cc_memcpy(dest, src, gp_n);
    return CCERR_OK;
}

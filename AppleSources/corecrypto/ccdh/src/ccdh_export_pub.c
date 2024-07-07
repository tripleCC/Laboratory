/* Copyright (c) (2011,2015,2017-2019,2021) Apple Inc. All rights reserved.
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
#include "ccdh_internal.h"

void ccdh_export_pub(ccdh_pub_ctx_t key, void *out)
{
    CC_ENSURE_DIT_ENABLED

    size_t len = ccdh_export_pub_size(key);
    ccdh_const_gp_t gp = ccdh_ctx_gp(key);
    cc_size n = ccdh_gp_n(gp);

    ccn_write_uint_padded_ct(n, ccdh_ctx_y(key), len, out);
}

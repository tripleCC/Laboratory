/* Copyright (c) (2011,2015-2019,2021) Apple Inc. All rights reserved.
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

int ccdh_import_pub(ccdh_const_gp_t gp, size_t in_len, const uint8_t *in,
                  ccdh_pub_ctx_t key)
{
    CC_ENSURE_DIT_ENABLED

    cc_unit *y = ccdh_ctx_y(key);
    ccdh_ctx_init(gp, key);

    if ((ccn_read_uint(ccdh_gp_n(gp), y, in_len, in)))
        return CCDH_INVALID_INPUT;

    if (ccn_cmp(ccdh_gp_n(gp), y, ccdh_gp_prime(gp)) >= 0)
        return CCDH_SAFETY_CHECK;

    return 0;
}

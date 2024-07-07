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
#include <corecrypto/cczp.h>

int ccdh_import_full(ccdh_const_gp_t gp,
                     size_t in_priv_len, const uint8_t *in_priv,
                     size_t in_pub_len,  const uint8_t *in_pub,
                     ccdh_full_ctx_t key)
{
    CC_ENSURE_DIT_ENABLED

    ccdh_ctx_init(gp, ccdh_ctx_public(key));
    cc_unit *x = ccdh_ctx_x(key);

    if ((ccn_read_uint(ccdh_gp_n(gp), x, in_priv_len, in_priv)))
        return CCDH_INVALID_INPUT;

    if (ccn_cmp(ccdh_gp_n(gp), x, cczp_prime(ccdh_gp_zp(gp))) >= 0)
        return CCDH_SAFETY_CHECK;

    return ccdh_import_pub(gp,in_pub_len,in_pub,ccdh_ctx_public(key));
}

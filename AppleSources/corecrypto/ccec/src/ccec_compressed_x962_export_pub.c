/* Copyright (c) (2014,2015,2018-2021) Apple Inc. All rights reserved.
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
#include <corecrypto/ccec_priv.h>
#include "ccec_internal.h"


size_t ccec_compressed_x962_export_pub_size(ccec_const_cp_t cp)
{
    CC_ENSURE_DIT_ENABLED

    return (ccec_cp_prime_size(cp) + 1);
}

int ccec_compressed_x962_export_pub(const ccec_pub_ctx_t key, uint8_t *out)
{
    CC_ENSURE_DIT_ENABLED

    // Export in compressed format
    ccec_const_cp_t cp = ccec_ctx_cp(key);
    size_t out_nbytes = ccec_compressed_x962_export_pub_size(cp);
    return ccec_export_affine_point(
        cp, CCEC_FORMAT_COMPRESSED, (ccec_const_affine_point_t)ccec_ctx_point(key), &out_nbytes, out);
}
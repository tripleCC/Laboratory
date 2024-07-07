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

#include "cc_internal.h"
#include "cc_macros.h"
#include "ccec_internal.h"

int ccec_raw_import_pub(ccec_const_cp_t cp, size_t in_len, const uint8_t *in, ccec_pub_ctx_t key)
{
    CC_ENSURE_DIT_ENABLED

    cc_require(in_len == 2 * ccec_cp_prime_size(cp), err);

    cc_size n = ccec_cp_n(cp);
    size_t step = ccec_cp_prime_size(cp);

    ccec_ctx_init(cp, key);
    cc_require(ccn_read_uint(n, ccec_ctx_x(key), step, in) == 0, err);
    cc_require(ccn_read_uint(n, ccec_ctx_y(key), step, in + step) == 0, err);
    ccn_seti(ccec_cp_n(cp), ccec_ctx_z(key), 1);

    return 0;

err:
    return -1;
}

int ccec_raw_import_priv_only(ccec_const_cp_t cp, size_t in_len, const uint8_t *in, ccec_full_ctx_t key)
{
    CC_ENSURE_DIT_ENABLED

    if (in_len != ccec_cp_order_size(cp)) {
        return -1;
    }

    cc_size n = ccec_cp_n(cp);

    ccec_ctx_init(cp, key);
    cc_memset(ccec_ctx_x(key), 0xff, ccn_sizeof_n(n));
    cc_memset(ccec_ctx_y(key), 0xff, ccn_sizeof_n(n));
    return ccn_read_uint(n, ccec_ctx_k(key), in_len, in);
}

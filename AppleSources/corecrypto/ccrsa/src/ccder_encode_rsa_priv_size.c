/* Copyright (c) (2012,2015,2016,2019,2021,2022) Apple Inc. All rights reserved.
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
#include <corecrypto/ccrsa_priv.h>
#include <corecrypto/ccder.h>

size_t ccder_encode_rsa_priv_size(const ccrsa_full_ctx_t key)
{
    cc_size n = ccrsa_ctx_n(key);
    cc_unit version_0 = 0;

    return ccder_sizeof(CCDER_CONSTRUCTED_SEQUENCE,
      ccder_sizeof_integer(ccn_nof(1), &version_0) +
      ccder_sizeof_integer(n, ccrsa_ctx_m(key)) +
      ccder_sizeof_integer(n, ccrsa_ctx_e(key)) +
      ccder_sizeof_integer(n, ccrsa_ctx_d(key)) +
      ccder_sizeof_integer(cczp_n(ccrsa_ctx_private_zp(key)), cczp_prime(ccrsa_ctx_private_zp(key))) +
      ccder_sizeof_integer(cczp_n(ccrsa_ctx_private_zq(key)), cczp_prime(ccrsa_ctx_private_zq(key))) +
      ccder_sizeof_integer(cczp_n(ccrsa_ctx_private_zp(key)), ccrsa_ctx_private_dp(key)) +
      ccder_sizeof_integer(cczp_n(ccrsa_ctx_private_zq(key)), ccrsa_ctx_private_dq(key)) +
      ccder_sizeof_integer(cczp_n(ccrsa_ctx_private_zp(key)), ccrsa_ctx_private_qinv(key))
    );
}

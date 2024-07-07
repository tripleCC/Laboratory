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

CC_INLINE uint8_t *
ccder_encode_cczp_as_integer(cczp_t zp, const uint8_t *der, uint8_t *der_end) {
    return ccder_encode_integer(cczp_n(zp), cczp_prime(zp), der, der_end);
}

uint8_t *ccder_encode_rsa_priv(const ccrsa_full_ctx_t key, const uint8_t *der, uint8_t *der_end) {
    CC_ENSURE_DIT_ENABLED

     
    cc_size n = ccrsa_ctx_n(key);
	cc_unit version_0[1] = {0x00};
    
    return ccder_encode_constructed_tl(CCDER_CONSTRUCTED_SEQUENCE, der_end, der,
      ccder_encode_integer(ccn_nof(1), version_0, der,
      ccder_encode_integer(n, ccrsa_ctx_m(key), der,
      ccder_encode_integer(n, ccrsa_ctx_e(key), der,
      ccder_encode_integer(n, ccrsa_ctx_d(key), der,
      ccder_encode_cczp_as_integer(ccrsa_ctx_private_zp(key), der,
      ccder_encode_cczp_as_integer(ccrsa_ctx_private_zq(key), der,
      ccder_encode_integer(cczp_n(ccrsa_ctx_private_zp(key)), ccrsa_ctx_private_dp(key), der,
      ccder_encode_integer(cczp_n(ccrsa_ctx_private_zq(key)), ccrsa_ctx_private_dq(key), der,
      ccder_encode_integer(cczp_n(ccrsa_ctx_private_zp(key)), ccrsa_ctx_private_qinv(key), der,
    der_end))))))))));
}

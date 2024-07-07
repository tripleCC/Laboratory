/* Copyright (c) (2012,2015,2017,2019-2022) Apple Inc. All rights reserved.
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
#include <corecrypto/ccrsa.h>
#include <corecrypto/ccder.h>
#include "cczp_internal.h"

// Key is expected to be in PKCS #1 format
const uint8_t *ccder_decode_rsa_pub(const ccrsa_pub_ctx_t key, const uint8_t *der, const uint8_t *der_end)
{
    cc_size n = ccrsa_ctx_n(key);

    der = ccder_decode_constructed_tl(CCDER_CONSTRUCTED_SEQUENCE, &der_end, der, der_end);
    der = ccder_decode_uint(n, ccrsa_ctx_m(key), der, der_end);
    der = ccder_decode_uint(n, ccrsa_ctx_e(key), der, der_end);
    if(der && (cczp_init(ccrsa_ctx_zm(key))!=0)) { // cczp_init only runs if no error
        der=NULL; // cczp_init failed, indicate error
    }
    return der;
}

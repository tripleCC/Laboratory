/* Copyright (c) (2012-2019,2021) Apple Inc. All rights reserved.
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
#include <corecrypto/ccder.h>
#include <corecrypto/ccec_priv.h>
#include "ccec_internal.h"
#include "cc_macros.h"
#include "cc_debug.h"


int ccec_der_import_priv_keytype(size_t length, const uint8_t * data, ccoid_t *oid, size_t *n)
{
    CC_ENSURE_DIT_ENABLED

    uint64_t version;
    size_t priv_size = 0, pub_size = 0;
    const uint8_t *priv_key = NULL, *pub_key = NULL;
    ccoid_t key_oid;

    cc_require(ccder_decode_eckey(&version, &priv_size, &priv_key, &key_oid, &pub_size, &pub_key, data, data + length), out);

    /* oid is optional, may have to derive cp from private key length */
    *oid = key_oid;
    *n = priv_size;

    return 0;
out:
    return -1;
}

int ccec_der_import_priv(ccec_const_cp_t cp, size_t length, const uint8_t *data, ccec_full_ctx_t full_key)
{
    CC_ENSURE_DIT_ENABLED

    uint64_t version;
    size_t priv_size = 0, pub_size = 0;
    const uint8_t *priv_key = NULL, *pub_key = NULL;
    ccoid_t key_oid;
    int result;
    ccec_ctx_init(cp, full_key);
    cc_require(ccder_decode_eckey(&version, &priv_size, &priv_key, &key_oid, &pub_size, &pub_key, data, data + length), out);

    /* Load up private key */
    cc_require(priv_size == ccec_cp_order_size(cp), out);
    cc_require(0 == ccn_read_uint(ccec_cp_n(cp), ccec_ctx_k(full_key), priv_size, priv_key), out);

    /* pub_size is partially checked by import pub: being odd */
    if (pub_key && (pub_size / 8 >= 2 * ccec_cp_prime_size(cp) + 1)) {
        cc_require(CCERR_OK == ccec_import_pub(cp, pub_size / 8, pub_key, ccec_ctx_pub(full_key)), out);
        result = 0;
    } else {
        /* Calculate pub from priv if absent */
        result = ccec_make_pub_from_priv(cp, NULL, ccec_ctx_k(full_key), NULL, ccec_ctx_pub(full_key));
    }

    return result;
out:
    return -1;
}

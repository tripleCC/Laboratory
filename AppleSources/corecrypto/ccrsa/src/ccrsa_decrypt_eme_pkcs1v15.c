/* Copyright (c) (2011,2013,2015-2017,2019,2021,2022) Apple Inc. All rights reserved.
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
#include "ccrsa_internal.h"

static int ccrsa_decrypt_eme_pkcs1v15_ws(cc_ws_t ws,
                                         ccrsa_full_ctx_t key,
                                         size_t *r_size, uint8_t *r,
                                         size_t s_size, const uint8_t *s)
{
    struct ccrng_state *rng = ccrng(NULL);
    if (!rng) {
        return CCERR_INTERNAL;
    }

    return ccrsa_decrypt_eme_pkcs1v15_blinded_ws(ws, rng, key, r_size, r, s_size, s);
}

int ccrsa_decrypt_eme_pkcs1v15(ccrsa_full_ctx_t key,
                               size_t *r_size, uint8_t *r,
                               size_t s_size, const uint8_t *s)
{
    CC_ENSURE_DIT_ENABLED

    CC_DECL_WORKSPACE_OR_FAIL(ws, CCRSA_DECRYPT_EME_PKCS1V15_WORKSPACE_N(ccrsa_ctx_n(key)));
    int rv = ccrsa_decrypt_eme_pkcs1v15_ws(ws, key, r_size, r, s_size, s);
    CC_FREE_WORKSPACE(ws);
    return rv;
}

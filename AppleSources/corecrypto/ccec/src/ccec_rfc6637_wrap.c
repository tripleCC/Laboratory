/* Copyright (c) (2014-2019,2021,2022) Apple Inc. All rights reserved.
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
#include <corecrypto/ccaes.h>
#include <corecrypto/ccdigest.h>
#include <corecrypto/ccsha2.h>
#include <corecrypto/ccwrap.h>

size_t
ccec_rfc6637_wrap_pub_size(ccec_pub_ctx_t public_key,
                           unsigned long flags)
{
    size_t len;

    if (flags & CCEC_RFC6637_COMPACT_KEYS)
        len = ccec_compact_export_size(0, public_key);
    else
        len = ccec_export_pub_size(public_key);
    return len;
}

size_t
ccec_rfc6637_wrap_key_size(ccec_pub_ctx_t public_key,
                           unsigned long flags,
                           size_t key_len)
{
    CC_ENSURE_DIT_ENABLED

    size_t len;

    len=ccec_rfc6637_wrap_pub_size(public_key,flags);
    if (flags & CCEC_RFC6637_DEBUG_KEYS) {
        len += 2;
        len += key_len;
        len += ccec_cp_prime_size(ccec_ctx_cp(public_key));
    }
    return 2 + len + 1 + 48;
}

CC_NONNULL_ALL CC_WARN_RESULT
static int ccec_rfc6637_wrap_key_ws(cc_ws_t ws,
                                    ccec_pub_ctx_t public_key,
                                    void *wrapped_key,
                                    unsigned long flags,
                                    uint8_t symm_alg_id,
                                    size_t key_len,
                                    const void *key,
                                    const struct ccec_rfc6637_curve *curve,
                                    const struct ccec_rfc6637_wrap *wrap,
                                    const uint8_t *fingerprint, /* 20 bytes */
                                    struct ccrng_state *rng)
{
    ccec_const_cp_t cp = ccec_ctx_cp(public_key);
    cc_size n = ccec_cp_n(cp);

    CC_DECL_BP_WS(ws, bp);
    ccec_full_ctx_t ephemeral_key = CCEC_ALLOC_FULL_WS(ws, n);

    /* Generate ephemeral key. We use the same generation method irrespective
        of compact format since the sign does not matter in wrapping operations */

    int rv = ccecdh_generate_key_ws(ws, cp, rng, ephemeral_key);
    cc_require(rv == CCERR_OK, errOut);


    /*
     *  Perform wrapping
     */

    rv = ccec_rfc6637_wrap_core_ws(ws, public_key,
                                       ephemeral_key,
                                       wrapped_key, flags,
                                       symm_alg_id, key_len,
                                       key, curve, wrap,
                                       fingerprint, rng);

errOut:
    CC_FREE_BP_WS(ws, bp);
    return rv;
}

int ccec_rfc6637_wrap_key(ccec_pub_ctx_t public_key,
                          void *wrapped_key,
                          unsigned long flags,
                          uint8_t symm_alg_id,
                          size_t key_len,
                          const void *key,
                          const struct ccec_rfc6637_curve *curve,
                          const struct ccec_rfc6637_wrap *wrap,
                          const uint8_t *fingerprint, /* 20 bytes */
                          struct ccrng_state *rng)
{
    CC_ENSURE_DIT_ENABLED

    ccec_const_cp_t cp = ccec_ctx_cp(public_key);
    CC_DECL_WORKSPACE_OR_FAIL(ws, CCEC_RFC6637_WRAP_KEY_WORKSPACE_N(ccec_cp_n(cp)));
    int rv = ccec_rfc6637_wrap_key_ws(ws, public_key, wrapped_key, flags,
                                          symm_alg_id, key_len, key, curve,
                                          wrap, fingerprint, rng);
    CC_FREE_WORKSPACE(ws);
    return rv;
}

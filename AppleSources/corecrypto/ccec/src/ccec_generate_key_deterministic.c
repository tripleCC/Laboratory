/* Copyright (c) (2015-2022) Apple Inc. All rights reserved.
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
#include <corecrypto/ccrng.h>
#include <corecrypto/ccn.h>
#include <corecrypto/cczp.h>
#include <corecrypto/ccrng_drbg.h>
#include <corecrypto/ccrng_sequence.h>
#include "ccrng_sequence_non_repeat.h"
#include <corecrypto/ccsha2.h>
#include "cc_macros.h"
#include "cc_debug.h"

int ccec_generate_key_deterministic_ws(cc_ws_t ws,
                                       ccec_const_cp_t cp,
                                       size_t entropy_len,
                                       const uint8_t *entropy,
                                       struct ccrng_state *rng, // For masking and signature
                                       uint32_t flags,
                                       ccec_full_ctx_t key)
{
    int result=CCEC_GENERATE_KEY_DEFAULT_ERR;

    ccec_ctx_init(cp,key);

    //==========================================================================
    // Key generation
    //==========================================================================

    if ((CCEC_GENKEY_DETERMINISTIC_SECBKP&flags)==CCEC_GENKEY_DETERMINISTIC_SECBKP) {
        struct ccrng_sequence_state seq_rng;
        // Discard some bytes to be compatible with previous behavior of corecrypto
        // functions
        size_t discarded_len=ccn_sizeof(ccec_cp_prime_bitlen(cp)-1);
        entropy += discarded_len;
        entropy_len -= discarded_len;
        // Retry takes a non deterministic number of byte, to reduce the probability
        // of failure, we need extra bytes
        cc_require_action(entropy_len>=10*(ccn_sizeof(ccec_cp_order_bitlen(cp))),errOut,result=CCERR_OUT_OF_ENTROPY);

        result = ccrng_sequence_non_repeat_init(&seq_rng,entropy_len, entropy);
        cc_require(result == CCERR_OK, errOut);

        result = ccec_generate_scalar_fips_retry_ws(ws, cp, (struct ccrng_state*)&seq_rng, ccec_ctx_k(key));
        cc_require(result == CCERR_OK, errOut);
    }
    else if ((CCEC_GENKEY_DETERMINISTIC_FIPS&flags)==CCEC_GENKEY_DETERMINISTIC_FIPS) {
        // Use entropy directly in the extrabits method, requires more bytes
        result = ccec_generate_scalar_fips_extrabits_ws(ws, cp, entropy_len, entropy, ccec_ctx_k(key));
        cc_require(result == CCERR_OK, errOut);
    }
    // Use entropy with the legacy method, to reconstruct previously generated
    // keys
    else if ((CCEC_GENKEY_DETERMINISTIC_LEGACY&flags)==CCEC_GENKEY_DETERMINISTIC_LEGACY) {
        result = ccec_generate_scalar_legacy_ws(ws, cp, entropy_len, entropy, ccec_ctx_k(key));
        cc_require(result == CCERR_OK, errOut);
    } else {
        result = CCEC_GENERATE_NOT_SUPPORTED;
        goto errOut;
    }

    //==========================================================================
    // Calculate the public key for k
    //==========================================================================
    result = ccec_make_pub_from_priv_ws(ws, cp, rng, ccec_ctx_k(key), NULL, ccec_ctx_pub(key));
    cc_require(result == CCERR_OK, errOut);

    //==========================================================================
    // Transform the key to support compact export/import format
    //==========================================================================
    if ((CCEC_GENKEY_DETERMINISTIC_COMPACT&flags)==CCEC_GENKEY_DETERMINISTIC_COMPACT) {
        ccec_compact_transform_key_ws(ws, key);
    }

    //==========================================================================
    // Pairwise consistency check
    //==========================================================================
    result = ccec_pairwise_consistency_check_ws(ws, key, rng);
    cc_require_action(result == CCERR_OK, errOut, result = CCEC_GENERATE_KEY_CONSISTENCY);

errOut:
    return result;
}

int ccec_generate_key_deterministic(ccec_const_cp_t cp,
                                    size_t entropy_len,
                                    const uint8_t *entropy,
                                    struct ccrng_state *rng, // For masking and signature
                                    uint32_t flags,
                                    ccec_full_ctx_t key)
{
    CC_ENSURE_DIT_ENABLED

    CC_DECL_WORKSPACE_OR_FAIL(ws, CCEC_GENERATE_KEY_DETERMINISTIC_WORKSPACE_N(ccec_cp_n(cp)));
    int rv = ccec_generate_key_deterministic_ws(ws, cp, entropy_len, entropy, rng, flags, key);
    CC_FREE_WORKSPACE(ws);
    return rv;
}

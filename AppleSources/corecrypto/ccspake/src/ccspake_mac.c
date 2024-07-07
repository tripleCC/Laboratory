/* Copyright (c) (2018,2019,2021,2022) Apple Inc. All rights reserved.
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
#include <corecrypto/ccspake.h>
#include <corecrypto/cchkdf.h>

#include "cc_workspaces.h"
#include "ccspake_internal.h"
#include "cc_priv.h"

static const uint8_t KDF_LABEL_CK[16] = { 'C', 'o', 'n', 'f', 'i', 'r', 'm', 'a', 't', 'i', 'o', 'n', 'K', 'e', 'y', 's' };
static const uint8_t KDF_LABEL_SK[9]  = { 'S', 'h', 'a', 'r', 'e', 'd', 'K', 'e', 'y' };

int ccspake_mac_hkdf_derive(ccspake_const_ctx_t ctx, size_t ikm_nbytes, const uint8_t *ikm, uint8_t *keys)
{
    const struct ccdigest_info *di = ccspake_ctx_mac(ctx)->di();
    size_t aad_nbytes = ccspake_ctx_aad_nbytes(ctx);

    size_t info_nbytes = sizeof(KDF_LABEL_CK);
    uint8_t info[sizeof(KDF_LABEL_CK) + sizeof(ctx->aad)] = { 0 };
    cc_memcpy(info, KDF_LABEL_CK, sizeof(KDF_LABEL_CK));

    // The CCC variant appends AAD to the label when deriving confirmation keys.
    if (ccspake_ctx_variant(ctx) == CCSPAKE_VARIANT_CCC_V1 && aad_nbytes > 0) {
        cc_memcpy(info + sizeof(KDF_LABEL_CK), ccspake_ctx_aad(ctx), aad_nbytes);
        info_nbytes += aad_nbytes;
    }

    size_t keys_nbytes = ccspake_ctx_mac(ctx)->confirm_key_nbytes * 2;
    return cchkdf(di, ikm_nbytes, ikm, 0, NULL, info_nbytes, info, keys_nbytes, keys);
}

/*! @function ccspake_mac_compute_internal
 @abstract Generic function to derive MAC keys and compute MACs

 @param ctx    SPAKE2+ context
 @param k_main Key to derive MAC keys from (K_main)
 @param use_k1 Flag to tell whether to compute a MAC with K_confirmP or K_confirmV
 @param x      x-coordinate of the point to confirm
 @param y      y-coordinate of the point to confirm
 @param t_len  Length of t
 @param t      Target buffer
 */
CC_NONNULL_ALL CC_WARN_RESULT
static int ccspake_mac_compute_internal(ccspake_const_ctx_t ctx,
                                        const uint8_t *k_main,
                                        bool use_k1,
                                        const cc_unit *x,
                                        const cc_unit *y,
                                        size_t t_len,
                                        uint8_t *t)
{
    size_t h_len = ccspake_ctx_mac(ctx)->di()->output_size;
    ccec_const_cp_t cp = ccspake_ctx_cp(ctx);
    size_t p_len = ccec_cp_prime_size(cp);
    cc_size n = ccec_cp_n(cp);

    size_t k_main_nbytes = h_len;
    if (ccspake_ctx_variant(ctx) == CCSPAKE_VARIANT_CCC_V1) {
        // CCC: CK || SK = SHA-256(TT) [K_main=CK is the first half.]
        k_main_nbytes /= 2;
    }

    uint8_t confirm_keys[CCSPAKE_MAX_CONFIRM_KEY_NBYTES * 2];
    int rv = ccspake_ctx_mac(ctx)->derive(ctx, k_main_nbytes, k_main, confirm_keys);
    if (rv != CCERR_OK) {
        return rv;
    }

    // CCC v1 has the reverse confirmation key order.
    use_k1 ^= (ccspake_ctx_variant(ctx) == CCSPAKE_VARIANT_CCC_V1);

    // Write coordinates.
    uint8_t info[1 + 2 * CCSPAKE_MAX_CURVE_NBYTES] = { CCSPAKE_X963_UNCOMPRESSED, 0x00 };
    ccn_write_uint_padded(n, x, p_len, info + 1);
    ccn_write_uint_padded(n, y, p_len, info + 1 + p_len);

    size_t ck_nbytes = ccspake_ctx_mac(ctx)->confirm_key_nbytes;
    if (ccspake_ctx_variant(ctx) == CCSPAKE_VARIANT_CCC_V1) {
        // CCC: K1 || K2 = HKDF(CK, "ConfirmationKeys" || AAD)
        ck_nbytes = h_len / 2;
    }

    uint8_t *ckey = confirm_keys + (!use_k1 * ck_nbytes);
    size_t pt_nbytes = ccspake_sizeof_point(ccspake_ctx_scp(ctx));
    rv = ccspake_ctx_mac(ctx)->compute(ctx, ck_nbytes, ckey, pt_nbytes, info, t_len, t);

    cc_clear(sizeof(confirm_keys), confirm_keys);
    return rv;
}

int ccspake_mac_compute(ccspake_ctx_t ctx, size_t t_len, uint8_t *t)
{
    CC_ENSURE_DIT_ENABLED

    CCSPAKE_EXPECT_STATES(KEX_BOTH, MAC_VERIFY);

    const uint8_t *key = ccspake_ctx_main_key(ctx);

    int rv = ccspake_mac_compute_internal(
        ctx, key, ccspake_ctx_is_prover(ctx), ccspake_ctx_Q_x(ctx), ccspake_ctx_Q_y(ctx), t_len, t);

    if (rv == CCERR_OK) {
        CCSPAKE_ADD_STATE(MAC_GENERATE);
    }

    return rv;
}

int ccspake_mac_verify_and_get_session_key(ccspake_ctx_t ctx, size_t t_len, const uint8_t *t, size_t sk_len, uint8_t *sk)
{
    CC_ENSURE_DIT_ENABLED

    CCSPAKE_EXPECT_STATES(KEX_BOTH, MAC_GENERATE);

    const struct ccdigest_info *di = ccspake_ctx_mac(ctx)->di();
    size_t h_len = di->output_size;

    if (ccspake_ctx_variant(ctx) == CCSPAKE_VARIANT_CCC_V1) {
        // CCC: CK || SK = Hash(TT)
        cc_require_or_return(sk_len == h_len / 2, CCERR_PARAMETER);
    } else if (ccspake_ctx_variant(ctx) == CCSPAKE_VARIANT_RFC) {
        // RFC: SK = KDF(nil, K_main, "SharedKey")
        cc_require_or_return(sk_len > 0, CCERR_PARAMETER);
    }

    if (t_len > CCSPAKE_MAX_TAG_NBYTES) {
        return CCERR_PARAMETER;
    }

    const uint8_t *key = ccspake_ctx_main_key(ctx);

    uint8_t tag[CCSPAKE_MAX_TAG_NBYTES];
    int rv = ccspake_mac_compute_internal(
        ctx, key, !ccspake_ctx_is_prover(ctx), ccspake_ctx_XY_x(ctx), ccspake_ctx_XY_y(ctx), t_len, tag);

    if (rv != CCERR_OK) {
        goto cleanup;
    }

    if (cc_cmp_safe(t_len, t, tag)) {
        rv = CCERR_INTEGRITY;
        goto cleanup;
    }

    if (ccspake_ctx_variant(ctx) == CCSPAKE_VARIANT_CCC_V1) {
        // CCC: CK || SK = Hash(TT)
        cc_memcpy(sk, key + h_len / 2, h_len / 2);
    } else if (ccspake_ctx_variant(ctx) == CCSPAKE_VARIANT_RFC) {
        // RFC: SK = KDF(nil, K_main, "SharedKey")
        rv = cchkdf(di, di->output_size, ccspake_ctx_main_key(ctx), 0, NULL, sizeof(KDF_LABEL_SK), KDF_LABEL_SK, sk_len, sk);
        cc_require(rv == CCERR_OK, cleanup);
    }

    CCSPAKE_ADD_STATE(MAC_VERIFY);

cleanup:
    cc_clear(sizeof(tag), tag);
    return rv;
}

/* Copyright (c) (2018,2019,2021-2023) Apple Inc. All rights reserved.
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
#include "ccspake_internal.h"
#include "ccec_internal.h"
#include "cc_macros.h"

const uint8_t CCSPAKE_STATE_INIT = 0b00001;
const uint8_t CCSPAKE_STATE_KEX_GENERATE = 0b00011;
const uint8_t CCSPAKE_STATE_KEX_PROCESS = 0b00101;
const uint8_t CCSPAKE_STATE_KEX_BOTH = 0b00111;
const uint8_t CCSPAKE_STATE_MAC_GENERATE = 0b01111;
const uint8_t CCSPAKE_STATE_MAC_VERIFY = 0b10111;
const uint8_t CCSPAKE_STATE_MAC_BOTH = 0b11111;

size_t ccspake_sizeof_w(ccspake_const_cp_t scp)
{
    size_t w_nbytes = ccec_cp_order_size(ccspake_cp_ec(scp));

    // The CCC variant reduces n+64 bits of entropy.
    if (scp->var == CCSPAKE_VARIANT_CCC_V1) {
        w_nbytes += 8;
    }

    return w_nbytes;
}

size_t ccspake_sizeof_point(ccspake_const_cp_t scp)
{
    return ccec_export_pub_size_cp(ccspake_cp_ec(scp));
}

size_t ccspake_sizeof_ctx(ccspake_const_cp_t scp)
{
    return sizeof(struct ccspake_ctx) +
        ccec_ccn_size(ccspake_cp_ec(scp)) * CCSPAKE_INTERNAL_STORAGE_NUNITS;
}

CC_WARN_RESULT CC_NONNULL_ALL
static int ccspake_reduce_w_ws(cc_ws_t ws,
                               ccspake_const_cp_t scp,
                               size_t w_in_nbytes,
                               const uint8_t *w_in,
                               size_t w_out_nbytes,
                               uint8_t *w_out)
{
    // The CCC variant doesn't need this API.
    if (scp->var == CCSPAKE_VARIANT_CCC_V1) {
        return CCERR_PARAMETER;
    }

    if (ccspake_sizeof_w(scp) != w_out_nbytes) {
        return CCERR_PARAMETER;
    }

    ccec_const_cp_t cp = ccspake_cp_ec(scp);
    cc_size n = ccec_cp_n(cp);

    CC_DECL_BP_WS(ws, bp);
    cc_unit *t = CC_ALLOC_WS(ws, n);

    int rv = ccec_generate_scalar_fips_extrabits_ws(ws, cp, w_in_nbytes, w_in, t);
    cc_require(rv == CCERR_OK, errOut);

    ccn_write_uint_padded_ct(n, t, w_out_nbytes, w_out);

errOut:
    CC_FREE_BP_WS(ws, bp);
    return rv;
}

int ccspake_reduce_w(ccspake_const_cp_t scp,
                     size_t w_in_nbytes,
                     const uint8_t *w_in,
                     size_t w_out_nbytes,
                     uint8_t *w_out)
{
    CC_ENSURE_DIT_ENABLED
    
    ccec_const_cp_t cp = ccspake_cp_ec(scp);
    CC_DECL_WORKSPACE_OR_FAIL(ws, CCSPAKE_REDUCE_W_WORKSPACE_N(ccec_cp_n(cp)));
    int rv = ccspake_reduce_w_ws(ws, scp, w_in_nbytes, w_in, w_out_nbytes, w_out);
    CC_FREE_WORKSPACE(ws);
    return rv;
}

CC_NONNULL_ALL CC_WARN_RESULT
static int ccspake_generate_L_ws(cc_ws_t ws,
                                 ccspake_const_cp_t scp,
                                 size_t w1_nbytes,
                                 const uint8_t *w1,
                                 size_t L_nbytes,
                                 uint8_t *L,
                                 struct ccrng_state *rng)
{
    int rv;

    if (w1_nbytes != ccspake_sizeof_w(scp)) {
        return CCERR_PARAMETER;
    }

    if (L_nbytes != ccspake_sizeof_point(scp)) {
        return CCERR_PARAMETER;
    }

    ccec_const_cp_t cp = ccspake_cp_ec(scp);
    cc_size n = ccec_cp_n(cp);

    CC_DECL_BP_WS(ws, bp);
    cc_unit *k = CC_ALLOC_WS(ws, n);
    ccec_full_ctx_t full = CCEC_ALLOC_FULL_WS(ws, n);
    ccec_ctx_init(cp, full);

    if (scp->var == CCSPAKE_VARIANT_CCC_V1) {
        // CCC: L := (w1 mod (q-1) + 1) * G
        rv = ccec_generate_key_deterministic_ws(ws, cp, w1_nbytes, w1, rng, CCEC_GENKEY_DETERMINISTIC_FIPS, full);
        cc_require(rv == CCERR_OK, errOut);
    } else {
        // RFC: L := w1 * G
        rv = ccn_read_uint(n, k, w1_nbytes, w1);
        cc_require(rv == CCERR_OK, errOut);

        rv = ccec_make_pub_from_priv_ws(ws, cp, rng, k, NULL, ccec_ctx_pub(full));
        cc_require(rv == CCERR_OK, errOut);
    }

    rv = ccec_export_pub(ccec_ctx_pub(full), L);
    cc_require(rv == CCERR_OK, errOut);

errOut:
    CC_FREE_BP_WS(ws, bp);
    return rv;
}

int ccspake_generate_L(ccspake_const_cp_t scp,
                       size_t w1_nbytes,
                       const uint8_t *w1,
                       size_t L_nbytes,
                       uint8_t *L,
                       struct ccrng_state *rng)
{
    CC_ENSURE_DIT_ENABLED

    ccec_const_cp_t cp = ccspake_cp_ec(scp);
    CC_DECL_WORKSPACE_OR_FAIL(ws, CCSPAKE_GENERATE_L_WORKSPACE_N(ccec_cp_n(cp)));
    int rv = ccspake_generate_L_ws(ws, scp, w1_nbytes, w1, L_nbytes, L, rng);
    CC_FREE_WORKSPACE(ws);
    return rv;
}

int ccspake_cmp_pub_key(ccec_pub_ctx_t pub, const cc_unit *X)
{
    ccec_const_cp_t cp = ccec_ctx_cp(pub);
    cc_size n = ccec_cp_n(cp);
    int rv = 0;

    rv |= ccn_cmp(n, X, ccec_ctx_x(pub));
    rv |= ccn_cmp(n, X + n, ccec_ctx_y(pub));

    return rv;
}

void ccspake_store_pub_key(const ccec_pub_ctx_t pub, cc_unit *dest)
{
    ccec_const_cp_t cp = ccec_ctx_cp(pub);
    cc_size n = ccec_cp_n(cp);

    ccn_set(n, dest, ccec_ctx_x(pub));
    ccn_set(n, dest + n, ccec_ctx_y(pub));
}

int ccspake_import_pub_ws(cc_ws_t ws, ccec_pub_ctx_t pub, size_t x_len, const uint8_t *x)
{
    ccec_const_cp_t cp = ccec_ctx_cp(pub);

    CC_DECL_BP_WS(ws, bp);
    int rv = ccec_import_pub_ws(ws, cp, x_len, x, pub);
    CC_FREE_BP_WS(ws, bp);
    return rv;
}

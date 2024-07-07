/* Copyright (c) (2017-2019,2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "cc_macros.h"
#include "ccdh_internal.h"

#define CCN32_N ccn_nof(32)
static const cc_unit REF_X[CCN32_N] = { CCN32_C(60,0d,de,ed) };

bool ccdh_pairwise_consistency_check_ws(cc_ws_t ws,
                                        ccdh_const_gp_t gp,
                                        struct ccrng_state *rng,
                                        ccdh_full_ctx_t key)
{
    bool result = false;

    cczp_const_t zp = ccdh_gp_zp(gp);
    cc_size n = cczp_n(zp);

    CC_DECL_BP_WS(ws, bp);
    cc_unit *t = CC_ALLOC_WS(ws, n);
    ccdh_full_ctx_t ref_key = CCDH_ALLOC_FULL_WS(ws, n);
    ccdh_ctx_init(gp, ccdh_ctx_public(ref_key));

    ccn_setn(n, ccdh_ctx_x(ref_key), CCN32_N, REF_X);
    cc_require(cczp_power_fast_ws(ws, zp, ccdh_ctx_y(ref_key), ccdh_gp_g(gp), ccdh_ctx_x(ref_key)) == 0, err);

    size_t ss_nbytes = ccdh_ccn_size(gp);
    uint8_t *ss1 = (uint8_t *)CC_ALLOC_WS(ws, n);
    uint8_t *ss2 = (uint8_t *)CC_ALLOC_WS(ws, n);

    cc_clear(ss_nbytes, ss1);
    cc_clear(ss_nbytes, ss2);

    size_t ss1_nbytes = ss_nbytes;
    cc_require(ccdh_compute_shared_secret_ws(ws, key, ccdh_ctx_public(ref_key), &ss1_nbytes, ss1, rng) == 0, err);

    // A faster, variable-time variant of ccdh_compute_shared_secret().
    cc_require(cczp_power_fast_ws(ws, zp, t, ccdh_ctx_y(key), ccdh_ctx_x(ref_key)) == 0, err);

    size_t ss2_nbytes = ccn_write_uint_size(n, t);
    ccn_write_uint_padded(n, t, ss2_nbytes, ss2);

    result = (ss1_nbytes == ss2_nbytes) && (cc_cmp_safe(ss1_nbytes, ss1, ss2) == 0);

err:
    CC_FREE_BP_WS(ws, bp);
    return result;
}

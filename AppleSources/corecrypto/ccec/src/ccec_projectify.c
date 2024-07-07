/* Copyright (c) (2010,2011,2015-2021,2023) Apple Inc. All rights reserved.
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
#include "ccec_internal.h"
#include "cczp_internal.h"
#include "cc_workspaces.h"

int ccec_projectify_jacobian_ws(cc_ws_t ws,
                                ccec_const_cp_t cp,
                                ccec_projective_point_t r,
                                ccec_const_affine_point_t s,
                                struct ccrng_state *masking_rng)
{
    int status;
    cczp_const_decl(zp, ccec_cp_zp(cp));

    cc_assert((void *)r!=(const void*) s); // Points must differ
    CC_DECL_BP_WS(ws, bp);

#if CCEC_DEBUG
    ccec_alprint(cp, "ccec_projectify input", s);
#endif

    // Initialize z
    // Randomized z coordinate
    if (masking_rng) {
        cc_size bitlen=ccec_cp_prime_bitlen(cp);
        status=ccn_random_bits(bitlen-1, ccec_point_z(r, cp), masking_rng);
        ccn_set_bit(ccec_point_z(r, cp), bitlen-2, 1);
        cczp_sqr_ws(ws, zp, ccec_point_x(r, cp), ccec_point_z(r, cp));                       // Z^2 (mtgR^-1)
        cczp_mul_ws(ws, zp, ccec_point_y(r, cp), ccec_point_x(r, cp), ccec_point_z(r, cp));  // Z^3 (mtgR^-2)

        // Set point coordinate from Z, Z^2, Z^3
        cczp_mul_ws(ws, zp, ccec_point_x(r, cp), ccec_point_x(r, cp), ccec_const_point_x(s, cp)); // x.Z^2.mtgR (mtgR^-3)
        cczp_mul_ws(ws, zp, ccec_point_y(r, cp), ccec_point_y(r, cp), ccec_const_point_y(s, cp)); // y.Z^3.mtgR (mtgR^-4)
                                                                                                  // Z.mtgR     (mtgR^-1)
        cczp_to_ws(ws, zp, ccec_point_x(r, cp), ccec_point_x(r, cp)); // x.Z^2.mtgR (mtgR^-2)
        cczp_to_ws(ws, zp, ccec_point_y(r, cp), ccec_point_y(r, cp)); // y.Z^3.mtgR (mtgR^-3)
                                                                      // Z.mtgR     (mtgR^-1)
    } else { // Fixed z coordinate
        ccn_seti(ccec_cp_n(cp), ccec_point_z(r, cp),1);
        (void) masking_rng;

        // Set point in the arithmetic representation
        cczp_to_ws(ws, zp, ccec_point_x(r, cp), ccec_const_point_x(s, cp));
        cczp_to_ws(ws, zp, ccec_point_y(r, cp), ccec_const_point_y(s, cp));
        cczp_to_ws(ws, zp, ccec_point_z(r, cp), ccec_point_z(r, cp));
        status=0;
    }
#if CCEC_DEBUG
    ccec_plprint(cp, "ccec_projectify output", r);
#endif

    CC_FREE_BP_WS(ws, bp);
    return status;
}

int ccec_projectify_homogeneous_ws(cc_ws_t ws,
                                   ccec_const_cp_t cp,
                                   ccec_projective_point_t r,
                                   ccec_const_affine_point_t s,
                                   struct ccrng_state *rng)
{
    int rv = CCERR_OK;

    cczp_const_t zp = ccec_cp_zp(cp);
    cc_size n = cczp_n(zp);

    CC_DECL_BP_WS(ws, bp);

    cc_unit *rx = ccec_point_x(r, cp);
    cc_unit *ry = ccec_point_y(r, cp);
    cc_unit *rz = ccec_point_z(r, cp);

    cczp_to_ws(ws, zp, rx, ccec_const_point_x(s, cp));
    cczp_to_ws(ws, zp, ry, ccec_const_point_y(s, cp));

    if (rng) {
        rv = cczp_generate_non_zero_element_ws(ws, zp, rng, rz);
        cc_require(rv == CCERR_OK, errOut);

        cczp_mul_ws(ws, zp, rx, rx, rz);
        cczp_mul_ws(ws, zp, ry, ry, rz);
    } else {
        ccn_seti(n, rz, 1);
        cczp_to_ws(ws, zp, rz, rz);
    }

errOut:
    CC_FREE_BP_WS(ws, bp);
    return rv;
}

CC_WORKSPACE_OVERRIDE(ccec_projectify_ws, ccec_projectify_jacobian_ws)
CC_WORKSPACE_OVERRIDE(ccec_projectify_ws, ccec_projectify_homogeneous_ws)

int ccec_projectify_ws(cc_ws_t ws,
                       ccec_const_cp_t cp,
                       ccec_projective_point_t r,
                       ccec_const_affine_point_t s,
                       struct ccrng_state *rng)
{
    return CCEC_FUNCS_GET(cp, ccec_projectify)(ws, cp, r, s, rng);
}

int ccec_projectify(ccec_const_cp_t cp,
                    ccec_projective_point_t r,
                    ccec_const_affine_point_t s,
                    struct ccrng_state *masking_rng)
{
    CC_ENSURE_DIT_ENABLED

    CC_DECL_WORKSPACE_OR_FAIL(ws, CCEC_PROJECTIFY_WORKSPACE_N(ccec_cp_n(cp)));
    int rv = ccec_projectify_ws(ws, cp, r,  s, masking_rng);
    CC_FREE_WORKSPACE(ws);
    return rv;
}

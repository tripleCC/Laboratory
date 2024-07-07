/* Copyright (c) (2022,2023) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "ccbfv_priv.h"
#include "ccbfv_debug.h"
#include "ccbfv_util.h"
#include "crypto_test_ccbfv.h"
#include "testmore.h"

/// @brief allocate an array of plaintexts from the workspace
/// @param ws The workspace
/// @param nptexts number of plaintexts to allocate
/// @param plain_ctx plaintext polynomial context
static ccbfv_plaintext_t *alloc_plaintext_array(cc_ws_t ws, uint32_t nptexts, ccpolyzp_po2cyc_ctx_const_t plain_ctx)
{
    ccbfv_plaintext_t *ptext_array = (ccbfv_plaintext_t *)CC_ALLOC_WS(ws, nptexts * ccn_nof_sizeof(ccbfv_plaintext_t));
    for (uint32_t ptext_idx = 0; ptext_idx < nptexts; ++ptext_idx) {
        ptext_array[ptext_idx] = CCBFV_PLAINTEXT_ALLOC_WS(ws, plain_ctx);
    }
    return ptext_array;
}

/// @brief convert an array of plaintexts to an array of constant plaintexts
/// @param ws The workspace
/// @param nptexts number of plaintexts to allocate
/// @param ptexts array of plaintexts to convert
static ccbfv_plaintext_const_t *plaintext_array_const(cc_ws_t ws, uint32_t nptexts, ccbfv_plaintext_t *ptexts)
{
    ccbfv_plaintext_const_t *ptext_array =
        (ccbfv_plaintext_const_t *)CC_ALLOC_WS(ws, nptexts * ccn_nof_sizeof(ccbfv_plaintext_const_t));
    for (uint32_t ptext_idx = 0; ptext_idx < nptexts; ++ptext_idx) {
        ptext_array[ptext_idx] = ptexts[ptext_idx];
    }
    return ptext_array;
}

static void test_ccbfv_compose_decompose_error(void)
{
    CC_DECL_WORKSPACE_TEST(ws);

    static const struct ccbfv_encrypt_params encrypt_params = { .poly_modulus_degree = 8,
                                                                .plaintext_modulus = 40961,
                                                                .nskip_lsbs = { 0, 0 },
                                                                .nmoduli = 4,
                                                                .moduli = { 65537, 114689, 147457, 163841 } };

    ccbfv_param_ctx_t param_ctx = CCBFV_PARAM_CTX_ALLOC_WS(ws, &encrypt_params);
    is(ccbfv_param_ctx_init_ws(ws, param_ctx, &encrypt_params),
       CCERR_OK,
       "BFV param ctx init (%" PRIu32 " moduli)",
       encrypt_params.nmoduli);
    uint32_t nmoduli = ccbfv_param_ctx_ciphertext_context(param_ctx)->dims.nmoduli;

    ccbfv_ciphertext_coeff_t ctext =
        CCBFV_CIPHERTEXT_COEFF_ALLOC_WS(ws, ccbfv_param_ctx_ciphertext_context(param_ctx), ccbfv_ciphertext_fresh_npolys());
    ccbfv_secret_key_t secret_key = CCBFV_SECRET_KEY_ALLOC_WS(ws, param_ctx);
    is(ccbfv_secret_key_generate_ws(ws, secret_key, param_ctx, global_test_rng),
       CCERR_OK,
       "Secret key generation (%" PRIu32 " moduli)",
       encrypt_params.nmoduli);

    int rv = ccbfv_encrypt_zero_symmetric_coeff_ws(ws, ctext, param_ctx, secret_key, nmoduli, NULL, global_test_rng);
    is(rv, CCERR_OK, "BFV encrypt symmetric no seed (%" PRIu32 " moduli)", encrypt_params.nmoduli);

    uint32_t nptexts = ccbfv_ciphertext_coeff_decompose_nptexts(ctext);
    ccpolyzp_po2cyc_ctx_const_t plain_ctx = ccbfv_param_ctx_plaintext_context(param_ctx);
    ccbfv_plaintext_t *ptext_array = alloc_plaintext_array(ws, nptexts, plain_ctx);

    // ok
    {
        is(ccbfv_ciphertext_coeff_decompose(nptexts, ptext_array, ctext), CCERR_OK, "ccbfv_ciphertext_coeff_decompose");
        is(ccbfv_ciphertext_coeff_compose(ctext, nptexts, plaintext_array_const(ws, nptexts, ptext_array), nmoduli),
           CCERR_OK,
           "ccbfv_ciphertext_coeff_compose error ok");
    }
    // wrong nptexts
    {
        is(ccbfv_ciphertext_coeff_decompose(nptexts, ptext_array, ctext), CCERR_OK, "ccbfv_ciphertext_coeff_decompose");
        is(ccbfv_ciphertext_coeff_compose(ctext, nptexts + 1, plaintext_array_const(ws, nptexts, ptext_array), nmoduli),
           CCERR_PARAMETER,
           "ccbfv_ciphertext_coeff_compose error wrong nptexts");
    }

    CC_FREE_WORKSPACE(ws);
}

static void test_ccbfv_compose_decompose_random(void)
{
    CC_DECL_WORKSPACE_TEST(ws);

    static const struct ccbfv_encrypt_params encrypt_params = { .poly_modulus_degree = 8,
                                                                .plaintext_modulus = 16411,
                                                                .nskip_lsbs = { 0, 0 },
                                                                .nmoduli = 4,
                                                                .moduli = { 65537, 114689, 536690689, 147457 } };
    uint32_t degree = encrypt_params.poly_modulus_degree;

    ccbfv_param_ctx_t param_ctx = CCBFV_PARAM_CTX_ALLOC_WS(ws, &encrypt_params);
    is(ccbfv_param_ctx_init_ws(ws, param_ctx, &encrypt_params),
       CCERR_OK,
       "BFV param ctx init (%" PRIu32 " moduli)",
       encrypt_params.nmoduli);
    uint32_t nmoduli = ccbfv_param_ctx_ciphertext_context(param_ctx)->dims.nmoduli;

    ccbfv_ciphertext_coeff_t ctext =
        CCBFV_CIPHERTEXT_COEFF_ALLOC_WS(ws, ccbfv_param_ctx_ciphertext_context(param_ctx), ccbfv_ciphertext_fresh_npolys());
    ccbfv_secret_key_t secret_key = CCBFV_SECRET_KEY_ALLOC_WS(ws, param_ctx);
    is(ccbfv_secret_key_generate_ws(ws, secret_key, param_ctx, global_test_rng),
       CCERR_OK,
       "Secret key generation (%" PRIu32 " moduli)",
       encrypt_params.nmoduli);

    ccpolyzp_po2cyc_ctx_const_t plain_ctx = ccbfv_param_ctx_plaintext_context(param_ctx);
    ccbfv_plaintext_t ptext = CCBFV_PLAINTEXT_ALLOC_WS(ws, plain_ctx);
    uint64_t values[degree];
    for (uint32_t i = 0; i < degree; ++i) {
        ccrng_uniform(global_test_rng, encrypt_params.plaintext_modulus, values + i);
    }
    is(ccbfv_encode_poly_uint64(ptext, param_ctx, degree, values),
       CCERR_OK,
       "ccbfv_encode_poly_uint64 != CCERR_OK (%" PRIu32 " moduli)",
       nmoduli);

    int rv = ccbfv_encrypt_symmetric_ws(ws, ctext, ptext, param_ctx, secret_key, nmoduli, NULL, global_test_rng);
    is(rv, CCERR_OK, "BFV encrypt symmetric no seed (%" PRIu32 " moduli)", encrypt_params.nmoduli);

    uint32_t nptexts = ccbfv_ciphertext_coeff_decompose_nptexts(ctext);
    ccbfv_plaintext_t *ptext_array = alloc_plaintext_array(ws, nptexts, plain_ctx);
    is(ccbfv_ciphertext_coeff_decompose(nptexts, ptext_array, ctext), CCERR_OK, "ccbfv_ciphertext_coeff_decompose");

    ccbfv_ciphertext_coeff_t ctext_roundtrip =
        CCBFV_CIPHERTEXT_COEFF_ALLOC_WS(ws, ccbfv_param_ctx_ciphertext_context(param_ctx), ccbfv_ciphertext_fresh_npolys());
    ccpolyzp_po2cyc_ctx_const_t ciphertext_ctx =
        ccpolyzp_po2cyc_ctx_chain_context_const(ccbfv_param_ctx_chain_const(param_ctx), nmoduli);
    ccbfv_ciphertext_coeff_init(ctext_roundtrip, param_ctx, ccbfv_ciphertext_fresh_npolys(), ciphertext_ctx);

    ccbfv_plaintext_const_t *const_ptext_array = plaintext_array_const(ws, nptexts, ptext_array);

    is(ccbfv_ciphertext_coeff_compose(ctext_roundtrip, nptexts, const_ptext_array, nmoduli),
       CCERR_OK,
       "ccbfv_ciphertext_coeff_compose");
    is(ccbfv_ciphertext_coeff_eq(ctext_roundtrip, ctext), true, "test_ccbfv_compose_decompose random roundtrip");

    CC_FREE_WORKSPACE(ws);
}

static void test_ccbfv_compose_decompose_kat(void)
{
    CC_DECL_WORKSPACE_TEST(ws);

    static const struct ccbfv_encrypt_params encrypt_params = { .poly_modulus_degree = 8,
                                                                .plaintext_modulus = 16411,
                                                                .nskip_lsbs = { 0, 0 },
                                                                .nmoduli = 4,
                                                                .moduli = { 65537, 114689, 536690689, 147457 } };
    uint32_t degree = encrypt_params.poly_modulus_degree;

    ccbfv_param_ctx_t param_ctx = CCBFV_PARAM_CTX_ALLOC_WS(ws, &encrypt_params);
    is(ccbfv_param_ctx_init_ws(ws, param_ctx, &encrypt_params),
       CCERR_OK,
       "BFV param ctx init (%" PRIu32 " moduli)",
       encrypt_params.nmoduli);
    uint32_t nmoduli = ccbfv_param_ctx_ciphertext_context(param_ctx)->dims.nmoduli;

    // Initialize KAT ciphertext
    ccbfv_ciphertext_coeff_t ctext =
        CCBFV_CIPHERTEXT_COEFF_ALLOC_WS(ws, ccbfv_param_ctx_ciphertext_context(param_ctx), ccbfv_ciphertext_fresh_npolys());
    ccpolyzp_po2cyc_ctx_const_t ciphertext_ctx =
        ccpolyzp_po2cyc_ctx_chain_context_const(ccbfv_param_ctx_chain_const(param_ctx), nmoduli);
    ccbfv_ciphertext_coeff_init(ctext, param_ctx, ccbfv_ciphertext_fresh_npolys(), ciphertext_ctx);

    ccrns_int kat_ctext_coeffs[] = { 64462,     12977,     25976,     14702,     20876,     41379,     10839,     57850,
                                     113776,    66340,     46621,     32795,     9507,      13316,     112741,    77533,
                                     283326724, 245366678, 200646293, 451216684, 143528146, 92219017,  464964407, 189807575,
                                     29621,     14620,     5752,      18504,     64351,     62033,     54757,     57644,
                                     94133,     26356,     96865,     2938,      33680,     77377,     104857,    40119,
                                     442366310, 390758409, 396735561, 106549356, 246623648, 155718891, 393730126, 271728636 };
    for (uint32_t ctext_poly_idx = 0, kat_idx = 0; ctext_poly_idx < ctext->npolys; ++ctext_poly_idx) {
        ccpolyzp_po2cyc_coeff_t ctext_poly = ccbfv_ciphertext_coeff_polynomial(ctext, ctext_poly_idx);
        for (uint32_t rns_idx = 0; rns_idx < nmoduli; ++rns_idx) {
            for (uint32_t coeff_idx = 0; coeff_idx < degree; ++coeff_idx, ++kat_idx) {
                cc_unit *data = CCPOLYZP_PO2CYC_DATA(ctext_poly, rns_idx, coeff_idx);
                ccpolyzp_po2cyc_rns_int_to_units(data, kat_ctext_coeffs[kat_idx]);
            }
        }
    }

    ccrns_int kat_ptext_coeffs[] = {
        15310, 12977, 9592,  14702, 4492,  8611,  10839, 8698,  3,     0,     1,     0,     1,     2,     0,     3,
        15472, 804,   13853, 27,    9507,  13316, 14437, 11997, 6,     4,     2,     2,     0,     0,     6,     4,
        14596, 16278, 7829,  1324,  4306,  9865,  2871,  15319, 908,   14975, 12246, 11156, 8760,  5628,  11995, 11584,
        1,     0,     0,     1,     0,     0,     1,     0,     13237, 14620, 5752,  2120,  15199, 12881, 5605,  8492,
        1,     0,     0,     1,     3,     3,     3,     3,     12213, 9972,  14945, 2938,  912,   11841, 6553,  7351,
        5,     1,     5,     0,     2,     4,     6,     2,     14694, 9,     13385, 4204,  11680, 5355,  6222,  16380,
        10615, 7466,  7830,  6503,  15052, 9504,  7647,  200,   1,     1,     1,     0,     0,     0,     1,     1,
    };

    uint32_t nptexts = ccbfv_ciphertext_coeff_decompose_nptexts(ctext);
    ccpolyzp_po2cyc_ctx_const_t plain_ctx = ccbfv_param_ctx_plaintext_context(param_ctx);
    ccbfv_plaintext_t *ptext_array = alloc_plaintext_array(ws, nptexts, plain_ctx);

    is(ccbfv_ciphertext_coeff_decompose(nptexts, ptext_array, ctext), CCERR_OK, "ccbfv_ciphertext_coeff_decompose");
    is(nptexts, CC_ARRAY_LEN(kat_ptext_coeffs) / degree, "test_ccbfv_decompose_kat wrong nptexts");
    // Check decomposed plaintexts
    {
        bool ptext_array_eq = true;
        for (uint32_t ptext_poly_idx = 0, kat_idx = 0; ptext_poly_idx < nptexts; ++ptext_poly_idx) {
            ccpolyzp_po2cyc_coeff_const_t ptext_poly = ccbfv_plaintext_polynomial_const(ptext_array[ptext_poly_idx]);
            for (uint32_t coeff_idx = 0; coeff_idx < degree; ++coeff_idx, ++kat_idx) {
                ccrns_int ptext_coeff = ccpolyzp_po2cyc_data_int((ccpolyzp_po2cyc_const_t)ptext_poly, 0, coeff_idx);
                ptext_array_eq &= (ptext_coeff == kat_ptext_coeffs[kat_idx]);
            }
            is(ptext_array_eq, true, "test_ccbfv_decompose_kat incorrect");
        }
    }

    // Check roundtrip
    ccbfv_ciphertext_coeff_t ctext_roundtrip =
        CCBFV_CIPHERTEXT_COEFF_ALLOC_WS(ws, ccbfv_param_ctx_ciphertext_context(param_ctx), ccbfv_ciphertext_fresh_npolys());
    ccbfv_ciphertext_coeff_init(ctext_roundtrip, param_ctx, ccbfv_ciphertext_fresh_npolys(), ciphertext_ctx);
    is(ccbfv_ciphertext_coeff_compose(ctext_roundtrip, nptexts, plaintext_array_const(ws, nptexts, ptext_array), nmoduli),
       CCERR_OK,
       "ccbfv_ciphertext_coeff_compose");

    is(ccbfv_ciphertext_coeff_eq(ctext_roundtrip, ctext), true, "test_ccbfv_decompose_kat kat roundtrip");

    CC_FREE_WORKSPACE(ws);
}

static void ciphertext_clear_lsbs(ccbfv_ciphertext_coeff_t ctext, const uint32_t *skip_lsbs)
{
    const ccpolyzp_po2cyc_dims_const_t dims = &ccbfv_ciphertext_coeff_ctx(ctext)->dims;
    const uint32_t degree = dims->degree;
    const uint32_t nmoduli = dims->nmoduli;
    for (uint32_t poly_idx = 0; poly_idx < ctext->npolys; ++poly_idx) {
        for (uint32_t rns_idx = 0; rns_idx < nmoduli; ++rns_idx) {
            const ccrns_int skip_lsb = (ccrns_int)skip_lsbs[poly_idx * nmoduli + rns_idx];
            const ccrns_int mask = ~((1 << skip_lsb) - 1);
            ccpolyzp_po2cyc_coeff_t ctext_poly = ccbfv_ciphertext_coeff_polynomial(ctext, poly_idx);
            for (uint32_t coeff_idx = 0; coeff_idx < degree; ++coeff_idx) {
                ccrns_int ctext_coeff = ccpolyzp_po2cyc_coeff_data_int(ctext_poly, rns_idx, coeff_idx);
                ctext_coeff &= mask;
                cc_unit *ctext_data = CCPOLYZP_PO2CYC_DATA(ctext_poly, rns_idx, coeff_idx);
                ccpolyzp_po2cyc_rns_int_to_units(ctext_data, ctext_coeff);
            }
        }
    }
}

static void test_ccbfv_compose_decompose_skip_lsbs_random(void)
{
    CC_DECL_WORKSPACE_TEST(ws);

    static const struct ccbfv_encrypt_params encrypt_params = {
        .poly_modulus_degree = 8,
        .plaintext_modulus = (1 << 4) + 1,
        .nskip_lsbs = { 0, 0 },
        .nmoduli = 5,
        .moduli = { (1 << 17) + 177, (1 << 17) + 225, (1 << 17) + 369, (1 << 17) + 417, (1 << 17) + 545 }
    };
    uint32_t degree = encrypt_params.poly_modulus_degree;
    uint32_t skip_lsbs[2];
    for (uint32_t i = 0; i < 2; ++i) {
        uint64_t rand;
        ccrng_uniform(global_test_rng, ccpolyzp_po2cyc_log2_uint64(encrypt_params.moduli[0]), &rand);
        skip_lsbs[i] = (uint32_t)rand;
    }

    ccbfv_param_ctx_t param_ctx = CCBFV_PARAM_CTX_ALLOC_WS(ws, &encrypt_params);
    is(ccbfv_param_ctx_init_ws(ws, param_ctx, &encrypt_params),
       CCERR_OK,
       "BFV param ctx init (%" PRIu32 " moduli)",
       encrypt_params.nmoduli);
    uint32_t nmoduli = ccbfv_param_ctx_ciphertext_context(param_ctx)->dims.nmoduli;

    ccbfv_ciphertext_coeff_t ctext =
        CCBFV_CIPHERTEXT_COEFF_ALLOC_WS(ws, ccbfv_param_ctx_ciphertext_context(param_ctx), ccbfv_ciphertext_fresh_npolys());
    ccbfv_secret_key_t secret_key = CCBFV_SECRET_KEY_ALLOC_WS(ws, param_ctx);
    is(ccbfv_secret_key_generate_ws(ws, secret_key, param_ctx, global_test_rng),
       CCERR_OK,
       "Secret key generation (%" PRIu32 " moduli)",
       encrypt_params.nmoduli);

    ccpolyzp_po2cyc_ctx_const_t plain_ctx = ccbfv_param_ctx_plaintext_context(param_ctx);
    ccbfv_plaintext_t ptext = CCBFV_PLAINTEXT_ALLOC_WS(ws, plain_ctx);
    uint64_t values[degree];
    for (uint32_t i = 0; i < degree; ++i) {
        ccrng_uniform(global_test_rng, encrypt_params.plaintext_modulus, values + i);
    }
    is(ccbfv_encode_poly_uint64(ptext, param_ctx, degree, values),
       CCERR_OK,
       "ccbfv_encode_poly_uint64 != CCERR_OK (%" PRIu32 " moduli)",
       nmoduli);

    int rv = ccbfv_encrypt_symmetric_ws(ws, ctext, ptext, param_ctx, secret_key, nmoduli, NULL, global_test_rng);
    is(rv, CCERR_OK, "BFV encrypt symmetric no seed (%" PRIu32 " moduli)", encrypt_params.nmoduli);

    is(ccbfv_ciphertext_mod_switch_down_to_single_ws(ws, ctext), CCERR_OK, "ccbfv_ciphertext_mod_switch_down_to_single_ws");
    nmoduli = 1;
    uint32_t nptexts = ccbfv_ciphertext_coeff_decompose_nptexts_skip_lsbs(ctext, skip_lsbs);
    ccbfv_plaintext_t *ptext_array = alloc_plaintext_array(ws, nptexts, plain_ctx);
    is(ccbfv_ciphertext_coeff_decompose_skip_lsbs(nptexts, ptext_array, ctext, skip_lsbs),
       CCERR_OK,
       "ccbfv_ciphertext_coeff_decompose");

    ccbfv_ciphertext_coeff_t ctext_roundtrip =
        CCBFV_CIPHERTEXT_COEFF_ALLOC_WS(ws, ccbfv_param_ctx_ciphertext_context(param_ctx), ccbfv_ciphertext_fresh_npolys());
    ccpolyzp_po2cyc_ctx_const_t ciphertext_ctx =
        ccpolyzp_po2cyc_ctx_chain_context_const(ccbfv_param_ctx_chain_const(param_ctx), nmoduli);
    ccbfv_ciphertext_coeff_init(ctext_roundtrip, param_ctx, ccbfv_ciphertext_fresh_npolys(), ciphertext_ctx);

    ccbfv_plaintext_const_t *const_ptext_array = plaintext_array_const(ws, nptexts, ptext_array);

    is(ccbfv_ciphertext_coeff_compose_skip_lsbs(ctext_roundtrip, nptexts, const_ptext_array, nmoduli, skip_lsbs),
       CCERR_OK,
       "ccbfv_ciphertext_coeff_compose");
    ciphertext_clear_lsbs(ctext, skip_lsbs);
    is(ccbfv_ciphertext_coeff_eq(ctext_roundtrip, ctext), true, "test_ccbfv_compose_decompose random roundtrip");

    CC_FREE_WORKSPACE(ws);
}

void test_ccbfv_compose_decompose(void)
{
    test_ccbfv_compose_decompose_error();
    test_ccbfv_compose_decompose_kat();
    test_ccbfv_compose_decompose_random();
    test_ccbfv_compose_decompose_skip_lsbs_random();
}

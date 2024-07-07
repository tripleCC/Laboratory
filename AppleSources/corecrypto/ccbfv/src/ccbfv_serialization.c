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

#include "cc_internal.h"
#include "ccbfv_serialization.h"
#include "ccbfv_util.h"
#include "ccpolyzp_po2cyc_serialization.h"

size_t ccbfv_serialize_ciphertext_coeff_nbytes(ccbfv_ciphertext_coeff_const_t ctext, const uint32_t *nskip_lsbs)
{
    CC_ENSURE_DIT_ENABLED

    uint32_t npolys = ctext->npolys;
    ccpolyzp_po2cyc_ctx_const_t ctx = ccbfv_ciphertext_coeff_ctx(ctext);

    size_t rv = 2; // Two bytes used to serialize `npolys`.
    for (uint32_t poly_idx = 0; poly_idx < npolys; ++poly_idx) {
        rv += ccpolyzp_po2cyc_serialize_poly_nbytes(ctx, nskip_lsbs ? nskip_lsbs[poly_idx] : 0);
    }
    return rv;
}

size_t ccbfv_serialize_ciphertext_eval_nbytes(ccbfv_ciphertext_eval_const_t ctext)
{
    CC_ENSURE_DIT_ENABLED

    return ccbfv_serialize_ciphertext_coeff_nbytes((ccbfv_ciphertext_coeff_const_t)ctext, NULL);
}

size_t ccbfv_serialize_seeded_ciphertext_coeff_nbytes(ccbfv_ciphertext_coeff_const_t ctext)
{
    CC_ENSURE_DIT_ENABLED

    ccpolyzp_po2cyc_ctx_const_t ctx = ccbfv_ciphertext_coeff_ctx(ctext);
    return ccpolyzp_po2cyc_serialize_poly_nbytes(ctx, 0);
}

size_t ccbfv_serialize_seeded_ciphertext_eval_nbytes(ccbfv_ciphertext_eval_const_t ctext)
{
    CC_ENSURE_DIT_ENABLED

    return ccbfv_serialize_seeded_ciphertext_coeff_nbytes((ccbfv_ciphertext_coeff_const_t)ctext);
}

void ccbfv_serialize_ciphertext_coeff_max_nskip_lsbs(uint32_t *nskip_lsbs, ccbfv_ciphertext_coeff_const_t ctext)
{
    CC_ENSURE_DIT_ENABLED

    for (uint32_t i = 0; i < ctext->npolys; ++i) {
        nskip_lsbs[i] = 0;
    }
    if (ctext->npolys == ccbfv_ciphertext_fresh_npolys()) {
        ccbfv_encrypt_params_const_t encrypt_params = ccbfv_param_ctx_encrypt_params_const(ctext->param_ctx);
        for (uint32_t i = 0; i < CC_ARRAY_LEN(encrypt_params->nskip_lsbs); ++i) {
            nskip_lsbs[i] = encrypt_params->nskip_lsbs[i];
        }
    }
}

int ccbfv_serialize_ciphertext_coeff_ws(cc_ws_t ws,
                                        size_t nbytes,
                                        uint8_t *cc_counted_by(nbytes) bytes,
                                        ccbfv_ciphertext_coeff_const_t ctext,
                                        const uint32_t *nskip_lsbs)
{
    int rv = CCERR_OK;
    cc_require_or_return(nbytes == ccbfv_serialize_ciphertext_coeff_nbytes(ctext, nskip_lsbs), CCERR_PARAMETER);
    ccbfv_ciphertext_coeff_const_t ctext_coeff = (ccbfv_ciphertext_coeff_const_t)ctext;
    cc_require_or_return(ctext_coeff->npolys <= UINT16_MAX, CCERR_PARAMETER);

    uint32_t npolys = ctext->npolys;
    if (nskip_lsbs) {
        cc_require_or_return(npolys == ccbfv_ciphertext_fresh_npolys(), CCERR_PARAMETER);
        uint32_t max_nskip_lsbs[CCBFV_CIPHERTEXT_FRESH_NPOLYS];
        ccbfv_serialize_ciphertext_coeff_max_nskip_lsbs(max_nskip_lsbs, ctext);
        for (uint32_t i = 0; i < npolys; ++i) {
            cc_require_or_return(nskip_lsbs[i] <= max_nskip_lsbs[i], CCERR_PARAMETER);
        }
    }

    ccpolyzp_po2cyc_ctx_const_t ctx = ccbfv_ciphertext_coeff_ctx(ctext);

    // write number of polys as little endian u16
    bytes[0] = npolys & 0xff;
    bytes[1] = (npolys >> 8) & 0xff;
    bytes += 2;

    // write each poly
    for (uint32_t poly_idx = 0; poly_idx < npolys; ++poly_idx) {
        ccpolyzp_po2cyc_const_t poly = (ccpolyzp_po2cyc_const_t)ccbfv_ciphertext_coeff_polynomial_const(ctext, poly_idx);
        uint32_t skip_lsbs = nskip_lsbs ? nskip_lsbs[poly_idx] : 0;
        const size_t npoly_bytes = ccpolyzp_po2cyc_serialize_poly_nbytes(ctx, skip_lsbs);
        rv = ccpolyzp_po2cyc_serialize_poly_ws(ws, npoly_bytes, bytes, skip_lsbs, poly);
        cc_require_or_return(rv == CCERR_OK, rv);
        bytes += npoly_bytes;
    }

    return rv;
}

int ccbfv_serialize_ciphertext_eval_ws(cc_ws_t ws,
                                       size_t nbytes,
                                       uint8_t *cc_counted_by(nbytes) bytes,
                                       ccbfv_ciphertext_eval_const_t ctext)
{
    return ccbfv_serialize_ciphertext_coeff_ws(ws, nbytes, bytes, (ccbfv_ciphertext_coeff_const_t)ctext, NULL);
}

int ccbfv_serialize_ciphertext_coeff(size_t nbytes,
                                     uint8_t *cc_counted_by(nbytes) bytes,
                                     ccbfv_ciphertext_coeff_const_t ctext,
                                     const uint32_t *nskip_lsbs)
{
    CC_ENSURE_DIT_ENABLED

    CC_DECL_WORKSPACE_OR_FAIL(ws,
                              CCBFV_SERIALIZE_CIPHERTEXT_COEFF_WORKSPACE_N(ccbfv_param_ctx_polynomial_degree(ctext->param_ctx)));
    int rv = ccbfv_serialize_ciphertext_coeff_ws(ws, nbytes, bytes, ctext, nskip_lsbs);
    CC_FREE_WORKSPACE(ws);
    return rv;
}

int ccbfv_serialize_ciphertext_eval(size_t nbytes, uint8_t *cc_counted_by(nbytes) bytes, ccbfv_ciphertext_eval_const_t ctext)
{
    CC_ENSURE_DIT_ENABLED

    CC_DECL_WORKSPACE_OR_FAIL(ws,
                              CCBFV_SERIALIZE_CIPHERTEXT_EVAL_WORKSPACE_N(ccbfv_param_ctx_polynomial_degree(ctext->param_ctx)));
    int rv = ccbfv_serialize_ciphertext_eval_ws(ws, nbytes, bytes, ctext);
    CC_FREE_WORKSPACE(ws);
    return rv;
}

int ccbfv_deserialize_ciphertext_coeff_ws(cc_ws_t ws,
                                          ccbfv_ciphertext_coeff_t ctext,
                                          size_t nbytes,
                                          const uint8_t *cc_counted_by(nbytes) bytes,
                                          const uint32_t *nskip_lsbs)
{
    int rv = CCERR_OK;

    ccpolyzp_po2cyc_ctx_const_t ctx = ccbfv_ciphertext_coeff_ctx(ctext);
    cc_require_or_return(nbytes == ccbfv_serialize_ciphertext_coeff_nbytes(ctext, nskip_lsbs), CCERR_PARAMETER);

    // read number of polys as little endian u16
    uint16_t read_npolys = (uint16_t)(bytes[0] | (bytes[1] << 8));
    bytes += 2;
    cc_require_or_return(read_npolys == ctext->npolys, CCERR_PARAMETER);

    // read each poly
    for (uint32_t poly_idx = 0; poly_idx < read_npolys; ++poly_idx) {
        uint32_t skip_bits = nskip_lsbs ? nskip_lsbs[poly_idx] : 0;
        const size_t poly_nbytes = ccpolyzp_po2cyc_serialize_poly_nbytes(ctx, skip_bits);
        ccpolyzp_po2cyc_t poly = (ccpolyzp_po2cyc_t)ccbfv_ciphertext_coeff_polynomial(ctext, poly_idx);
        rv = ccpolyzp_po2cyc_deserialize_poly_ws(ws, poly, skip_bits, poly_nbytes, bytes);

        cc_require_or_return(rv == CCERR_OK, rv);
        bytes += poly_nbytes;
    }

    return rv;
}

int ccbfv_deserialize_ciphertext_eval_ws(cc_ws_t ws,
                                         ccbfv_ciphertext_eval_t ctext,
                                         size_t nbytes,
                                         const uint8_t *cc_counted_by(nbytes) bytes)
{
    return ccbfv_deserialize_ciphertext_coeff_ws(ws, (ccbfv_ciphertext_coeff_t)ctext, nbytes, bytes, NULL);
}

int ccbfv_deserialize_ciphertext_coeff(ccbfv_ciphertext_coeff_t ctext,
                                       size_t nbytes,
                                       const uint8_t *cc_counted_by(nbytes) bytes,
                                       ccbfv_param_ctx_const_t param_ctx,
                                       uint32_t nmoduli,
                                       uint32_t npolys,
                                       const uint32_t *nskip_lsbs)
{
    CC_ENSURE_DIT_ENABLED

    CC_DECL_WORKSPACE_OR_FAIL(ws, CCBFV_DESERIALIZE_CIPHERTEXT_COEFF_WORKSPACE_N(ccbfv_param_ctx_polynomial_degree(param_ctx)));
    ccpolyzp_po2cyc_ctx_const_t cipher_ctx = ccbfv_param_ctx_ciphertext_context_specific(param_ctx, nmoduli);
    ccbfv_ciphertext_coeff_init(ctext, param_ctx, npolys, cipher_ctx);
    int rv = ccbfv_deserialize_ciphertext_coeff_ws(ws, ctext, nbytes, bytes, nskip_lsbs);
    CC_FREE_WORKSPACE(ws);
    return rv;
}

int ccbfv_deserialize_ciphertext_eval(ccbfv_ciphertext_eval_t ctext,
                                      size_t nbytes,
                                      const uint8_t *cc_counted_by(nbytes) bytes,
                                      ccbfv_param_ctx_const_t param_ctx,
                                      uint32_t nmoduli,
                                      uint32_t npolys)
{
    CC_ENSURE_DIT_ENABLED

    CC_DECL_WORKSPACE_OR_FAIL(ws, CCBFV_DESERIALIZE_CIPHERTEXT_EVAL_WORKSPACE_N(ccbfv_param_ctx_polynomial_degree(param_ctx)));
    ccpolyzp_po2cyc_ctx_const_t cipher_ctx = ccbfv_param_ctx_ciphertext_context_specific(param_ctx, nmoduli);
    ccbfv_ciphertext_eval_init(ctext, param_ctx, npolys, cipher_ctx);
    int rv = ccbfv_deserialize_ciphertext_eval_ws(ws, ctext, nbytes, bytes);
    CC_FREE_WORKSPACE(ws);
    return rv;
}

int ccbfv_serialize_seeded_ciphertext_coeff_ws(cc_ws_t ws,
                                               size_t nbytes,
                                               uint8_t *cc_counted_by(nbytes) bytes,
                                               ccbfv_ciphertext_coeff_const_t ctext)
{
    ccpolyzp_po2cyc_const_t poly = (ccpolyzp_po2cyc_const_t)ccbfv_ciphertext_coeff_polynomial_const(ctext, 0);
    return ccpolyzp_po2cyc_serialize_poly_ws(ws, nbytes, bytes, 0, poly);
}

int ccbfv_serialize_seeded_ciphertext_eval_ws(cc_ws_t ws,
                                              size_t nbytes,
                                              uint8_t *cc_counted_by(nbytes) bytes,
                                              ccbfv_ciphertext_eval_const_t ctext)
{
    return ccbfv_serialize_seeded_ciphertext_coeff_ws(ws, nbytes, bytes, (ccbfv_ciphertext_coeff_const_t)ctext);
}

int ccbfv_serialize_seeded_ciphertext_coeff(size_t nbytes,
                                            uint8_t *cc_counted_by(nbytes) bytes,
                                            ccbfv_ciphertext_coeff_const_t ctext)
{
    CC_ENSURE_DIT_ENABLED

    CC_DECL_WORKSPACE_OR_FAIL(
        ws, CCBFV_SERIALIZE_SEEDED_CIPHERTEXT_COEFF_WORKSPACE_N(ccbfv_param_ctx_polynomial_degree(ctext->param_ctx)));
    int rv = ccbfv_serialize_seeded_ciphertext_coeff_ws(ws, nbytes, bytes, ctext);
    CC_FREE_WORKSPACE(ws);
    return rv;
}

int ccbfv_serialize_seeded_ciphertext_eval(size_t nbytes,
                                           uint8_t *cc_counted_by(nbytes) bytes,
                                           ccbfv_ciphertext_eval_const_t ctext)
{
    CC_ENSURE_DIT_ENABLED

    CC_DECL_WORKSPACE_OR_FAIL(
        ws, CCBFV_SERIALIZE_SEEDED_CIPHERTEXT_EVAL_WORKSPACE_N(ccbfv_param_ctx_polynomial_degree(ctext->param_ctx)));
    int rv = ccbfv_serialize_seeded_ciphertext_eval_ws(ws, nbytes, bytes, ctext);
    CC_FREE_WORKSPACE(ws);
    return rv;
}

int ccbfv_deserialize_seeded_ciphertext_coeff_ws(cc_ws_t ws,
                                                 ccbfv_ciphertext_coeff_t ctext,
                                                 size_t nbytes,
                                                 const uint8_t *cc_counted_by(nbytes) bytes,
                                                 ccbfv_rng_seed_const_t seed)
{
    ccbfv_ciphertext_eval_t ctext_eval = (ccbfv_ciphertext_eval_t)ctext;
    int rv = ccbfv_deserialize_seeded_ciphertext_eval_ws(ws, ctext_eval, nbytes, bytes, seed);
    cc_require(rv == CCERR_OK, errOut);
    rv = ccpolyzp_po2cyc_inv_ntt(ccbfv_ciphertext_eval_polynomial(ctext_eval, 1));
    cc_require(rv == CCERR_OK, errOut);

errOut:
    return rv;
}

cc_size CCBFV_DESERIALIZE_SEEDED_CIPHERTEXT_EVAL_WORKSPACE_N(cc_size degree)
{
    return CC_MAX_EVAL(CCPOLYZP_PO2CYC_DESERIALIZE_POLY_WORKSPACE_N(degree),
                       CCPOLYZP_PO2CYC_RANDOM_UNIFORM_WORKSPACE_N(degree) +
                           cc_ceiling(sizeof_struct_ccpolyzp_po2cyc_block_rng_state(), sizeof_cc_unit()));
}

int ccbfv_deserialize_seeded_ciphertext_eval_ws(cc_ws_t ws,
                                                ccbfv_ciphertext_eval_t ctext,
                                                size_t nbytes,
                                                const uint8_t *cc_counted_by(nbytes) bytes,
                                                ccbfv_rng_seed_const_t seed)
{
    cc_require_or_return(ctext->npolys == ccbfv_ciphertext_fresh_npolys(), CCERR_PARAMETER);
    ccpolyzp_po2cyc_ctx_const_t ctx = ccbfv_ciphertext_eval_ctx(ctext);
    const size_t bytes_per_poly = ccpolyzp_po2cyc_serialize_poly_nbytes(ctx, 0);
    cc_require_or_return(bytes_per_poly == nbytes, CCERR_PARAMETER);

    CC_DECL_BP_WS(ws, bp);

    // deserialize first polynomial
    ccpolyzp_po2cyc_t c0 = (ccpolyzp_po2cyc_t)ccbfv_ciphertext_eval_polynomial(ctext, 0);
    int rv = ccpolyzp_po2cyc_deserialize_poly_ws(ws, c0, 0, nbytes, bytes);
    cc_require(rv == CCERR_OK, errOut);

    // recreate the second polynomial from seed
    ccpolyzp_po2cyc_block_rng_state_t block_rng = CCPOLYZP_PO2CYC_BLOCK_RNG_STATE_ALLOC_WS(ws);
    rv = ccpolyzp_po2cyc_block_rng_init(block_rng, (ccpolyzp_po2cyc_block_rng_seed_const_t)seed);
    cc_require(rv == CCERR_OK, errOut);
    ccpolyzp_po2cyc_t a = (ccpolyzp_po2cyc_t)ccbfv_ciphertext_eval_polynomial(ctext, 1);
    rv = ccpolyzp_po2cyc_random_uniform_ws(ws, a, (struct ccrng_state *)block_rng);
    cc_require(rv == CCERR_OK, errOut);

errOut:
    CC_FREE_BP_WS(ws, bp);
    return rv;
}

int ccbfv_deserialize_seeded_ciphertext_coeff(ccbfv_ciphertext_coeff_t ctext,
                                              size_t nbytes,
                                              const uint8_t *cc_counted_by(nbytes) bytes,
                                              ccbfv_rng_seed_const_t seed,
                                              ccbfv_param_ctx_const_t param_ctx,
                                              uint32_t nmoduli)
{
    CC_ENSURE_DIT_ENABLED

    CC_DECL_WORKSPACE_OR_FAIL(
        ws, CCBFV_DESERIALIZE_SEEDED_CIPHERTEXT_COEFF_WORKSPACE_N(ccbfv_param_ctx_polynomial_degree(param_ctx)));
    ccpolyzp_po2cyc_ctx_const_t cipher_ctx = ccbfv_param_ctx_ciphertext_context_specific(param_ctx, nmoduli);
    ccbfv_ciphertext_coeff_init(ctext, param_ctx, ccbfv_ciphertext_fresh_npolys(), cipher_ctx);
    int rv = ccbfv_deserialize_seeded_ciphertext_coeff_ws(ws, ctext, nbytes, bytes, seed);
    CC_FREE_WORKSPACE(ws);
    return rv;
}

int ccbfv_deserialize_seeded_ciphertext_eval(ccbfv_ciphertext_eval_t ctext,
                                             size_t nbytes,
                                             const uint8_t *cc_counted_by(nbytes) bytes,
                                             ccbfv_rng_seed_const_t seed,
                                             ccbfv_param_ctx_const_t param_ctx,
                                             uint32_t nmoduli)
{
    CC_ENSURE_DIT_ENABLED

    CC_DECL_WORKSPACE_OR_FAIL(ws,
                              CCBFV_DESERIALIZE_SEEDED_CIPHERTEXT_EVAL_WORKSPACE_N(ccbfv_param_ctx_polynomial_degree(param_ctx)));
    ccpolyzp_po2cyc_ctx_const_t cipher_ctx = ccbfv_param_ctx_ciphertext_context_specific(param_ctx, nmoduli);
    ccbfv_ciphertext_eval_init(ctext, param_ctx, ccbfv_ciphertext_fresh_npolys(), cipher_ctx);
    int rv = ccbfv_deserialize_seeded_ciphertext_eval_ws(ws, ctext, nbytes, bytes, seed);
    CC_FREE_WORKSPACE(ws);
    return rv;
}

int ccbfv_bytes_to_coeffs(size_t ncoeffs,
                          uint64_t *cc_counted_by(ncoeffs) coeffs,
                          size_t nbytes,
                          const uint8_t *cc_counted_by(nbytes) bytes,
                          size_t bits_per_coeff)
{
    CC_ENSURE_DIT_ENABLED

    return ccpolyzp_po2cyc_bytes_to_coeffs(ncoeffs, coeffs, nbytes, bytes, bits_per_coeff, 0);
}

int ccbfv_coeffs_to_bytes(size_t nbytes,
                          uint8_t *cc_counted_by(nbytes) bytes,
                          size_t ncoeffs,
                          const uint64_t *cc_counted_by(ncoeffs) coeffs,
                          size_t bits_per_coeff)
{
    CC_ENSURE_DIT_ENABLED

    return ccpolyzp_po2cyc_coeffs_to_bytes(nbytes, bytes, ncoeffs, coeffs, bits_per_coeff, 0);
}

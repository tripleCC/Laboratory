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

#include "ccpolyzp_po2cyc_random.h"
#include <corecrypto/cc_memory.h>
#include <corecrypto/ccdrbg.h>
#include <corecrypto/ccaes.h>

// MARK: - Block RNG

/// block rng generate function
///
/// This will copy bytes from the internal buffer and when the buffer runs empty, uses the drbg to refill the buffer.
static int generate(struct ccrng_state *rng, size_t outlen, void *out)
{
    int rv = CCERR_OK;
    struct ccpolyzp_po2cyc_block_rng_state *block_rng = (struct ccpolyzp_po2cyc_block_rng_state *)rng;
    size_t written = 0;
    while (written < outlen) {
        const size_t remaining = outlen - written;
        if (block_rng->index + remaining < CCPOLYZP_PO2CYC_RANDOM_BUFFER) {
            cc_memcpy(out, block_rng->buffer + block_rng->index, remaining);
            block_rng->index += remaining;
            written += remaining;
        } else if (block_rng->index < CCPOLYZP_PO2CYC_RANDOM_BUFFER) {
            size_t remaining_in_buffer = CCPOLYZP_PO2CYC_RANDOM_BUFFER - block_rng->index;
            cc_memcpy(out, block_rng->buffer + block_rng->index, remaining_in_buffer);
            out = ((uint8_t *)out) + remaining_in_buffer;
            written += remaining_in_buffer;
            block_rng->index += remaining_in_buffer;
        } else {
            rv = block_rng->info.generate(
                (struct ccdrbg_state *)&block_rng->drbg_state, CCPOLYZP_PO2CYC_RANDOM_BUFFER, block_rng->buffer, 0, NULL);
            cc_require(rv == CCERR_OK, errOut);
            block_rng->index = 0;
        }
    }

errOut:
    return rv;
}

/// initialize the block rng
int ccpolyzp_po2cyc_block_rng_init(ccpolyzp_po2cyc_block_rng_state_t rng, ccpolyzp_po2cyc_block_rng_seed_const_t seed)
{
    rng->generate = generate;
    rng->custom.ctr_info = ccaes_ctr_crypt_mode();
    rng->custom.keylen = 16;
    rng->custom.strictFIPS = 1;
    rng->custom.df_ctx = NULL;

    ccdrbg_factory_nistctr(&rng->info, &rng->custom);
    cc_require_or_return(rng->info.size <= CCPOLYZP_PO2CYC_RANDOM_DRBG_MAX_STATE_SIZE, CCERR_INTERNAL);
    rng->index = CCPOLYZP_PO2CYC_RANDOM_BUFFER;
    return rng->info.init(
        &rng->info, (struct ccdrbg_state *)&rng->drbg_state, CCPOLYZP_PO2CYC_RANDOM_RNG_SEED_SIZE, seed->data, 0, NULL, 0, NULL);
}

CC_PURE size_t sizeof_struct_ccpolyzp_po2cyc_block_rng_state(void)
{
    return sizeof(struct ccpolyzp_po2cyc_block_rng_state);
}

// MARK: - ccpolyzp_po2cyc randomization

/// Maximum number of coefficients to generate random values for at a time
#define CCPOLYZP_PO2CYC_RANDOM_MAX_RNG_NCOEFFS 1024

cc_size CCPOLYZP_PO2CYC_RANDOM_UNIFORM_WORKSPACE_N(cc_size degree)
{
    cc_size rng_ncoeffs = CC_MIN_EVAL(CCPOLYZP_PO2CYC_RANDOM_MAX_RNG_NCOEFFS, degree);
    return ccn_nof(128 * rng_ncoeffs);
}

int ccpolyzp_po2cyc_random_uniform_ws(cc_ws_t ws, ccpolyzp_po2cyc_t r, struct ccrng_state *rng)
{
    int rv = CCERR_OK;
    ccpolyzp_po2cyc_coeff_t x = (ccpolyzp_po2cyc_coeff_t)r;
    const uint32_t degree = x->context->dims.degree;
    const uint32_t nmoduli = x->context->dims.nmoduli;

    CC_DECL_BP_WS(ws, bp);
    cc_size rng_ncoeffs = CC_MIN_EVAL(CCPOLYZP_PO2CYC_RANDOM_MAX_RNG_NCOEFFS, degree);
    cc_size rng_nbits_per_coeff = 128;
    cc_size rng_nbytes = (rng_nbits_per_coeff / 8) * rng_ncoeffs;
    cc_unit *random_buffer = (cc_unit *)CC_ALLOC_WS(ws, ccn_nof(rng_nbits_per_coeff * rng_ncoeffs));

    // we can uniformly sample each RNS component
    for (uint32_t rns_idx = 0; rns_idx < nmoduli; ++rns_idx) {
        ccrns_modulus_const_t modulus = ccpolyzp_po2cyc_ctx_ccrns_modulus(x->context, rns_idx);
        for (uint32_t coeff_idx = 0; coeff_idx < degree; ++coeff_idx) {
            uint32_t coeff_rng_offset = coeff_idx % rng_ncoeffs;
            if (coeff_rng_offset == 0) {
                cc_require((rv = ccrng_generate(rng, rng_nbytes, random_buffer)) == CCERR_OK, errOut);
            }
            cc_unit *coeff = &(random_buffer[coeff_rng_offset * ccn_nof(rng_nbits_per_coeff)]);
            ccrns_int rns_coeff = ccpolyzp_po2cyc_scalar_mod2(coeff, modulus);
            ccpolyzp_po2cyc_rns_int_to_units(CCPOLYZP_PO2CYC_DATA(r, rns_idx, coeff_idx), rns_coeff);
        }
    }
    CC_FREE_BP_WS(ws, bp);

errOut:
    return rv;
}

// ccpolyzp_po2cyc_random_ternary_ws samples 96 bits = 12 bytes, then does modular reduction
#define CCPOLYZP_PO2CYC_RANDOM_TERNARY_RNG_NBITS_PER_COEFF 96

cc_size CCPOLYZP_PO2CYC_RANDOM_TERNARY_WORKSPACE_N(cc_size degree)
{
    cc_size rng_ncoeffs = CC_MIN_EVAL(CCPOLYZP_PO2CYC_RANDOM_MAX_RNG_NCOEFFS, degree);
    cc_size rng_buffer_size = ccn_nof(CCPOLYZP_PO2CYC_RANDOM_TERNARY_RNG_NBITS_PER_COEFF * rng_ncoeffs);
    return rng_buffer_size + CCRNS_MODULUS_INIT_WORKSPACE_N(CCPOLYZP_PO2CYC_NUNITS_PER_COEFF);
}

int ccpolyzp_po2cyc_random_ternary_ws(cc_ws_t ws, ccpolyzp_po2cyc_t r, struct ccrng_state *rng)
{
    int rv = CCERR_OK;
    ccpolyzp_po2cyc_coeff_t x = (ccpolyzp_po2cyc_coeff_t)r;
    const uint32_t degree = x->context->dims.degree;
    const uint32_t nmoduli = x->context->dims.nmoduli;

    CC_DECL_BP_WS(ws, bp);
    cc_size rng_ncoeffs = CC_MIN_EVAL(CCPOLYZP_PO2CYC_RANDOM_MAX_RNG_NCOEFFS, degree);
    uint8_t *random_bytes = (uint8_t *)CC_ALLOC_WS(ws, ccn_nof(CCPOLYZP_PO2CYC_RANDOM_TERNARY_RNG_NBITS_PER_COEFF * rng_ncoeffs));

    static const uint32_t rng_nbytes_per_coeff = CCPOLYZP_PO2CYC_RANDOM_TERNARY_RNG_NBITS_PER_COEFF / 8;
    cc_size rng_nbytes = rng_nbytes_per_coeff * rng_ncoeffs;
    // ccpolyzp_po2cyc_scalar_mod2 requires 2 * CCRNS_INT_NBITS
    static const uint32_t rng_nunits_per_coeff = ccn_nof(2 * CCRNS_INT_NBITS);
    cc_static_assert(
        2 * CCRNS_INT_NBITS >= CCPOLYZP_PO2CYC_RANDOM_TERNARY_RNG_NBITS_PER_COEFF,
        "ccpolyzp_po2cyc_random_ternary_ws requires 2 * CCRNS_INT_NBITS >= CCPOLYZP_PO2CYC_RANDOM_TERNARY_RNG_NBITS_PER_COEFF");

    cc_assert(rng_nunits_per_coeff >= ccn_nof_size(rng_nbytes_per_coeff));
    cc_unit random[rng_nunits_per_coeff];
    ccn_clear(rng_nunits_per_coeff, random);

    // prepare for modular reduction with 3
    struct ccrns_modulus mod3;
    cc_require((rv = ccrns_modulus_init_ws(ws, &mod3, 3)) == CCERR_OK, errOut);

    for (uint32_t coeff_idx = 0; coeff_idx < degree; ++coeff_idx) {
        uint32_t coeff_rng_offset = coeff_idx % rng_ncoeffs;
        if (coeff_rng_offset == 0) {
            cc_require((rv = ccrng_generate(rng, rng_nbytes, (cc_unit *)random_bytes)) == CCERR_OK, errOut);
        }

        cc_unit *random_coeff_ptr = (cc_unit *)(&(random_bytes[coeff_rng_offset * rng_nbytes_per_coeff]));
        ccn_set(rng_nunits_per_coeff, random, random_coeff_ptr);
        uint64_t *random_coeff_64bit_ptr = &((uint64_t *)random)[1];
        // Mask out top 32 bits, so modular reduction is on 128 - 32 = 96 bits
        *random_coeff_64bit_ptr &= 0x00000000ffffffff;
        ccrns_int random_reduced = ccpolyzp_po2cyc_scalar_mod2(random, &mod3);

        for (uint32_t rns_idx = 0; rns_idx < nmoduli; ++rns_idx) {
            ccrns_int modulus = ccpolyzp_po2cyc_ctx_int_modulus(x->context, rns_idx);
            ccrns_int ternary = ccpolyzp_po2cyc_scalar_sub_mod(random_reduced, 1, modulus);
            ccpolyzp_po2cyc_rns_int_to_units(CCPOLYZP_PO2CYC_DATA(r, rns_idx, coeff_idx), ternary);
        }
    }
    CC_FREE_BP_WS(ws, bp);

errOut:
    return rv;
}

#define HAMMING_WEIGHT(v) popcount((v))

CC_INLINE CC_CONST cc_unit popcount(uint64_t v)
{
#if CCN_UNIT_SIZE == 8
    return cc_popcount64(v);
#elif CCN_UNIT_SIZE == 4
    const uint32_t *p = (uint32_t *)&v;
    return cc_popcount32(*p) + cc_popcount32(*(p + 1));
#else
#error("Invalid CCN_UNIT_SIZE")
#endif
}

// ccpolyzp_po2cyc_random_cbs_ws samples 48 bits = 6 bytes, and uses the lowest 42 bits.
#define CCPOLYZP_PO2CYC_RANDOM_CBD_RNG_NBITS_PER_COEFF_SIGMA_3_2 48

cc_size CCPOLYZP_PO2CYC_RANDOM_CBD_WORKSPACE_N(cc_size degree)
{
    cc_size rng_ncoeffs = CC_MIN_EVAL(CCPOLYZP_PO2CYC_RANDOM_MAX_RNG_NCOEFFS, degree);
    return ccn_nof(rng_ncoeffs * CCPOLYZP_PO2CYC_RANDOM_CBD_RNG_NBITS_PER_COEFF_SIGMA_3_2);
}

int ccpolyzp_po2cyc_random_cbd_ws(cc_ws_t ws,
                                  ccpolyzp_po2cyc_t r,
                                  struct ccrng_state *rng,
                                  ccpolyzp_po2cyc_random_cbd_sigma_t sigma)
{
    int rv = CCERR_OK;
    uint32_t k = 2;

    switch (sigma) {
    case CCPOLYZP_PO2CYC_RANDOM_CBD_SIGMA3_2:
        k = 21;
        break;
    default:
        return CCERR_PARAMETER;
    }
    cc_assert(k <= 32);

    // Mask to select the k lowest bits for positive samples
    // pos_mask = 00..0011..11 for (64-k) 0's and k 1's.
    uint64_t pos_mask = (1 << k) - 1;
    // Mask to select the next k lowest bits for negative samples
    // neg_mask = 00..0011..1100..00 for (64 - k * 2) 0's, k 1's, k 0's.
    uint64_t neg_mask = pos_mask << k;

    ccpolyzp_po2cyc_coeff_t x = (ccpolyzp_po2cyc_coeff_t)r;
    const uint32_t degree = x->context->dims.degree;
    const uint32_t nmoduli = x->context->dims.nmoduli;

    CC_DECL_BP_WS(ws, bp);
    cc_size rng_ncoeffs = CC_MIN_EVAL(CCPOLYZP_PO2CYC_RANDOM_MAX_RNG_NCOEFFS, degree);
    uint8_t *random_bytes =
        (uint8_t *)CC_ALLOC_WS(ws, ccn_nof(CCPOLYZP_PO2CYC_RANDOM_CBD_RNG_NBITS_PER_COEFF_SIGMA_3_2 * rng_ncoeffs));

    cc_size rng_nbytes_per_coeff = (CCPOLYZP_PO2CYC_RANDOM_CBD_RNG_NBITS_PER_COEFF_SIGMA_3_2 / 8);
    cc_size rng_nbytes = rng_nbytes_per_coeff * rng_ncoeffs;
    cc_static_assert(CCRNS_INT_NBITS >= CCPOLYZP_PO2CYC_RANDOM_CBD_RNG_NBITS_PER_COEFF_SIGMA_3_2,
                     "ccpolyzp_po2cyc_random_cbs_ws requires CCRNS_INT_NBITS >=\
                     CCPOLYZP_PO2CYC_RANDOM_CBD_RNG_NBITS_PER_COEFF_SIGMA_3_2");

    uint8_t *random_coeff_ptr = random_bytes;
    for (uint32_t coeff_idx = 0; coeff_idx < degree; ++coeff_idx) {
        uint32_t coeff_rng_offset = coeff_idx % rng_ncoeffs;
        if (coeff_rng_offset == 0) {
            cc_require((rv = ccrng_generate(rng, rng_nbytes, (cc_unit *)random_bytes)) == CCERR_OK, errOut);
            random_coeff_ptr = random_bytes;
        }
        // NOTE: we assume that number of positive and negative bits never overflows one cc_unit
        uint64_t pos = HAMMING_WEIGHT(CC_H2LE64(cc_load64_le(random_coeff_ptr)) & pos_mask);
        uint64_t neg = HAMMING_WEIGHT(CC_H2LE64(cc_load64_le(random_coeff_ptr)) & neg_mask);

        for (uint32_t rns_idx = 0; rns_idx < nmoduli; ++rns_idx) {
            // coeff = pos - neg % mod
            ccrns_int modulus = ccpolyzp_po2cyc_ctx_int_modulus(x->context, rns_idx);
            ccrns_int rns_coeff = ccpolyzp_po2cyc_scalar_sub_mod(pos, neg, modulus);
            ccpolyzp_po2cyc_rns_int_to_units(CCPOLYZP_PO2CYC_DATA(r, rns_idx, coeff_idx), rns_coeff);
        }
        random_coeff_ptr += rng_nbytes_per_coeff;
    }
    CC_FREE_BP_WS(ws, bp);

errOut:
    return rv;
}

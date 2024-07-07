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

#include "ccpolyzp_po2cyc_serialization.h"
#include "ccpolyzp_po2cyc_internal.h"

int ccpolyzp_po2cyc_bytes_to_coeffs(size_t ncoeffs,
                                    ccrns_int *cc_counted_by(ncoeffs) coeffs,
                                    size_t nbytes,
                                    const uint8_t *cc_counted_by(nbytes) bytes,
                                    size_t bits_per_coeff,
                                    size_t nskip_lsbs_per_coeff)
{
    int rv = CCERR_OK;
    cc_require_or_return(bits_per_coeff > 0, CCERR_PARAMETER);
    cc_require_or_return(bits_per_coeff > nskip_lsbs_per_coeff, CCERR_PARAMETER);

    size_t nserialized_bits = bits_per_coeff - nskip_lsbs_per_coeff;

    const size_t nbytes_decode = cc_ceiling(ncoeffs * nserialized_bits, 8);
    const size_t ncoeffs_ceil = cc_ceiling(8 * nbytes, nserialized_bits);
    cc_require_or_return((nbytes_decode == nbytes) || (ncoeffs_ceil == ncoeffs), CCERR_PARAMETER);

    size_t coeff_idx = 0;
    ccrns_int coeff = 0;
    size_t remaining_coeff_bits = nserialized_bits;

    // consume bytes and populate coeffs
    for (uint32_t i = 0; i < nbytes; ++i) {
        uint8_t byte = bytes[i];
        size_t remaining_data_bits = 8;
        do {
            if (remaining_coeff_bits == 0) {
                remaining_coeff_bits = nserialized_bits;
                coeffs[coeff_idx++] = coeff << nskip_lsbs_per_coeff;
                coeff = 0;
            }

            size_t shift = CC_MIN(remaining_coeff_bits, remaining_data_bits);
            coeff <<= shift;
            coeff |= byte >> (8 - shift);
            byte = (uint8_t)(byte << shift);
            remaining_coeff_bits -= shift;
            remaining_data_bits -= shift;
        } while (remaining_data_bits != 0);
    }
    if (coeff_idx < ncoeffs) {
        coeff <<= (remaining_coeff_bits + nskip_lsbs_per_coeff);
        coeffs[coeff_idx++] = coeff;
    }
    cc_assert(coeff_idx == ncoeffs);

    return rv;
}

int ccpolyzp_po2cyc_coeffs_to_bytes(size_t nbytes,
                                    uint8_t *cc_counted_by(nbytes) bytes,
                                    size_t ncoeffs,
                                    const ccrns_int *cc_counted_by(ncoeffs) coeffs,
                                    size_t bits_per_coeff,
                                    size_t nskip_lsbs_per_coeff)
{
    int rv = CCERR_OK;
    cc_require_or_return(bits_per_coeff > 0, CCERR_PARAMETER);
    cc_require_or_return(bits_per_coeff > nskip_lsbs_per_coeff, CCERR_PARAMETER);
    const size_t serialized_bits_per_coeff = bits_per_coeff - nskip_lsbs_per_coeff;
    const size_t ncoeffs_decode = cc_ceiling(nbytes * 8, serialized_bits_per_coeff);
    const size_t nbytes_ceil = cc_ceiling(serialized_bits_per_coeff * ncoeffs, 8);
    cc_require_or_return((ncoeffs_decode == ncoeffs) || (nbytes_ceil == nbytes), CCERR_PARAMETER);

    size_t byte_idx = 0;
    uint8_t byte = 0;
    size_t remaining_data_bits = 8;

    // consume coefficients and populate bytes
    for (uint32_t i = 0; i < ncoeffs; ++i) {
        ccrns_int coeff = coeffs[i] >> nskip_lsbs_per_coeff;
        size_t remaining_coeff_bits = serialized_bits_per_coeff;
        do {
            if (remaining_data_bits == 0) {
                bytes[byte_idx++] = byte;
                if (byte_idx == nbytes) {
                    return rv;
                }
                remaining_data_bits = 8;
                byte = 0;
            }
            size_t shift = CC_MIN(remaining_coeff_bits, remaining_data_bits);
            uint8_t byte_val = (uint8_t)(coeff >> (remaining_coeff_bits - shift));
            byte_val &= CCRNS_INT_MASK >> (CCRNS_INT_NBITS - remaining_coeff_bits);
            byte = (uint8_t)(byte << shift) | byte_val;
            remaining_data_bits -= shift;
            remaining_coeff_bits -= shift;
        } while (remaining_coeff_bits != 0);
    }
    if (byte_idx < nbytes) {
        byte <<= remaining_data_bits;
        bytes[byte_idx++] = byte;
    }
    cc_assert(byte_idx == nbytes);

    return rv;
}

/// @brief Return the number of bytes needed for serializing `degree` coefficents each with `bits_per_coeff` bits.
/// @param bits_per_coeff The number of bits per coefficient
CC_WARN_RESULT CC_INLINE size_t ccpolyzp_po2cyc_serialize_rns_nbytes(uint32_t degree, size_t bits_per_coeff)
{
    return cc_ceiling(bits_per_coeff * degree, 8);
}

/// @brief Return the number of bits per coefficient for RNS component
/// @param ctx The polynomial context
/// @param rns_idx The RNS component index
CC_NONNULL_ALL CC_WARN_RESULT CC_INLINE size_t ccpolyzp_po2cyc_serialize_bits_per_coeff(ccpolyzp_po2cyc_ctx_const_t ctx,
                                                                                        uint32_t rns_idx)
{
    const ccrns_int modulus = ccpolyzp_po2cyc_ctx_int_modulus(ctx, rns_idx);
    return CCRNS_INT_NBITS - cc_clz64(modulus);
}

size_t ccpolyzp_po2cyc_serialize_poly_nbytes(ccpolyzp_po2cyc_ctx_const_t ctx, uint32_t nskip_lsbs)
{
    uint32_t degree = ctx->dims.degree;
    uint32_t nmoduli = ctx->dims.nmoduli;
    size_t nbytes = 0;

    for (uint32_t rns_idx = 0; rns_idx < nmoduli; ++rns_idx) {
        const size_t bits_per_coeff = ccpolyzp_po2cyc_serialize_bits_per_coeff(ctx, rns_idx) - nskip_lsbs;
        nbytes += ccpolyzp_po2cyc_serialize_rns_nbytes(degree, bits_per_coeff);
    }

    return nbytes;
}

cc_size CCPOLYZP_PO2CYC_SERIALIZE_POLY_WORKSPACE_N(cc_size degree)
{
    return degree * CCPOLYZP_PO2CYC_NUNITS_PER_COEFF;
}

int ccpolyzp_po2cyc_serialize_poly_ws(cc_ws_t ws,
                                      size_t nbytes,
                                      uint8_t *cc_counted_by(nbytes) bytes,
                                      uint32_t nskip_lsbs,
                                      ccpolyzp_po2cyc_const_t poly)
{
    ccpolyzp_po2cyc_coeff_const_t poly_coeff = (ccpolyzp_po2cyc_coeff_const_t)poly;
    ccpolyzp_po2cyc_ctx_const_t ctx = poly_coeff->context;
    uint32_t degree = ctx->dims.degree;
    uint32_t nmoduli = ctx->dims.nmoduli;
    cc_require_or_return(nbytes == ccpolyzp_po2cyc_serialize_poly_nbytes(ctx, nskip_lsbs), CCERR_PARAMETER);
    cc_require_or_return(nskip_lsbs == 0 || nmoduli == 1, CCERR_PARAMETER);

    int rv = CCERR_OK;
    CC_DECL_BP_WS(ws, bp);

    ccrns_int *coeffs = (ccrns_int *)CC_ALLOC_WS(ws, degree * CCPOLYZP_PO2CYC_NUNITS_PER_COEFF);

    for (uint32_t rns_idx = 0; rns_idx < nmoduli; ++rns_idx) {
        // copy units to rns_ints
        for (uint32_t coeff_idx = 0; coeff_idx < degree; ++coeff_idx) {
            coeffs[coeff_idx] = ccpolyzp_po2cyc_units_to_rns_int(CCPOLYZP_PO2CYC_DATA_CONST(poly, rns_idx, coeff_idx));
        }

        // convert coeffs to bytes
        const size_t bits_per_coeff = ccpolyzp_po2cyc_serialize_bits_per_coeff(ctx, rns_idx);
        cc_require_or_return(bits_per_coeff > nskip_lsbs, CCERR_PARAMETER);
        const size_t serialized_bits_per_coeff = bits_per_coeff - nskip_lsbs;
        const size_t rns_nbytes = ccpolyzp_po2cyc_serialize_rns_nbytes(degree, serialized_bits_per_coeff);
        rv = ccpolyzp_po2cyc_coeffs_to_bytes(rns_nbytes, bytes, degree, coeffs, bits_per_coeff, nskip_lsbs);
        cc_require(rv == CCERR_OK, errOut);
        bytes += rns_nbytes;
    }

errOut:
    CC_FREE_BP_WS(ws, bp);
    return rv;
}

cc_size CCPOLYZP_PO2CYC_DESERIALIZE_POLY_WORKSPACE_N(cc_size degree)
{
    return degree * CCPOLYZP_PO2CYC_NUNITS_PER_COEFF;
}

int ccpolyzp_po2cyc_deserialize_poly_ws(cc_ws_t ws,
                                        ccpolyzp_po2cyc_t poly,
                                        uint32_t nskip_lsbs,
                                        size_t nbytes,
                                        const uint8_t *cc_counted_by(nbytes) bytes)
{
    ccpolyzp_po2cyc_coeff_const_t poly_coeff = (ccpolyzp_po2cyc_coeff_const_t)poly;
    ccpolyzp_po2cyc_ctx_const_t ctx = poly_coeff->context;
    uint32_t degree = ctx->dims.degree;
    uint32_t nmoduli = ctx->dims.nmoduli;
    cc_require_or_return(nbytes == ccpolyzp_po2cyc_serialize_poly_nbytes(ctx, nskip_lsbs), CCERR_PARAMETER);
    cc_require_or_return(nskip_lsbs == 0 || nmoduli == 1, CCERR_PARAMETER);

    int rv = CCERR_OK;
    CC_DECL_BP_WS(ws, bp);

    ccrns_int *coeffs = (ccrns_int *)CC_ALLOC_WS(ws, degree * CCPOLYZP_PO2CYC_NUNITS_PER_COEFF);

    for (uint32_t rns_idx = 0; rns_idx < nmoduli; ++rns_idx) {
        // convert bytes to coeffs
        const size_t bits_per_coeff = ccpolyzp_po2cyc_serialize_bits_per_coeff(ctx, rns_idx);
        cc_require_or_return(bits_per_coeff > nskip_lsbs, CCERR_PARAMETER);
        size_t serialized_bits_per_coeff = bits_per_coeff - nskip_lsbs;
        const size_t rns_nbytes = cc_ceiling(serialized_bits_per_coeff * degree, 8);
        rv = ccpolyzp_po2cyc_bytes_to_coeffs(degree, coeffs, rns_nbytes, bytes, bits_per_coeff, nskip_lsbs);
        cc_require(rv == CCERR_OK, errOut);
        bytes += rns_nbytes;

        // copy rns_ints to units
        for (uint32_t coeff_idx = 0; coeff_idx < degree; ++coeff_idx) {
            ccpolyzp_po2cyc_rns_int_to_units(CCPOLYZP_PO2CYC_DATA(poly, rns_idx, coeff_idx), coeffs[coeff_idx]);
        }
    }

errOut:
    CC_FREE_BP_WS(ws, bp);
    return rv;
}

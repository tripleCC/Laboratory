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

#ifndef _CORECRYPTO_CCPOLYZP_PO2CYC_SERIALIZATION_H
#define _CORECRYPTO_CCPOLYZP_PO2CYC_SERIALIZATION_H

#include <corecrypto/cc_config.h>
#include "ccpolyzp_po2cyc_internal.h"

CC_PTRCHECK_CAPABLE_HEADER()

/// @brief Convert a sequence of bytes to a sequence of `ccrns_int` where each coefficient holds `bits_per_coeff` bits
/// @param ncoeffs The number of coefficients
/// @param coeffs Converted coefficients will be written here
/// @param nbytes Number of bytes to convert
/// @param bytes The array of bytes to convert to coefficients
/// @param bits_per_coeff Number of bits that can be encoded in one coefficient
/// @param nskip_lsbs_per_coeff Number of least significant bits omitted from each serialized coefficient
/// @details `ncoeffs` and `nbytes` must be related to each other. Either `ncoeffs` = number of coefficients to hold `nbytes`
/// bytes or `nbytes` = number of bytes to hold `ncoeff` coefficients.
CC_NONNULL_ALL CC_WARN_RESULT int ccpolyzp_po2cyc_bytes_to_coeffs(size_t ncoeffs,
                                                                  ccrns_int *cc_counted_by(ncoeffs) coeffs,
                                                                  size_t nbytes,
                                                                  const uint8_t *cc_counted_by(nbytes) bytes,
                                                                  size_t bits_per_coeff,
                                                                  size_t nskip_lsbs_per_coeff);

/// @brief Convert a sequence of coefficients into a sequence of bytes, where each coefficient holds `bits_per_coeff` bits
/// @param nbytes Number of bytes
/// @param bytes Converted bytes will be written here
/// @param ncoeffs The number of coefficients to convert
/// @param coeffs Coefficients to convert
/// @param bits_per_coeff Number of bits that are encoded in one coefficient
/// @param nskip_lsbs_per_coeff Number of least significant bits omitted from each serialized coefficient
/// @details `ncoeffs` and `nbytes` must be related to each other. Either `ncoeffs` = number of coefficients to hold `nbytes`
/// bytes or `nbytes` = number of bytes to hold `ncoeff` coefficients.
CC_NONNULL_ALL CC_WARN_RESULT int ccpolyzp_po2cyc_coeffs_to_bytes(size_t nbytes,
                                                                  uint8_t *cc_counted_by(nbytes) bytes,
                                                                  size_t ncoeffs,
                                                                  const ccrns_int *cc_counted_by(ncoeffs) coeffs,
                                                                  size_t bits_per_coeff,
                                                                  size_t nskip_lsbs_per_coeff);

/// @brief Return the number of bytes needed to serialize a polynomial with the given context
/// @param nskip_lsbs Number of least significant bits to omit from each serialized coefficient
/// @param ctx The polynomial context
CC_NONNULL_ALL CC_WARN_RESULT size_t ccpolyzp_po2cyc_serialize_poly_nbytes(ccpolyzp_po2cyc_ctx_const_t ctx, uint32_t nskip_lsbs);

/// @param ws Workspace
/// @param nbytes Number of bytes the bytes buffer can hold
/// @param bytes Serialized polynomial will be written here
/// @param nskip_lsbs Number of least significant bits to omit from each RNS coefficient
/// @param poly The polynomial to serialize
/// @details Compressed serialization which takes advantage of the polynomial
/// coefficients being in a finite field with word-sized moduli, while
/// stored in a 64-bit value. As such, when the word-sized modulus is less
/// than 64 bits, the top bits of each coefficient will be zero and can be
/// omitted from serialization.
/// Concretely, a polynomial with word-sized modulus `q_1` can be compressed by a factor of
/// `\frac{64*L}{log2(q_1) + 1 nskip_lsbs}`.
/// @warning Setting `nskip_lsbs > 0` is only meaningful when the polynomial has 1 modulus.
CC_NONNULL_ALL CC_WARN_RESULT int ccpolyzp_po2cyc_serialize_poly_ws(cc_ws_t ws,
                                                                    size_t nbytes,
                                                                    uint8_t *cc_counted_by(nbytes) bytes,
                                                                    uint32_t nskip_lsbs,
                                                                    ccpolyzp_po2cyc_const_t poly);

/// @brief Deserialize a polynomial from a byte array
/// @param ws Workspace
/// @param poly The deserialized polynomial will be stored here
/// @param nskip_lsbs Number of least significant bits omitted from serialization of each coefficient
/// @param nbytes Number of bytes in the bytes buffer
/// @param bytes The byte buffer to deserialize
/// @details Omitted LSBs are deserialized to 0s
CC_NONNULL_ALL CC_WARN_RESULT int ccpolyzp_po2cyc_deserialize_poly_ws(cc_ws_t ws,
                                                                      ccpolyzp_po2cyc_t poly,
                                                                      uint32_t nskip_lsbs,
                                                                      size_t nbytes,
                                                                      const uint8_t *cc_counted_by(nbytes) bytes);

#endif /* _CORECRYPTO_CCPOLYZP_PO2CYC_SERIALIZATION_H */

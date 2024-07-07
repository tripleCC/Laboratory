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

#ifndef _CORECRYPTO_CCHE_SERIALIZATION_H_
#define _CORECRYPTO_CCHE_SERIALIZATION_H_

#include <corecrypto/cc_config.h>
#include "cche_internal.h"

CC_PTRCHECK_CAPABLE_HEADER()

/// @brief Serialize a ciphertext in coefficient format
/// @param ws Workspace
/// @param nbytes Number of bytes the bytes buffer can hold
/// @param bytes The buffer where to store the serialized ciphertext
/// @param ctext The ciphertext to serialize; Must have less than 2^16 polynomials.
/// @param nskip_lsbs i'th entry contains the number of least significant bits to omit from each serialized coefficient of the
/// i'th polynomial; if NULL, assumed to be 0 for all polynomials
/// @return `CCERR_OK` if the operation is successful
CC_NONNULL((1, 3, 4))
CC_WARN_RESULT int cche_serialize_ciphertext_coeff_ws(cc_ws_t ws,
                                                      size_t nbytes,
                                                      uint8_t *cc_counted_by(nbytes) bytes,
                                                      cche_ciphertext_coeff_const_t ctext,
                                                      const uint32_t *nskip_lsbs);

/// @brief Serialize a ciphertext in evaluation format
/// @param ws Workspace
/// @param nbytes Number of bytes the bytes buffer can hold
/// @param bytes The buffer where to store the serialized ciphertext
/// @param ctext The ciphertext to serialize; Must have less than 2^16 polynomials.
/// @return `CCERR_OK` if the operation is successful
CC_NONNULL_ALL CC_WARN_RESULT int cche_serialize_ciphertext_eval_ws(cc_ws_t ws,
                                                                    size_t nbytes,
                                                                    uint8_t *cc_counted_by(nbytes) bytes,
                                                                    cche_ciphertext_eval_const_t ctext);

/// @brief Deserialize a ciphertext in coefficient format
/// @param ws Workspace
/// @param ctext The ciphertext where to store the deserialized ciphertext; Must be initialized with `cche_ciphertext_coeff_init`
/// @param nbytes Number of bytes in the bytes buffer
/// @param bytes The buffer of bytes to deserialize
/// @param nskip_lsbs Number of least significant bits omitted from serialization of each polynomial coefficient; if NULL, no LSBs
/// are assumed to be omitted.
/// @return `CCERR_OK` if the operation is successful
/// @details BFV decryption is unlikely to rely on the LSBs of the polynomials, so omitted LSBs are deserialized to 0s
CC_NONNULL((1, 2, 4))
CC_WARN_RESULT int cche_deserialize_ciphertext_coeff_ws(cc_ws_t ws,
                                                        cche_ciphertext_coeff_t ctext,
                                                        size_t nbytes,
                                                        const uint8_t *cc_counted_by(nbytes) bytes,
                                                        const uint32_t *nskip_lsbs);

/// @brief Deserialize a ciphertext in evaluation format
/// @param ws Workspace
/// @param ctext The ciphertext where to store the deserialized ciphertext; Must be initialized with `cche_ciphertext_eval_init`
/// @param nbytes Number of bytes in the bytes buffer
/// @param bytes The buffer of bytes to deserialize
/// @return `CCERR_OK` if the operation is successful
CC_NONNULL_ALL CC_WARN_RESULT int cche_deserialize_ciphertext_eval_ws(cc_ws_t ws,
                                                                      cche_ciphertext_eval_t ctext,
                                                                      size_t nbytes,
                                                                      const uint8_t *cc_counted_by(nbytes) bytes);

/// @brief Serialize the first polynomial of a ciphertext in coefficient format
/// @param ws Workspace
/// @param nbytes Number of bytes the bytes buffer can hold
/// @param bytes The buffer where to store the serialized ciphertext polynomial
/// @param ctext The ciphertext whose first polynomial to serialize
/// @return `CCERR_OK` if the operation is successful
CC_NONNULL_ALL CC_WARN_RESULT int cche_serialize_seeded_ciphertext_coeff_ws(cc_ws_t ws,
                                                                            size_t nbytes,
                                                                            uint8_t *cc_counted_by(nbytes) bytes,
                                                                            cche_ciphertext_coeff_const_t ctext);

/// @brief Serialize the first polynomial of a ciphertext in evaluation format
/// @param ws Workspace
/// @param nbytes Number of bytes the bytes buffer can hold
/// @param bytes The buffer where to store the serialized ciphertext polynomial
/// @param ctext The ciphertext whose first polynomial to serialize
/// @return `CCERR_OK` if the operation is successful
CC_NONNULL_ALL CC_WARN_RESULT int cche_serialize_seeded_ciphertext_eval_ws(cc_ws_t ws,
                                                                           size_t nbytes,
                                                                           uint8_t *cc_counted_by(nbytes) bytes,
                                                                           cche_ciphertext_eval_const_t ctext);

/// @brief Deserialize a ciphertext in coefficient format using a seed
/// @param ws Workspace
/// @param ctext The ciphertext where to store the deserialized ciphertext; Must be initialized with `cche_ciphertext_coeff_init`
/// and must have `cche_ciphertext_fresh_npolys()` polynomials.
/// @param nbytes Number of bytes in the bytes buffer
/// @param bytes The buffer of bytes to deserialize
/// @param seed The seed to regenerate the second polynomial.
/// @return `CCERR_OK` if the operation is successful
/// @details The bytes array is assumed to contain the serialization of the first polynomial and the second polynomial of the
/// ciphertext is represented by the seed.
CC_NONNULL_ALL CC_WARN_RESULT int cche_deserialize_seeded_ciphertext_coeff_ws(cc_ws_t ws,
                                                                              cche_ciphertext_coeff_t ctext,
                                                                              size_t nbytes,
                                                                              const uint8_t *cc_counted_by(nbytes) bytes,
                                                                              cche_rng_seed_const_t seed);

/// @brief Deserialize a ciphertext in evalutation format using a seed
/// @param ws Workspace
/// @param ctext The ciphertext where to store the deserialized ciphertext; Must be initialized with `cche_ciphertext_eval_init`
/// and must have `cche_ciphertext_fresh_npolys()` polynomials.
/// @param nbytes Number of bytes in the bytes buffer
/// @param bytes The buffer of bytes to deserialize
/// @param seed The seed to regenerate the second polynomial.
/// @return `CCERR_OK` if the operation is successful
/// @details The bytes array is assumed to contain the serialization of the first polynomial and the second polynomial of the
/// ciphertext is represented by the seed.
CC_NONNULL_ALL CC_WARN_RESULT int cche_deserialize_seeded_ciphertext_eval_ws(cc_ws_t ws,
                                                                             cche_ciphertext_eval_t ctext,
                                                                             size_t nbytes,
                                                                             const uint8_t *cc_counted_by(nbytes) bytes,
                                                                             cche_rng_seed_const_t seed);

#endif /* _CORECRYPTO_CCHE_SERIALIZATION_H_ */

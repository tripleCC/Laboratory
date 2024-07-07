/* Copyright (c) (2018-2020,2022,2023) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef cctestvector_parser_h
#define cctestvector_parser_h

#include <corecrypto/cc.h>
#include <stdint.h>
#include <stdbool.h>

#include "ccdict.h"
#include "cctest_driver.h"

/*!
 * @enum cctestvector_result_t
 * @abstract Set of possible test vector results. Acceptable tests are those which
 *  are deemd valid but borderline on unsafe.
 */
typedef enum {
    cctestvector_result_valid,
    cctestvector_result_acceptable,
    cctestvector_result_invalid,
} cctestvector_result_t;

/*!
 * These are keys used to index into test vector dictionaries for relevant test vector data.
 */
extern const char *cctestvector_key_algorithm;
extern const char *cctestvector_key_iv_size;
extern const char *cctestvector_key_key_size;
extern const char *cctestvector_key_tag_size;
extern const char *cctestvector_key_comment;
extern const char *cctestvector_key_id;
extern const char *cctestvector_key_type;
extern const char *cctestvector_key_value;
extern const char *cctestvector_key_key;
extern const char *cctestvector_key_key_der;
extern const char *cctestvector_key_iv;
extern const char *cctestvector_key_aad;
extern const char *cctestvector_key_msg;
extern const char *cctestvector_key_ct;
extern const char *cctestvector_key_tag;
extern const char *cctestvector_key_curve;
extern const char *cctestvector_key_public;
extern const char *cctestvector_key_private;
extern const char *cctestvector_key_private_key_pkcs8;
extern const char *cctestvector_key_shared;
extern const char *cctestvector_key_signature;
extern const char *cctestvector_key_rsa_modulus;
extern const char *cctestvector_key_rsa_public_key;
extern const char *cctestvector_key_sha;
extern const char *cctestvector_key_mgf_sha;
extern const char *cctestvector_key_padding;
extern const char *cctestvector_key_valid;
extern const char *cctestvector_key_flags;
extern const char *cctestvector_key_label;
extern const char *cctestvector_key_salt_size;
extern const char *cctestvector_key_pk;
extern const char *cctestvector_key_sk;

/*!
 * @enum wycheproof_flag_t
 * @abstract Set of possible test vector flags.
 */
typedef enum {
    wycheproof_flag_ConstructedIv = 1 << 0,
    wycheproof_flag_ZeroLengthIv = 1 << 1,
    wycheproof_flag_AddSubChain = 1 << 2,
    wycheproof_flag_CVE_2017_10176 = 1 << 3,
    wycheproof_flag_CompressedPoint = 1 << 4,
    wycheproof_flag_GroupIsomorphism = 1 << 5,
    wycheproof_flag_InvalidPublic = 1 << 6,
    wycheproof_flag_IsomorphicPublicKey = 1 << 7,
    wycheproof_flag_ModifiedPrime = 1 << 8,
    wycheproof_flag_UnnamedCurve = 1 << 9,
    wycheproof_flag_UnusedParam = 1 << 10,
    wycheproof_flag_WeakPublicKey = 1 << 11,
    wycheproof_flag_WrongOrder = 1 << 12,
    wycheproof_flag_BER = 1 << 13,
    wycheproof_flag_EdgeCase = 1 << 14,
    wycheproof_flag_MissingZero = 1 << 15,
    wycheproof_flag_PointDuplication = 1 << 16,
    wycheproof_flag_WeakHash = 1 << 17,
    wycheproof_flag_MissingNull = 1 << 18,
    wycheproof_flag_SmallModulus = 1 << 19,
    wycheproof_flag_SmallPublicKey = 1 << 20,
    wycheproof_flag_SignatureMalleability = 1 << 21,
    wycheproof_flag_NegativeOfPrime = 1 << 22,
    wycheproof_flag_ZeroSharedSecret = 1 << 23,
    wycheproof_flag_LowOrderPublic = 1 << 24,
} wycheproof_flag_t;

typedef struct cctestvector_parser *cctestvector_parser_t;

/*
 * Run a given test vector and return true on success and false otherwise.
 */
typedef bool (*cctestvector_handler_t)(ccdict_t test_vector_data);

/*!
 * @function cctestvector_parser_from_algorithm
 * @abstract Return the appropriate `cctestvector_parser_from_algorithm` based on the expected format.
 * @param format String identifier for the test vector format. Note: this should be automatically generated
 *    when the tests are compiled into binary data.
 * @return A `cctestvector_parser_t` instance, or NULL if no such format-specific parser exists.
 */
CC_NONNULL((1))
cctestvector_parser_t
cctestvector_parser_from_family(const char *format);

/*!
 * @function cctestvector_parser_parse
 * @abstract Run the test vector parser with the given test vector handler.
 * @param parser A `cctestvector_parser_t` created using `cctestvector_parser_from_algorithm`.
 * @param vector_buffer A pointer to the JSON test vector bytes.
 * @param vector_buffer_len Length of the test vector buffer.
 * @param driver A function to be invoked for each generated test.
 *   Note: this is normally `cctestvector_run`.
 */
CC_NONNULL((1,2,4))
int cctestvector_parser_parse(cctestvector_parser_t parser,
                              const uint8_t *vector_buffer,
                              size_t vector_buffer_len,
                              cctest_driver_t driver);

#endif /* cctestvector_parser_h */

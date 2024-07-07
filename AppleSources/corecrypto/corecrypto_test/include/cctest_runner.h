/* Copyright (c) (2019,2020,2022,2023) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CCTEST_RUNNER_H_
#define _CORECRYPTO_CCTEST_RUNNER_H_

#include <stdbool.h>

#include <corecrypto/ccsha1.h>
#include <corecrypto/ccsha2.h>
#include <corecrypto/ccsha3.h>

#include "ccdict.h"

CC_NONNULL_ALL
bool crypto_test_chacha20poly1305_runner(ccdict_t vector);

CC_NONNULL_ALL
bool crypto_test_aes_gcm_runner(ccdict_t vector);

CC_NONNULL_ALL
bool crypto_test_aes_ccm_runner(ccdict_t vector);

CC_NONNULL_ALL
bool crypto_test_cmac_runner(ccdict_t vector);

CC_NONNULL_ALL
bool crypto_test_ecdh_runner(ccdict_t vector);

CC_NONNULL_ALL
bool crypto_test_ecdsa_runner(ccdict_t vector);

CC_NONNULL_ALL
bool crypto_test_x25519_runner(ccdict_t vector);

CC_NONNULL_ALL
bool crypto_test_ed25519_runner(ccdict_t vector);

CC_NONNULL_ALL
bool crypto_test_x448_runner(ccdict_t vector);

CC_NONNULL_ALL
bool crypto_test_ed448_runner(ccdict_t vector);

CC_NONNULL_ALL
bool crypto_test_rsassa_runner(ccdict_t vector);

CC_NONNULL_ALL
bool crypto_test_rsaes_runner(ccdict_t vector);

CC_NONNULL_ALL
bool crypto_test_primality_runner(ccdict_t vector);

#define EXTRACT_HEX_STRING_PARAMETER(NAME)                    \
    if (NAME##_buffer != NULL) {                              \
        NAME##_string = malloc(NAME##_len + 1);               \
        memset(NAME##_string, 0, NAME##_len + 1);             \
        memcpy(NAME##_string, NAME##_buffer, NAME##_len);     \
        NAME = hexStringToBytes((const char *)NAME##_string); \
    }

#define EXTRACT_STRING_PARAMETER(NAME)                    \
    if (NAME##_buffer != NULL) {                          \
        NAME##_string = malloc(NAME##_len + 1);           \
        memset(NAME##_string, 0, NAME##_len + 1);         \
        memcpy(NAME##_string, NAME##_buffer, NAME##_len); \
        NAME = bytesToBytes(NAME##_buffer, NAME##_len);   \
    }

#define HEX_VALUE_TO_BUFFER(NAME, KEY)                                         \
    size_t NAME##_len = 0;                                                     \
    const uint8_t *NAME##_buffer = ccdict_get_value(vector, KEY, &NAME##_len); \
    char *NAME##_string = NULL;                                                \
    byteBuffer NAME = NULL;                                                    \
    EXTRACT_HEX_STRING_PARAMETER(NAME);

#define STRING_TO_BUFFER(NAME, KEY)                                            \
    size_t NAME##_len = 0;                                                     \
    const uint8_t *NAME##_buffer = ccdict_get_value(vector, KEY, &NAME##_len); \
    char *NAME##_string = NULL;                                                \
    byteBuffer NAME = NULL;                                                    \
    EXTRACT_STRING_PARAMETER(NAME);

#define RELEASE_BUFFER(BUFFER) \
    free(BUFFER);              \
    free(BUFFER##_string);

#define CC_WYCHEPROOF_CHECK_OP_RESULT(_opresult_, _result_, _label_) \
    do {                                                             \
        if (!(_opresult_)) {                                         \
            _result_ = false;                                        \
            goto _label_;                                            \
        }                                                            \
    } while (0)

CC_INLINE CC_NONNULL_ALL
const struct ccdigest_info* cctest_parse_digest(const byteBuffer sha)
{
#define IS_DIGEST(_name_) \
    (sha->len == strlen(_name_) && \
     memcmp(sha->bytes, _name_, strlen(_name_)) == 0)

    if (IS_DIGEST("SHA-1")) {
        return ccsha1_di();
    }

    if (IS_DIGEST("SHA-224")) {
        return ccsha224_di();
    }

    if (IS_DIGEST("SHA-256")) {
        return ccsha256_di();
    }

    if (IS_DIGEST("SHA-384")) {
        return ccsha384_di();
    }

    if (IS_DIGEST("SHA-512")) {
        return ccsha512_di();
    }

    if (IS_DIGEST("SHA-512/256")) {
        return ccsha512_256_di();
    }

    if (IS_DIGEST("SHA3-224")) {
        return ccsha3_224_di();
    }

    if (IS_DIGEST("SHA3-256")) {
        return ccsha3_256_di();
    }

    if (IS_DIGEST("SHA3-384")) {
        return ccsha3_384_di();
    }

    if (IS_DIGEST("SHA3-512")) {
        return ccsha3_512_di();
    }

    return NULL;
}

#endif /* _CORECRYPTO_CCTEST_RUNNER_H_ */

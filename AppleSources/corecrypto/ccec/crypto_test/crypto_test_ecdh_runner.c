/* Copyright (c) (2018-2023) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "ccdict.h"
#include "testbyteBuffer.h"
#include "cctestvector_parser.h"
#include "cctest_driver.h"
#include "cctest_runner.h"
#include "crypto_test_ec.h"

#include <corecrypto/ccec.h>
#include <corecrypto/ccder.h>

bool crypto_test_ecdh_runner(ccdict_t vector)
{
    bool result = true;

    STRING_TO_BUFFER(id, cctestvector_key_id);
    STRING_TO_BUFFER(curve, cctestvector_key_curve);
    HEX_VALUE_TO_BUFFER(public, cctestvector_key_public);
    HEX_VALUE_TO_BUFFER(private, cctestvector_key_private);
    HEX_VALUE_TO_BUFFER(shared, cctestvector_key_shared);

    uint64_t test_result = ccdict_get_uint64(vector, cctestvector_key_valid);
    uint64_t flags = ccdict_get_flags(vector, cctestvector_key_flags);

    if (curve == NULL || public == NULL || private == NULL || shared == NULL || id == NULL) {
        RELEASE_BUFFER(id);
        RELEASE_BUFFER(curve);
        RELEASE_BUFFER(private);
        RELEASE_BUFFER(public);
        RELEASE_BUFFER(shared);
        return false;
    }

    // These test vectors have valid public keys for our curve (and the resultant shared secret
    // is correct). However they also, a la RFC 3279, contain information describing an unnamed
    // elliptic curve in which to operate with. We do not allow unnamed curves and do not
    // parse these extra parameters anyways. Because of this, we will end up passing these vectors
    // while the test vectors themselves are invalid; just return true immediately.
    if (flags & wycheproof_flag_UnnamedCurve) {
        RELEASE_BUFFER(id);
        RELEASE_BUFFER(curve);
        RELEASE_BUFFER(private);
        RELEASE_BUFFER(public);
        RELEASE_BUFFER(shared);
        return true;
    }

    ccec_const_cp_t cp = NULL;
    if (curve && strlen("secp224r1") == curve->len && memcmp(curve->bytes, "secp224r1", curve->len) == 0) {
        cp = ccec_cp_224();
    } else if (curve && strlen("secp256r1") == curve->len && memcmp(curve->bytes, "secp256r1", curve->len) == 0) {
        cp = ccec_cp_256();
    } else if (curve && strlen("secp384r1") == curve->len && memcmp(curve->bytes, "secp384r1", curve->len) == 0) {
        cp = ccec_cp_384();
    } else if (curve && strlen("secp521r1") == curve->len && memcmp(curve->bytes, "secp521r1", curve->len) == 0) {
        cp = ccec_cp_521();
    } else {
        RELEASE_BUFFER(id);
        RELEASE_BUFFER(curve);
        RELEASE_BUFFER(private);
        RELEASE_BUFFER(public);
        RELEASE_BUFFER(shared);
        return true;
    }

    ccec_full_ctx_decl_cp(cp, private_key);
    ccec_ctx_init(cp, private_key);
    ccec_pub_ctx_decl_cp(cp, public_key);
    ccec_ctx_init(cp, public_key);

    uint8_t shared_secret[256];
    size_t shared_secret_len = sizeof(shared_secret);

    // There are a few edge cases here.
    //
    // First, our ccec_raw_import_priv_only function requires the
    // input buffer to be exactly as long as the curve size.
    //
    // Second, Wycheproof inputs may be too short or too long with
    // leading zeros.
    size_t curve_size = ccec_cp_order_size(cp);
    size_t private_bytes_len = curve_size;
    uint8_t private_bytes[private_bytes_len];
    memset(private_bytes, 0, private_bytes_len);

    // Input is too long (i.e. we have leading zeros)
    if (private->len > private_bytes_len) {
        size_t number_leading_zeros = private->len - private_bytes_len;
        memcpy(private_bytes, private->bytes + number_leading_zeros, private_bytes_len);
    } else if (private->len == private_bytes_len) {
        memcpy(private_bytes, private->bytes, private_bytes_len);
    } else {
        // Input is too short
        memcpy(private_bytes + (private_bytes_len - private->len), private->bytes, private->len);
    }

    int result_code = ccec_raw_import_priv_only(cp, private_bytes_len, private_bytes, private_key);
    CC_WYCHEPROOF_CHECK_OP_RESULT(result_code == 0, result, cleanup);

    byteBuffer public_key_buffer = ccec_test_parse_spki(public, NULL, NULL);
    CC_WYCHEPROOF_CHECK_OP_RESULT(public_key_buffer != NULL, result, cleanup);

    result_code = ccec_import_pub(cp, public_key_buffer->len, public_key_buffer->bytes, public_key);
    free(public_key_buffer);
    CC_WYCHEPROOF_CHECK_OP_RESULT(result_code == 0, result, cleanup);

    result_code = ccecdh_compute_shared_secret(private_key, public_key, &shared_secret_len, shared_secret, ccrng(NULL));
    CC_WYCHEPROOF_CHECK_OP_RESULT(result_code == 0, result, cleanup);

    CC_WYCHEPROOF_CHECK_OP_RESULT(shared_secret_len == shared->len, result, cleanup);
    CC_WYCHEPROOF_CHECK_OP_RESULT(cc_cmp_safe(shared_secret_len, shared_secret, shared->bytes) == 0, result, cleanup);

cleanup:
    if (test_result == cctestvector_result_invalid) {
        result = !result;
    }
    if (!result) {
        fprintf(stderr, "Test ID %s failed\n", id_string);
    }

    RELEASE_BUFFER(id);
    RELEASE_BUFFER(curve);
    RELEASE_BUFFER(private);
    RELEASE_BUFFER(public);
    RELEASE_BUFFER(shared);

    return result;
}

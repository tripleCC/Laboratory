/* Copyright (c) (2018,2019,2023) Apple Inc. All rights reserved.
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

#include <corecrypto/ccchacha20poly1305.h>
#include <corecrypto/ccchacha20poly1305_priv.h>

bool
crypto_test_chacha20poly1305_runner(ccdict_t vector)
{
    bool result = true;

    HEX_VALUE_TO_BUFFER(id, cctestvector_key_id);
    HEX_VALUE_TO_BUFFER(iv, cctestvector_key_iv);
    HEX_VALUE_TO_BUFFER(key, cctestvector_key_key);
    HEX_VALUE_TO_BUFFER(tag, cctestvector_key_tag);
    HEX_VALUE_TO_BUFFER(aad, cctestvector_key_aad);
    HEX_VALUE_TO_BUFFER(msg, cctestvector_key_msg);
    HEX_VALUE_TO_BUFFER(expected_ct, cctestvector_key_ct);

    uint64_t test_result = ccdict_get_uint64(vector, cctestvector_key_valid);

    const struct ccchacha20poly1305_info *info = ccchacha20poly1305_info();
    ccchacha20poly1305_ctx context;

    uint8_t actual_tag[16];
    uint8_t actual_ct[msg_len / 2];

    if (!(id && iv && key && tag && aad && msg && expected_ct)) {
        result = false;
        goto cleanup;
    }

    CC_WYCHEPROOF_CHECK_OP_RESULT(iv->len == CCCHACHA20_NONCE_NBYTES, result, cleanup);

    int rc = ccchacha20poly1305_init(info, &context, key->bytes);
    CC_WYCHEPROOF_CHECK_OP_RESULT(rc == CCERR_OK, result, cleanup);

    rc = ccchacha20poly1305_setnonce(info, &context, iv->bytes);
    CC_WYCHEPROOF_CHECK_OP_RESULT(rc == CCERR_OK, result, cleanup);

    rc = ccchacha20poly1305_aad(info, &context, aad->len, aad->bytes);
    CC_WYCHEPROOF_CHECK_OP_RESULT(rc == CCERR_OK, result, cleanup);

    rc = ccchacha20poly1305_encrypt(info, &context, msg->len, msg->bytes, actual_ct);
    CC_WYCHEPROOF_CHECK_OP_RESULT(rc == CCERR_OK, result, cleanup);

    rc = ccchacha20poly1305_finalize(info, &context, actual_tag);
    CC_WYCHEPROOF_CHECK_OP_RESULT(rc == CCERR_OK, result, cleanup);

    CC_WYCHEPROOF_CHECK_OP_RESULT(tag->len == sizeof(actual_tag), result, cleanup);
    CC_WYCHEPROOF_CHECK_OP_RESULT(cc_cmp_safe(sizeof(actual_tag), actual_tag, tag->bytes) == 0, result, cleanup);

    if (msg->len > 0) {
        CC_WYCHEPROOF_CHECK_OP_RESULT(expected_ct->len == sizeof(actual_ct), result, cleanup);
        CC_WYCHEPROOF_CHECK_OP_RESULT(cc_cmp_safe(expected_ct->len, expected_ct->bytes, actual_ct) == 0, result, cleanup);
    }

cleanup:
    if (test_result == cctestvector_result_invalid) {
        result = !result;
    }

    if (!result) {
        fprintf(stderr, "Test ID %s failed\n", id_string);
    }

    RELEASE_BUFFER(id);
    RELEASE_BUFFER(iv);
    RELEASE_BUFFER(key);
    RELEASE_BUFFER(tag);
    RELEASE_BUFFER(msg);
    RELEASE_BUFFER(aad);
    RELEASE_BUFFER(expected_ct);

    return result;
}

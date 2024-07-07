/* Copyright (c) (2018-2020,2023) Apple Inc. All rights reserved.
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

#include <corecrypto/ccmode.h>

bool
crypto_test_aes_ccm_runner(ccdict_t vector)
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

    uint8_t actual_tag[16];
    uint8_t actual_ct[msg_len / 2];

    const struct ccmode_ccm *mode = ccaes_ccm_encrypt_mode();
    ccccm_ctx_decl(mode->size, context);
    ccccm_nonce_decl(mode->nonce_size, nonce_context);

    if (!(id && iv && key && tag && aad && msg && expected_ct)) {
        result = false;
        goto cleanup;
    }

    int rc = mode->init(mode, context, key->len, key->bytes);
    CC_WYCHEPROOF_CHECK_OP_RESULT(rc == CCERR_OK, result, cleanup);

    rc = mode->set_iv(context, nonce_context, iv->len, iv->bytes, tag->len, aad->len, msg->len);
    CC_WYCHEPROOF_CHECK_OP_RESULT(rc == CCERR_OK, result, cleanup);

    rc = mode->cbcmac(context, nonce_context, aad->len, aad->bytes);
    CC_WYCHEPROOF_CHECK_OP_RESULT(rc == CCERR_OK, result, cleanup);

    rc = mode->ccm(context, nonce_context, msg->len, msg->bytes, actual_ct);
    CC_WYCHEPROOF_CHECK_OP_RESULT(rc == CCERR_OK, result, cleanup);

    rc = mode->finalize(context, nonce_context, actual_tag);
    CC_WYCHEPROOF_CHECK_OP_RESULT(rc == CCERR_OK, result, cleanup);
    ccccm_ctx_clear(mode->size, context);

    CC_WYCHEPROOF_CHECK_OP_RESULT(cc_cmp_safe(tag->len, actual_tag, tag->bytes) == 0, result, cleanup);

    if (msg->len > 0) {
        CC_WYCHEPROOF_CHECK_OP_RESULT(expected_ct->len == sizeof(actual_ct), result, cleanup);
        CC_WYCHEPROOF_CHECK_OP_RESULT(cc_cmp_safe(expected_ct->len, expected_ct->bytes, actual_ct) == 0, result, cleanup);
    }

cleanup:
    if (test_result == cctestvector_result_invalid) {
        result = !result;
    }

    if (!result) {
        fprintf(stderr, "Test ID %s failed [AES-CCM]\n", id_string);
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

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

#include "ccdict.h"
#include "testbyteBuffer.h"
#include "cctestvector_parser.h"
#include "cctest_driver.h"
#include "cctest_runner.h"

#include <corecrypto/cc_priv.h>
#include <corecrypto/ccrsa.h>
#include <corecrypto/ccsha1.h>
#include <corecrypto/ccsha2.h>
#include <corecrypto/ccder.h>

bool crypto_test_rsassa_runner(ccdict_t vector)
{
    bool result = true;

    STRING_TO_BUFFER(id, cctestvector_key_id);
    STRING_TO_BUFFER(type, cctestvector_key_type);
    STRING_TO_BUFFER(sha, cctestvector_key_sha);
    STRING_TO_BUFFER(mgfSha, cctestvector_key_mgf_sha);
    STRING_TO_BUFFER(keySize, cctestvector_key_key_size);
    HEX_VALUE_TO_BUFFER(key, cctestvector_key_key_der);
    HEX_VALUE_TO_BUFFER(signature, cctestvector_key_signature);
    HEX_VALUE_TO_BUFFER(msg, cctestvector_key_msg);

    cc_assert(id && type && sha && keySize && key);

    uint64_t test_result = ccdict_get_uint64(vector, cctestvector_key_valid);
    uint64_t flags = ccdict_get_flags(vector, cctestvector_key_flags);

    bool isPSS = strcmp(type_string, "RsassaPssVerify") == 0;
    cc_assert(mgfSha || !isPSS);

    const struct ccdigest_info *di = cctest_parse_digest(sha);
    const struct ccdigest_info *mgf_di = NULL;
    if (mgfSha) {
        mgf_di = cctest_parse_digest(mgfSha);
    }

    if (msg == NULL || signature == NULL || di == NULL || (mgfSha && mgf_di == NULL)) {
        RELEASE_BUFFER(id);
        RELEASE_BUFFER(type);
        RELEASE_BUFFER(sha);
        RELEASE_BUFFER(mgfSha);
        RELEASE_BUFFER(keySize);
        RELEASE_BUFFER(key);
        RELEASE_BUFFER(signature);
        RELEASE_BUFFER(msg);
        return true;
    }

    uint8_t digest[di->output_size];
    uint8_t fault_canary[sizeof(CCRSA_PKCS1_FAULT_CANARY)];
    ccdigest(di, msg->len, msg->bytes, digest);

    bool valid = false;
    int result_code = 0;

    cc_size n = ccrsa_import_pub_n(key->len, key->bytes);
    ccrsa_pub_ctx_decl_n(n, public_key);
    ccrsa_ctx_n(public_key) = n;

    result_code = ccrsa_import_pub(public_key, key->len, key->bytes);
    CC_WYCHEPROOF_CHECK_OP_RESULT(result_code == CCERR_OK, result, cleanup);

    if (isPSS) {
        size_t slen_len = 0;
        const uint8_t *slen_ptr = ccdict_get_value(vector, cctestvector_key_salt_size, &slen_len);
        cc_assert(slen_ptr && slen_len > 0);

        uint8_t slen_str[slen_len + 1];
        memcpy(slen_str, slen_ptr, slen_len);
        slen_str[slen_len] = 0;

        size_t salt_size = (size_t)strtoull((const char *)slen_str, NULL, 10);

        result_code = ccrsa_verify_pss_digest(public_key, di, mgf_di, di->output_size, digest, signature->len, signature->bytes, salt_size, fault_canary);
        CC_WYCHEPROOF_CHECK_OP_RESULT(result_code == CCERR_VALID_SIGNATURE, result, cleanup);
        result_code = cc_cmp_safe(sizeof(CCRSA_PSS_FAULT_CANARY), CCRSA_PSS_FAULT_CANARY, fault_canary);
        CC_WYCHEPROOF_CHECK_OP_RESULT(result_code == 0, result, cleanup);

        result_code = ccrsa_verify_pss_msg(public_key, di, mgf_di, msg->len, msg->bytes, signature->len, signature->bytes, salt_size, fault_canary);
        CC_WYCHEPROOF_CHECK_OP_RESULT(result_code == CCERR_VALID_SIGNATURE, result, cleanup);
        result_code = cc_cmp_safe(sizeof(CCRSA_PSS_FAULT_CANARY), CCRSA_PSS_FAULT_CANARY, fault_canary);
        CC_WYCHEPROOF_CHECK_OP_RESULT(result_code == 0, result, cleanup);
    } else {
        result_code = ccrsa_verify_pkcs1v15(public_key, di->oid, di->output_size, digest, signature->len, signature->bytes, &valid);
        CC_WYCHEPROOF_CHECK_OP_RESULT((result_code == CCERR_OK) && valid, result, cleanup);

        result_code = ccrsa_verify_pkcs1v15_digest(public_key, di->oid, di->output_size, digest, signature->len, signature->bytes, fault_canary);
        CC_WYCHEPROOF_CHECK_OP_RESULT(result_code == CCERR_VALID_SIGNATURE, result, cleanup);
        result_code = cc_cmp_safe(sizeof(CCRSA_PKCS1_FAULT_CANARY), CCRSA_PKCS1_FAULT_CANARY, fault_canary);
        CC_WYCHEPROOF_CHECK_OP_RESULT(result_code == 0, result, cleanup);

        result_code = ccrsa_verify_pkcs1v15_msg(public_key, di, msg->len, msg->bytes, signature->len, signature->bytes, fault_canary);
        CC_WYCHEPROOF_CHECK_OP_RESULT(result_code == CCERR_VALID_SIGNATURE, result, cleanup);
        result_code = cc_cmp_safe(sizeof(CCRSA_PKCS1_FAULT_CANARY), CCRSA_PKCS1_FAULT_CANARY, fault_canary);
        CC_WYCHEPROOF_CHECK_OP_RESULT(result_code == 0, result, cleanup);
    }

cleanup:
    // Some tests contains a signature that, during verification, is missing a NULL byte.
    // Specifically, the test vector omits the bytes \x05\x00 after the OID and in turn
    // includes 2 extra \xff bytes in the padding string. Legacy implementations may
    // exhibit the above behaviour.
    if (flags & wycheproof_flag_MissingNull) {
        // We flip the result since we expect to fail these otherwise `acceptable` tests
        result = !result;
    }

    if (test_result == cctestvector_result_invalid) {
        result = !result;
    }

    if (!result) {
        const char *variant = isPSS ? "PSS": "PKCS1v15";
        fprintf(stderr, "Test ID %s failed [RSASSA-%s-%s-%s]\n", id_string, keySize_string, variant, sha_string);
    }
    ccrsa_pub_ctx_clear_n(n, public_key);
    RELEASE_BUFFER(id);
    RELEASE_BUFFER(type);
    RELEASE_BUFFER(sha);
    RELEASE_BUFFER(mgfSha);
    RELEASE_BUFFER(key);
    RELEASE_BUFFER(keySize);
    RELEASE_BUFFER(signature);
    RELEASE_BUFFER(msg);
    ccrsa_pub_ctx_clear_n(n, public_key);

    return result;
}

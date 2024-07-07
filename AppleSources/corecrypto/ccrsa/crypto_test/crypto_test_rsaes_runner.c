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

#include <corecrypto/cc_priv.h>
#include <corecrypto/ccrsa_priv.h>
#include <corecrypto/ccder.h>
#include <corecrypto/ccsha1.h>
#include <corecrypto/ccsha2.h>

// Checks whether the ciphertext is longer than the modulus but would actually
// fit if we removed leading zeros.
CC_NONNULL_ALL CC_INLINE
bool zeros_prepended_to_ciphertext(const ccrsa_full_ctx_t fk, const byteBuffer ct)
{
    size_t modulusBytes = cc_ceiling(ccrsa_pubkeylength(ccrsa_ctx_public(fk)), 8);

    if (modulusBytes >= ct->len) {
        return false;
    }

    size_t actual_length = ct->len;
    for (size_t i = 0; ct->bytes[i] == 0x00 && i < ct->len; i++) {
        actual_length--;
    }

    return modulusBytes >= actual_length;
}

bool crypto_test_rsaes_runner(ccdict_t vector)
{
    bool result = true;

    STRING_TO_BUFFER(id, cctestvector_key_id);
    STRING_TO_BUFFER(type, cctestvector_key_type);
    STRING_TO_BUFFER(sha, cctestvector_key_sha);
    STRING_TO_BUFFER(mgfSha, cctestvector_key_mgf_sha);
    STRING_TO_BUFFER(keySize, cctestvector_key_key_size);
    HEX_VALUE_TO_BUFFER(key, cctestvector_key_private_key_pkcs8);
    HEX_VALUE_TO_BUFFER(msg, cctestvector_key_msg);
    HEX_VALUE_TO_BUFFER(label, cctestvector_key_label);
    HEX_VALUE_TO_BUFFER(ct, cctestvector_key_ct);

    cc_assert(id && type && keySize && key);

    byteBuffer pt = NULL;
    uint64_t test_result = ccdict_get_uint64(vector, cctestvector_key_valid);

    bool isOAEP = strcmp(type_string, "RsaesOaepDecrypt") == 0;
    cc_assert(sha || !isOAEP);

    const struct ccdigest_info *di = NULL;
    if (sha) {
        di = cctest_parse_digest(sha);
    }

    if (msg == NULL || msg->len == 0 || ct == NULL || (sha && di == NULL) || (isOAEP && mgfSha_string && strcmp(sha_string, mgfSha_string))) {
        RELEASE_BUFFER(id);
        RELEASE_BUFFER(type);
        RELEASE_BUFFER(sha);
        RELEASE_BUFFER(mgfSha);
        RELEASE_BUFFER(keySize);
        RELEASE_BUFFER(key);
        RELEASE_BUFFER(msg);
        RELEASE_BUFFER(label);
        RELEASE_BUFFER(ct);
        return true;
    }

    int result_code = 0;

    size_t der_len = 0;
    const uint8_t *der = key->bytes;
    const uint8_t *der_end = key->bytes + key->len;

    // Peel the PKCS#1 out of its PKCS#8 shell.
    der = ccder_decode_sequence_tl(&der_end, der, der_end);
    uint64_t version;
    der = ccder_decode_uint64(&version, der, der_end);
    (void)ccder_decode_sequence_tl(&der, der, der_end);
    der = ccder_decode_tl(CCDER_OCTET_STRING, &der_len, der, der_end);

    cc_size n = ccrsa_import_priv_n(der_len, der);
    ccrsa_full_ctx_decl_n(n, full_key);
    ccrsa_ctx_n(full_key) = n;
    CC_WYCHEPROOF_CHECK_OP_RESULT(n > 0, result, cleanup);

    result_code = ccrsa_import_priv(full_key, der_len, der);
    CC_WYCHEPROOF_CHECK_OP_RESULT(result_code == CCERR_OK, result, cleanup);

    pt = mallocByteBuffer(ccn_sizeof_n(n));

    if (isOAEP) {
        size_t params_len = label ? label->len : 0;
        const uint8_t *params = label ? label->bytes : NULL;
        result_code = ccrsa_decrypt_oaep(full_key, di, &pt->len, pt->bytes, ct->len, ct->bytes, params_len, params);
        CC_WYCHEPROOF_CHECK_OP_RESULT(result_code == CCERR_OK, result, cleanup);
    } else {
        result_code = ccrsa_decrypt_eme_pkcs1v15(full_key, &pt->len, pt->bytes, ct->len, ct->bytes);
        CC_WYCHEPROOF_CHECK_OP_RESULT(result_code == CCERR_OK, result, cleanup);
    }

    result_code = cc_cmp_safe(CC_MIN(pt->len, msg->len), pt->bytes, msg->bytes);
    CC_WYCHEPROOF_CHECK_OP_RESULT((result_code == 0) && pt->len == msg->len, result, cleanup);

cleanup:
    // Invert the result if the ciphertext is longer than the modulus but fits
    // if we remove leading zeros. We simply ignore zeros that were prepended
    // and decrypt successfully. Wycheproof wants us to fail.
    if (zeros_prepended_to_ciphertext(full_key, ct)) {
        result = !result;
    }

    if (test_result == cctestvector_result_invalid) {
        result = !result;
    }

    if (!result) {
        const char *variant = isOAEP ? "OAEP": "PKCS1v15";
        char hash[9] = { 0 };
        if (isOAEP) {
            snprintf(hash, sizeof(hash), "-%s", sha_string);
        }
        fprintf(stderr, "Test ID %s failed [RSAES-%s-%s%s]\n", id_string, keySize_string, variant, hash);
    }

    RELEASE_BUFFER(id);
    RELEASE_BUFFER(type);
    RELEASE_BUFFER(sha);
    RELEASE_BUFFER(mgfSha);
    RELEASE_BUFFER(key);
    RELEASE_BUFFER(keySize);
    RELEASE_BUFFER(msg);
    RELEASE_BUFFER(label);
    RELEASE_BUFFER(ct);
    free(pt);
    ccrsa_full_ctx_clear_n(n, full_key);

    return result;
}

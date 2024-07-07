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
#include "ccec_internal.h"
#include <corecrypto/ccsha2.h>
#include <corecrypto/ccder.h>

static const char *skipped_wycheproof_tests_BER[] = {
    // We accept BER encoded signatures instead of DER encoded signatures. In this particular
    // case we do not enforce a strict (unique) encoding of the length of the signature
    // values. In the future we should *not* support these.
    "4", "5", "68", "69", "70", "71"
};
static const size_t skipped_wycheproof_tests_BER_len = CC_ARRAY_LEN(skipped_wycheproof_tests_BER);

byteBuffer ccec_test_parse_spki(byteBuffer spki, byteBuffer *algorithmOID, byteBuffer *parameters)
{
    const uint8_t *der = spki->bytes, *der_end = spki->bytes + spki->len;
    size_t len;

    /* pull out key from SPKI
     *
     * SubjectPublicKeyInfo  ::=  SEQUENCE  {
     *   algorithm            AlgorithmIdentifier,
     *   subjectPublicKey     BIT STRING
     * }
     *
     * AlgorithmIdentifier  ::=  SEQUENCE  {
     *   algorithm               OBJECT IDENTIFIER,
     *   parameters              ANY DEFINED BY algorithm OPTIONAL
     *  }
     */

    der = ccder_decode_tl(CCDER_CONSTRUCTED_SEQUENCE, &len, der, der_end);
    if (der == NULL) {
        return NULL;
    }

    { /* AlgorithmIdentifier */
        const uint8_t *ai_der = der, *ai_der_end = der + len;

        ai_der = ccder_decode_tl(CCDER_CONSTRUCTED_SEQUENCE, &len, ai_der, ai_der_end);
        if (ai_der == NULL) {
            return NULL;
        }

        ai_der_end = ai_der + len;

        ai_der = ccder_decode_tl(CCDER_OBJECT_IDENTIFIER, &len, ai_der, ai_der_end);
        if (ai_der == NULL) {
            return NULL;
        }
        if (algorithmOID) {
            *algorithmOID = bytesToBytes(ai_der, len);
        }

        ai_der += len;

        if (ai_der != ai_der_end && parameters) {
            *parameters = bytesToBytes(ai_der, (size_t)(ai_der_end - ai_der));
        }

        der = ai_der_end;
    }

    size_t length_in_bits = 0;
    const uint8_t *spkiBytes = NULL;
    der = ccder_decode_bitstring(&spkiBytes, &length_in_bits, der, der_end);

    byteBuffer subjectPublicKey = bytesToBytes(spkiBytes, (size_t)((length_in_bits + 7) / 8));
    if (der == NULL) {
        return NULL;
    }
    if (der != der_end) {
        return NULL;
    }

    return subjectPublicKey;
}

bool crypto_test_ecdsa_runner(ccdict_t vector)
{
    bool result = true;
    bool ber_test_vector = false;

    STRING_TO_BUFFER(id, cctestvector_key_id);
    STRING_TO_BUFFER(curve, cctestvector_key_curve);
    STRING_TO_BUFFER(sha, cctestvector_key_sha);
    HEX_VALUE_TO_BUFFER(key, cctestvector_key_key_der);
    HEX_VALUE_TO_BUFFER(msg, cctestvector_key_msg);
    HEX_VALUE_TO_BUFFER(signature, cctestvector_key_signature);

    uint64_t test_result = ccdict_get_uint64(vector, cctestvector_key_valid);
    uint64_t flags = ccdict_get_flags(vector, cctestvector_key_flags);
    const struct ccdigest_info *di = NULL;
    if (sha) {
        di = cctest_parse_digest(sha);
    }

    if (curve == NULL || key == NULL || msg == NULL || id == NULL || di == NULL) {
        RELEASE_BUFFER(id);
        RELEASE_BUFFER(key);
        RELEASE_BUFFER(curve);
        RELEASE_BUFFER(sha);
        RELEASE_BUFFER(signature);
        RELEASE_BUFFER(msg);
        return false;
    }

    // Check for skipped tests.
    for (size_t i = 0; i < skipped_wycheproof_tests_BER_len; i++) {
        const char *test_id = skipped_wycheproof_tests_BER[i];
        if (strlen(id_string) == strlen(test_id) && strncmp(test_id, id_string, strlen(test_id)) == 0) {
            ber_test_vector = flags & wycheproof_flag_BER;
        }
    }

    ccec_const_cp_t cp = NULL;
    if (strlen("secp256r1") == curve->len && memcmp(curve->bytes, "secp256r1", curve->len) == 0) {
        cp = ccec_cp_256();
    } else if (strlen("secp224r1") == curve->len && memcmp(curve->bytes, "secp224r1", curve->len) == 0) {
        cp = ccec_cp_224();
    } else if (strlen("secp384r1") == curve->len && memcmp(curve->bytes, "secp384r1", curve->len) == 0) {
        cp = ccec_cp_384();
    } else if (strlen("secp521r1") == curve->len && memcmp(curve->bytes, "secp521r1", curve->len) == 0) {
        cp = ccec_cp_521();
    } else {
        // Unsupported test case
        RELEASE_BUFFER(id);
        RELEASE_BUFFER(key);
        RELEASE_BUFFER(curve);
        RELEASE_BUFFER(sha);
        RELEASE_BUFFER(signature);
        RELEASE_BUFFER(msg);
        return true;
    }

    uint8_t digest[di->output_size];
    ccdigest(di, msg->len, msg->bytes, digest);

    ccec_pub_ctx_decl_cp(cp, publickey);
    ccec_ctx_init(cp, publickey);
    byteBuffer spki_key = ccec_test_parse_spki(key, NULL, NULL);

    bool valid = false;
    bool valid_strict = false;

    int rc = ccec_import_pub(cp, spki_key->len, spki_key->bytes, publickey);
    CC_WYCHEPROOF_CHECK_OP_RESULT(rc == 0, result, cleanup);

    rc = ccec_verify(publickey, di->output_size, digest, signature->len, signature->bytes, &valid);
    int rc_strict = ccec_verify_strict(publickey, di->output_size, digest, signature->len, signature->bytes, &valid_strict);

    if (!ber_test_vector && (valid != valid_strict || ((rc == 0 && rc_strict != 0) || (rc != 0 && rc_strict == 0)))) {
        // Inconsistent results between ccec_verify and ccec_verify_strict, return false;
        RELEASE_BUFFER(id);
        RELEASE_BUFFER(key);
        RELEASE_BUFFER(curve);
        RELEASE_BUFFER(sha);
        RELEASE_BUFFER(signature);
        RELEASE_BUFFER(msg);
        return false;
    }

    if (ber_test_vector) {
        CC_WYCHEPROOF_CHECK_OP_RESULT(rc_strict == 0 && valid_strict, result, cleanup);
    } else {
        CC_WYCHEPROOF_CHECK_OP_RESULT(rc == 0 && valid, result, cleanup);
    }

cleanup:
    // Some test vectors are missing a null byte within the ASN encoding. This means that the values
    // are technically negative and implementations are free to do as they please (accept or reject
    // these values). Since these test vectors are marked as acceptable, it is fine to fail them.
    if (flags & wycheproof_flag_MissingZero) {
        // We flip the result since we expect to fail these otherwise `acceptable` tests
        result = !result;
    }

    if (test_result == cctestvector_result_invalid) {
        result = !result;
    }

    if (!result) {
        fprintf(stderr, "Test ID %s failed\n", id_string);
    }

    RELEASE_BUFFER(id);
    RELEASE_BUFFER(key);
    RELEASE_BUFFER(curve);
    RELEASE_BUFFER(sha);
    RELEASE_BUFFER(signature);
    RELEASE_BUFFER(msg);

    return result;
}

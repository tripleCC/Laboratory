/* Copyright (c) (2019,2022,2023) Apple Inc. All rights reserved.
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
#include "cctest_driver.h"
#include "cctestvector_parser.h"
#include "cctest_runner.h"
#include "ccec448_internal.h"

bool crypto_test_x448_runner(ccdict_t vector)
{
    bool result = true;

    STRING_TO_BUFFER(id, cctestvector_key_id);
    STRING_TO_BUFFER(curve, cctestvector_key_curve);
    HEX_VALUE_TO_BUFFER(public, cctestvector_key_public);
    HEX_VALUE_TO_BUFFER(private, cctestvector_key_private);
    HEX_VALUE_TO_BUFFER(shared, cctestvector_key_shared);

    uint64_t flags = ccdict_get_flags(vector, cctestvector_key_flags);

    if (!(id && curve && public && private && shared)) {
        result = false;
        goto cleanup;
    }

    if (ccdict_get_uint64(vector, cctestvector_key_valid) == cctestvector_result_invalid) {
        result = false;
        goto cleanup;
    }

    if (strlen("curve448") != curve->len || memcmp(curve->bytes, "curve448", curve->len)) {
        RELEASE_BUFFER(id);
        RELEASE_BUFFER(curve);
        RELEASE_BUFFER(public);
        RELEASE_BUFFER(private);
        RELEASE_BUFFER(shared);
        return true;
    }

    struct ccrng_state *rng = ccrng(NULL);
    CC_WYCHEPROOF_CHECK_OP_RESULT(rng != NULL, result, cleanup);

    for (unsigned i = 0; i < CC_ARRAY_LEN(ccec_cp_x448_impls); i++) {
        ccec_const_cp_t cp = ccec_cp_x448_impls[i]();

        ccec448key out;
        int rc = cccurve448_internal(cp, out, private->bytes, public->bytes, rng);
        CC_WYCHEPROOF_CHECK_OP_RESULT(rc == CCERR_OK, result, cleanup);

        rc = memcmp(out, shared->bytes, sizeof(out));
        CC_WYCHEPROOF_CHECK_OP_RESULT(rc == 0, result, cleanup);
    }

cleanup:
    if (flags & wycheproof_flag_ZeroSharedSecret) {
        // Flip the result since we fail these otherwise `acceptable` tests.
        result = !result;
    }

    if (!result) {
        fprintf(stderr, "Test ID %s failed\n", id_string);
    }

    RELEASE_BUFFER(id);
    RELEASE_BUFFER(curve);
    RELEASE_BUFFER(public);
    RELEASE_BUFFER(private);
    RELEASE_BUFFER(shared);

    return result;
}

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

#include <corecrypto/cccmac.h>

bool crypto_test_cmac_runner(ccdict_t vector)
{
    bool result = true;

    HEX_VALUE_TO_BUFFER(id, cctestvector_key_id);
    HEX_VALUE_TO_BUFFER(key, cctestvector_key_key);
    HEX_VALUE_TO_BUFFER(tag, cctestvector_key_tag);
    HEX_VALUE_TO_BUFFER(msg, cctestvector_key_msg);

    uint64_t test_result = ccdict_get_uint64(vector, cctestvector_key_valid);

    uint8_t actual_answer[CMAC_BLOCKSIZE];

    const struct ccmode_cbc *mode = ccaes_cbc_encrypt_mode();

    if (id == NULL) {
        result = false;
        goto cleanup;
    }

    int result_code = cccmac_one_shot_generate(mode,
                                               key ? key->len : 0,
                                               key ? key->bytes : NULL,
                                               msg ? msg->len : 0,
                                               msg ? msg->bytes : NULL,
                                               tag ? tag->len : 0,
                                               actual_answer);
    CC_WYCHEPROOF_CHECK_OP_RESULT(result_code == 0, result, cleanup);
    CC_WYCHEPROOF_CHECK_OP_RESULT(tag == NULL || cc_cmp_safe(tag->len, actual_answer, tag->bytes) == 0, result, cleanup);

cleanup:
    if (test_result == cctestvector_result_invalid) {
        result = !result;
    }

    if (!result) {
        fprintf(stderr, "Test ID %s failed\n", id_string);
    }

    RELEASE_BUFFER(id);
    RELEASE_BUFFER(key);
    RELEASE_BUFFER(tag);
    RELEASE_BUFFER(msg);

    return result;
}

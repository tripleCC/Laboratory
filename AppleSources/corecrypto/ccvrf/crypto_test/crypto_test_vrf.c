/* Copyright (c) (2019,2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "testmore.h"
#include "testbyteBuffer.h"
#include "testccnBuffer.h"

#if (CCVRF == 0)
entryPoint(ccvrf_tests, "ccvrf test")
#else
#include <corecrypto/cc_priv.h>
#include <corecrypto/cc.h>
#include "cc_macros.h"
#include <corecrypto/ccsha2.h>
#include <corecrypto/ccec25519_priv.h>
#include <corecrypto/cc_priv.h>
#include "cc_memory.h"
#include <corecrypto/ccec.h>
#include <corecrypto/ccvrf.h>

#include "ccec_internal.h"

typedef struct {
    const char *secretString;
    const char *msgString;
    const char *proofString;
    const char *outputString;
} ccvrf_test_vector;

static const ccvrf_test_vector ccvrf_test_vectors[] = {
#include "crypto_test_vrf_data.inc"
};

static const size_t ccvrf_test_vectors_len = CC_ARRAY_LEN(ccvrf_test_vectors);

static int
ccvrf_test_prove_verify(void)
{
    struct ccvrf ctx;
    ccvrf_factory_irtfdraft03_default(&ctx);

    for (size_t i = 0; i < ccvrf_test_vectors_len; i++) {
        const ccvrf_test_vector vector = ccvrf_test_vectors[i];

        byteBuffer secretBuffer = hexStringToBytes(vector.secretString);
        byteBuffer msgBuffer = hexStringToBytes(vector.msgString);
        byteBuffer proofBuffer = hexStringToBytes(vector.proofString);
        byteBuffer hashBuffer = hexStringToBytes(vector.outputString);

        uint8_t proof[ccvrf_sizeof_proof(&ctx)];
        int result = ccvrf_prove(&ctx, secretBuffer->len, secretBuffer->bytes, msgBuffer->len, msgBuffer->bytes, sizeof(proof), proof);
        is(result, CCERR_OK, "ccvrf_prove failed");
        ok_memcmp(proof, proofBuffer->bytes, proofBuffer->len, "proof generation failed");

        uint8_t output[ccvrf_sizeof_hash(&ctx)];
        is(ccvrf_proof_to_hash(&ctx, sizeof(proof), proof, sizeof(output), output), CCERR_OK, "ccvrf_proof_to_hash failed");
        ok_memcmp(output, hashBuffer->bytes, hashBuffer->len, "hash generation failed");

        uint8_t pk[ccvrf_sizeof_public_key(&ctx)];
        is(ccvrf_derive_public_key(&ctx, secretBuffer->len, secretBuffer->bytes, sizeof(pk), pk), CCERR_OK, "ccvrf_derive_public_key failed");
        is(ccvrf_verify(&ctx, sizeof(pk), pk, msgBuffer->len, msgBuffer->bytes, sizeof(proof), proof), CCERR_OK, "ccvrf_verify failed");

        // Modify the proof and watch verification fail
        proof[0] ^= 0xFF;
        isnt(ccvrf_verify(&ctx, sizeof(pk), pk, msgBuffer->len, msgBuffer->bytes, sizeof(proof), proof), CCERR_OK, "ccvrf_verify failed");
        proof[0] ^= 0xFF;

        // Modify the message and watch verifiation fail
        if (msgBuffer->len > 0) {
            msgBuffer->bytes[0] += 1;
            isnt(ccvrf_verify(&ctx, sizeof(pk), pk, msgBuffer->len, msgBuffer->bytes, sizeof(proof), proof), CCERR_OK, "ccvrf_verify failed");
            msgBuffer->bytes[0] -= 1;
        }

        // Generate a different public key and watch verification fail
        secretBuffer->bytes[0] ^= 1;
        is(ccvrf_derive_public_key(&ctx, secretBuffer->len, secretBuffer->bytes, sizeof(pk), pk), CCERR_OK, "ccvrf_derive_public_key failed");
        isnt(ccvrf_verify(&ctx, sizeof(pk), pk, msgBuffer->len, msgBuffer->bytes, sizeof(proof), proof), CCERR_OK, "ccvrf_verify failed");

        free(secretBuffer);
        free(msgBuffer);
        free(proofBuffer);
        free(hashBuffer);
    }

    return 1;
}

int
ccvrf_tests(TM_UNUSED int argc, TM_UNUSED char *const *argv)
{
    plan_tests(310);

    ok(ccvrf_test_prove_verify(), "ccvrf_test_prove_verify");

    return 0;
}

#endif // CCECVRF

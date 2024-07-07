/* Copyright (c) (2015,2016,2019,2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */



#include <corecrypto/ccec.h>
#include <corecrypto/ccec_priv.h>
#include <corecrypto/ccrng_test.h>
#include <corecrypto/ccsha1.h>
#include <corecrypto/ccsha2.h>
#include <corecrypto/ccpbkdf2.h>
#include <corecrypto/ccrng_sequence.h>
#include "crypto_test_ec.h"

#include "testmore.h"
#include "testbyteBuffer.h"
#include "testccnBuffer.h"

#include <corecrypto/ccec_priv.h>

#define ECKEYGEN_TEST_SECURE_BACKUP 1

struct cceckeygen_vector {
    ccec_const_cp_t (*cp)(void);
    uint32_t    test_flags;
    uint32_t    flags;
    char        *str_entropy;
    char        *str_salt;
    size_t      iteration_nb;
    char        *str_x963_full_key;
    int         retval;
};

const struct cceckeygen_vector cceckeygen_vectors[]=
{
#include "../test_vectors/eckeygen.inc"
};

static bool
ECKeyGen_KAT_vector(struct ccrng_state * rng,
                 const struct cceckeygen_vector *test_vector)
{
    bool rc=true;
    ccec_const_cp_t cp=test_vector->cp();
    uint32_t test_flags=test_vector->test_flags;
    uint32_t flags=test_vector->flags;
    int expected_retval=test_vector->retval;
    int retval;

    byteBuffer entropy  = hexStringToBytes(test_vector->str_entropy);
    byteBuffer expected_x963_full_key = hexStringToBytes(test_vector->str_x963_full_key);

    ccec_full_ctx_decl_cp(cp, full_key);

    // ------------------------------
    // Generate the Key from entropy
    // ------------------------------
    if (test_flags&ECKEYGEN_TEST_SECURE_BACKUP) {
        size_t drbg_output_size=1024;
        byteBuffer drbg_output = mallocByteBuffer(drbg_output_size);
        byteBuffer salt  = hexStringToBytes(test_vector->str_salt);
        ccpbkdf2_hmac(ccsha256_di(), strlen(test_vector->str_entropy), test_vector->str_entropy,
                      salt->len, salt->bytes,
                      test_vector->iteration_nb,
                      drbg_output->len, drbg_output->bytes);
        retval=ccec_generate_key_deterministic(cp, drbg_output->len, drbg_output->bytes,rng, flags, full_key);
        free(drbg_output);
        free(salt);
    } else {
        retval=ccec_generate_key_deterministic(cp, entropy->len, entropy->bytes, rng, flags, full_key);
    }

    rc&=is(retval,expected_retval, "Return value");

    if (expected_retval==0) {
        uint8_t computed_x963_full_key[ccec_x963_export_size(1,ccec_ctx_pub(full_key))];
        // ------------------------------
        // Export
        // ------------------------------
        rc &= is(ccec_x963_export(1, computed_x963_full_key, full_key), CCERR_OK, "Export full key");

        // ------------------------------
        // Compare
        // ------------------------------
        rc&=is(sizeof(computed_x963_full_key),expected_x963_full_key->len,"Exported key length");
        rc&=ok_memcmp(computed_x963_full_key,expected_x963_full_key->bytes, expected_x963_full_key->len, "Exported key");
        if (!rc) cc_print("exported_key: ",sizeof(computed_x963_full_key),computed_x963_full_key);
    }
    free(entropy);
    free(expected_x963_full_key);
    return rc;
}

static void
ECKeyGen_KAT_Test(struct ccrng_state * rng) {
    for (size_t i = 0; i < CC_ARRAY_LEN(cceckeygen_vectors); i++) {
        ok(ECKeyGen_KAT_vector(rng,&cceckeygen_vectors[i]), "EC key gen KAT, test #%d",i);
    }
}

int
eckeygen_tests(void)
{
    const int verbose=1;
    struct ccrng_state *rng = global_test_rng;

    if(verbose) diag("KAT KeyGen");
    ECKeyGen_KAT_Test(rng);

    return 1;
}

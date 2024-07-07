/* Copyright (c) (2010-2023) Apple Inc. All rights reserved.
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

#if (CCRNG == 0)
entryPoint(ccrng_tests,"ccrng")
#else

#include <corecrypto/ccrng.h>
#include <corecrypto/ccrng_system.h>
#include "ccrng_getentropy.h"
#include "cc_runtime_config.h"
#include "ccrng_rdrand.h"
#include "ccrng_cryptographic.h"
#include <corecrypto/ccrng_drbg.h>
#include <corecrypto/ccrng_sequence.h>
#include <corecrypto/ccrng_pbkdf2_prng.h>
#include <corecrypto/ccrng_test.h>
#include <corecrypto/ccaes.h>
#include <corecrypto/ccsha2.h>
#include "ccrng_cryptographic_priv.h"
#include "ccrng_crypto.h"
#include "ccrng_internal.h"

#include "crypto_test_rng.h"

static int verbose=0;
//==============================================================================
//
//      HELPERS
//
//==============================================================================

static int compare64_t(const void *va, const void *vb) {
    uint64_t a = *((const uint64_t *) va);
    uint64_t b = *((const uint64_t *) vb);
    if(a < b) return -1;
    if(a == b) return 0;
    return 1;
}

int find_duplicate_uint64(uint64_t *array, size_t array_size) {
    qsort(array, array_size, sizeof(uint64_t), compare64_t);
    int rc=1; // success
    for(size_t i = 0; i < (array_size-1); i++) {
        if(verbose) diag("Comparing %d\n", i);
        rc&=ok(array[i] != array[i+1], "items %i and %i are the same:%"PRIx64, i, i+1, array[i]);
    }
    return rc;
}

static int no_repeat(struct ccrng_state *rng) {
    uint64_t results[128];
    int status;

    for(int i = 0; i<128; i++) {
        if(verbose) diag("Creating %d\n", i);
        status = ccrng_generate(rng, 8, &results[i]);
        ok_or_fail(status == 0, "got random bytes");
    }

    return find_duplicate_uint64(results,128);
}

static int zero_length(struct ccrng_state *rng) {
    int status = ccrng_generate(rng, 0, NULL);
    if (status!=0) {
        status=0; // fail
        goto errOut;
    }
    status=1;
errOut:
    return status;
}

static int must_repeat(struct ccrng_state *rng) {
    uint64_t results[2];
    int status;

    status = ccrng_generate(rng, 8, &results[0]);
    ok_or_fail(status == 0, "got bytes");
    status = ccrng_generate(rng, 8, &results[1]);
    ok_or_fail(status == 0, "got bytes");
    ok_or_fail(results[0] == results[1], "results match");
    return 1;
}

static int too_many(struct ccrng_state *rng, size_t limit, size_t split) {
    // Assume that there are "limit" bytes available, no less, no more.
    uint64_t results[limit+1];
    int status;
    size_t done=0;
    for (size_t i=0;i<split;i++) {
        status = ccrng_generate(rng, (size_t)limit/split, &results[0]);
        ok_or_fail(status == 0, "got bytes");
        done+=(size_t)limit/split;
    }
    status = ccrng_generate(rng, (limit-done)+1, &results[0]);
    ok_or_fail(status == CCERR_OUT_OF_ENTROPY, "report lack of bytes"); // Todo: Proper Error code
    return 1;
}

static int must_be(struct ccrng_state *rng, size_t len, char *pattern) {
    uint8_t results[len];
    int status;

    status = ccrng_generate(rng, len, results);
    ok_or_fail(status == 0, "got bytes");


    if(pattern) {
        struct byte_buf resultsByte={len,&results[0]};
        char * got_string = bytesToHexString(&resultsByte);
        eq_string(got_string, pattern, "Results Match");
        free(got_string);
    } else {
        cc_print("Results for must_be - ",len,results);
    }
    return 1;
}

static uint8_t salt[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
static size_t saltlen = sizeof(salt);

#define CCRNG_CRYPTO_TEST_ENTROPY_LENGTH 64

static int crypto_rng_test(void) {
    ccentropy_rng_ctx_t entropy_ctx;
    int err = ccentropy_rng_init(&entropy_ctx,
                                 global_test_rng);
    is(err, CCERR_OK, "crypto rng ccentropy_rng_init");

    ccrng_schedule_constant_ctx_t schedule_ctx;
    ccrng_schedule_constant_init(&schedule_ctx,
                                 CCRNG_SCHEDULE_MUST_RESEED);

    cc_lock_ctx_t lock_ctx;
    err = cc_lock_init(&lock_ctx, "crypto test");
    is(err, CCERR_OK, "crypto rng cc_lock_init");

    ccdrbg_df_bc_ctx_t df_ctx;
    err = ccdrbg_df_bc_init(&df_ctx,
                            ccaes_cbc_encrypt_mode(),
                            32);
    is(err, CCERR_OK, "crypto rng ccdrbg_df_bc_init");

    struct ccdrbg_info drbg_info;
    struct ccdrbg_nistctr_custom drbg_custom = {
        .ctr_info = ccaes_ctr_crypt_mode(),
        .keylen = 32,
        .strictFIPS = 1,
        .df_ctx = &df_ctx.df_ctx,
    };
    ccdrbg_factory_nistctr(&drbg_info, &drbg_custom);

    uint8_t drbg_state[1280];
    struct ccdrbg_state *drbg_ctx = (struct ccdrbg_state *)&drbg_state;

    uint8_t seed[CCRNG_CRYPTO_TEST_ENTROPY_LENGTH];
    err = ccrng_generate(global_test_rng, sizeof(seed), seed);
    is(err, CCERR_OK, "crypto rng ccrng_generate 1");

    uint64_t nonce;
    err = ccrng_generate(global_test_rng, sizeof(nonce), &nonce);
    is(err, CCERR_OK, "crypto rng ccrng_generate 2");

    const char *ps = "crypto test rng";
    err = ccdrbg_init(&drbg_info,
                      drbg_ctx,
                      sizeof(seed),
                      seed,
                      sizeof(nonce),
                      &nonce,
                      sizeof(ps),
                      ps);
    is(err, CCERR_OK, "crypto rng ccdrbg_init");

    uint8_t cache[256];

    ccrng_crypto_ctx_t rng_ctx;

    err = ccrng_crypto_init(&rng_ctx,
                            (ccentropy_ctx_t *)&entropy_ctx,
                            (ccrng_schedule_ctx_t *)&schedule_ctx,
                            &lock_ctx,
                            &drbg_info,
                            drbg_ctx,
                            256,
                            CCRNG_CRYPTO_TEST_ENTROPY_LENGTH,
                            sizeof(cache),
                            cache);
    is(err, CCERR_OK, "crypto rng ccrng_crypto_init");

    ok(no_repeat((struct ccrng_state *)&rng_ctx), "crypto rng no repeat");
    return 0;
}

#if defined(__x86_64__)
#define TEST_RDRAND (CC_HAS_RDRAND())
#else
#define TEST_RDRAND (0)
#endif

//==============================================================================
//
//      Test RNGs one by one
//
//==============================================================================

int ccrng_tests(TM_UNUSED int argc, TM_UNUSED char *const *argv)
{
    int test_system_rng = 1;
    int test_crypto_nist_rng = 1;
    int test_pbkdf2_rng = 1;
    int test_drbg_rng = 1;
    int test_sequence = 1;
    int test_getentropy_rng = 1;
    int test_rdrand_rng = 1;
    int status;

    plan_tests(266116 +
               28 +             // ccrng_schedule
#if CC_GETENTROPY_SUPPORTED
               284 +            // ccrng_getentropy
#endif
               (TEST_RDRAND ? 283 : 0) + // ccrng_rdrand
               264000 + /*N_TEST 250 and 500*/
               2099206 + /* ccrng_uniform tests */
               9         // ccrng_process
               );

    schedule_test();
    fortuna_test_kat();
    crypto_rng_test_kat();
    crypto_rng_test();
    process_rng_test();
    
#if CC_RNG_MULTITHREAD_USER
    pthread_atfork(ccrng_cryptographic_atfork_prepare, ccrng_cryptographic_atfork_parent, ccrng_cryptographic_atfork_child);
#endif

    //==========================================================================
    //
    //      CCRNG_DRBG
    //
    //==========================================================================

    if(test_drbg_rng) {
        if(verbose) diag("Testing drbg rng\n");
        struct ccrng_drbg_state drbg_ctx;
        struct ccdrbg_info info;
        char *expect_result_init;
        char *expect_result_reseed;

        ccdrbg_df_bc_ctx_t df_ctx;
        status = ccdrbg_df_bc_init(&df_ctx,
                                   ccaes_cbc_encrypt_mode(),
                                   16);
        is(status, CCERR_OK, "test_drbg_rng ccdrbg_df_bc_init");

        // DRBG - NIST CTR
        struct ccdrbg_nistctr_custom custom_ctr = {
            .ctr_info = ccaes_ctr_crypt_mode(),
            .keylen = 16,
            .strictFIPS = 0,
            .df_ctx = &df_ctx.df_ctx,
        };

        // DRBG - NIST HMAC
        struct ccdrbg_nisthmac_custom custom_hmac = {
            .di = ccsha256_di(),
            .strictFIPS = 0,
        };

        for (size_t i=0;i<2;i++) {
            switch (i) {
                case 0:
                {
                    ccdrbg_factory_nistctr(&info, &custom_ctr);
                    expect_result_init="0e5bc77112a93a7089420072c7bb4627";
                    expect_result_reseed="4a218a3d3a0d76e77108099993cc4028";
                    break;
                }
                case 1:
                {
                    ccdrbg_factory_nisthmac(&info, &custom_hmac);
                    expect_result_init="65d8e3c527fb85df1a943b1dea7bd647";
                    expect_result_reseed="c8cdc03ade8233b9e5f769a970148561";
                    break;
                }
                default:
                    cc_assert(false); // should never get here
                    expect_result_init=NULL;
                    expect_result_reseed=NULL;
                    break;

            }

            // Actual tests

            // Preferred interface
            struct ccdrbg_state *state = malloc(info.size);
            const char const_seed[]="corecrypto drbg based rng";

            const char drbg_init_salt[]="init 17byte seed";
            const char drbg_reseed_salt[]="reseed 19byte seed";
            status = ccdrbg_init(&info, state,
                                 sizeof(drbg_init_salt), drbg_init_salt,
                                 sizeof(drbg_init_salt), drbg_init_salt,
                                 sizeof(const_seed), const_seed);
            ok(status == 0, "Initialize DRBG");
            status = ccrng_drbg_init_withdrbg(&drbg_ctx, &info, state);
            ok(status == 0, "Make RNG-DRBG context");
            if(status == 0) {
                ok(must_be((struct ccrng_state *)&drbg_ctx, 16, expect_result_init), "Got expected pattern init");
                ok(no_repeat((struct ccrng_state *)&drbg_ctx), "successful generation");

                status = ccdrbg_init(&info, state,
                                     sizeof(drbg_init_salt), drbg_init_salt,
                                     sizeof(drbg_init_salt), drbg_init_salt,
                                     sizeof(const_seed), const_seed);
                ok(status == 0, "Reinitialize DRBG");

                status = ccdrbg_reseed(&info, state, sizeof(drbg_reseed_salt), drbg_reseed_salt, 0, NULL);
                ok(status == 0, "Reseed DRBG");

                ok(must_be((struct ccrng_state *)&drbg_ctx, 16, expect_result_reseed), "Got expected pattern reseed");
                ok(no_repeat((struct ccrng_state *)&drbg_ctx), "successful generation");
                ok(zero_length((struct ccrng_state *)&drbg_ctx), "zero length generation");
            }
            ccdrbg_done(&info, state);

            // Legacy interface
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
            status = ccrng_drbg_init(&drbg_ctx, &info, state, sizeof(drbg_init_salt), drbg_init_salt);
            ok(status == 0, "Made drbg context");
            if(status == 0) {
                ok(must_be((struct ccrng_state *)&drbg_ctx, 16, expect_result_init), "Got expected pattern init");
                ok(no_repeat((struct ccrng_state *)&drbg_ctx), "successful generation");

                status = ccrng_drbg_init(&drbg_ctx, &info, state, sizeof(drbg_init_salt), drbg_init_salt);
                ok(status == 0, "Re-Init drbg context");
                status = ccrng_drbg_reseed(&drbg_ctx, sizeof(drbg_reseed_salt), drbg_reseed_salt, 0, NULL);
                ok(status == 0, "Reseed drbg context");
                ok(must_be((struct ccrng_state *)&drbg_ctx, 16, expect_result_reseed), "Got expected pattern reseed");
                ok(no_repeat((struct ccrng_state *)&drbg_ctx), "successful generation");
                ok(zero_length((struct ccrng_state *)&drbg_ctx), "zero length generation");
            }
            ccrng_drbg_done(&drbg_ctx);
            free(state);
#pragma clang diagnostic pop
        }

    }

    //==========================================================================
    //
    //      ccrng_system (deprecated, use ccrng_cryptographic under the hood)
    //
    //==========================================================================
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    if(test_system_rng) {
        if(verbose) diag("Testing system rng\n");
        struct ccrng_system_state system_ctx;
        status = ccrng_system_init(&system_ctx);
        ok(status >= 0, "Made system_rng context");
        if(status >= 0) {
            struct ccrng_state *crypto_ctx = ccrng(NULL);
            isnt(crypto_ctx, NULL, "Made crypto context");
            if (crypto_ctx) {
                is(system_ctx.generate, crypto_ctx->generate, "System RNG passthrough");
            }
            ccrng_system_done(&system_ctx);
        }
    }
#pragma clang diagnostic pop
    //==========================================================================
    //
    //      ccrng_cryptographic
    //
    //==========================================================================
    if(test_crypto_nist_rng) {

        if(verbose) diag("Testing crypto rng\n");
        struct ccrng_state* crypto_ctx=ccrng(&status);

        ok(status == 0, "Crypto RNG Made crypto context");

        // Test basic no repeatance
        if(status == 0) {
            ok(no_repeat(crypto_ctx), "Crypto RNG successful generation");
        }

        // Generate more than the reseed limit in a single call
        size_t tmp_size = CCDRBG_MAX_REQUEST_SIZE+8;
        uint8_t *tmp = malloc(tmp_size);
        status = ccrng_generate(crypto_ctx, tmp_size, tmp);
        ok_or_fail(status == 0, "Crypto RNG got random bytes");

        // Generate multiple times to trigger prediction_break
        for (size_t i=0;i<10;i++) {
            status = ccrng_generate(crypto_ctx, 10, tmp);
            ok_or_fail(status == 0, "Crypto RNG got random bytes");
        }

        // Thread safe test
        ok(multi_thread_test(crypto_ctx), "Crypto RNG thread safe test");

        // Try again without getting the error code
        crypto_ctx=ccrng(NULL);
        ok(no_repeat(crypto_ctx), "Crypto RNG successful generation");
        free(tmp);
    }

    //==========================================================================
    //
    //      ccrng_getentropy
    //
    //==========================================================================
#if CC_GETENTROPY_SUPPORTED
    if (test_getentropy_rng) {
        ok(no_repeat(&ccrng_getentropy), "getentropy RNG successful generation");
        ok(zero_length(&ccrng_getentropy), "getentropy RNG zero-length generation");

        // getentropy(2) has a max request size of 256. This test
        // exercises the chunking behavior of the RNG wrapper.
        uint8_t buf[257];
        int status = ccrng_generate(&ccrng_getentropy, sizeof(buf), buf);
        is(status, CCERR_OK, "getentropy RNG chunking generation");
    }
#endif /* CC_GETENTROPY_SUPPORTED */

    //==========================================================================
    //
    //      ccrng_rdrand
    //
    //==========================================================================
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunreachable-code"
    if (TEST_RDRAND && test_rdrand_rng) {
        ok(no_repeat(&ccrng_rdrand), "rdrand RNG successful generation");
        ok(zero_length(&ccrng_rdrand), "rdrand RNG zero-length generation");
    }
#pragma clang diagnostic pop

    //==========================================================================
    //
    //      ccrng_pbkdf2
    //
    //==========================================================================
    if(test_pbkdf2_rng) {
        if(verbose) diag("Testing pbkdf2 rng\n");
        struct ccrng_pbkdf2_prng_state pbkdf2rng_ctx;

        status = ccrng_pbkdf2_prng_init(&pbkdf2rng_ctx, 4096,
                                        14, "Test_test_test",
                                        saltlen, salt,
                                        1024);
        ok(status == 0, "Made pbkdf2_rng context");
        if(status == 0) {
            ok(must_be((struct ccrng_state *)&pbkdf2rng_ctx, 16, "7bad1f07c4ff2c9d287974f05cd5ea55"), "Got expected pattern");
            ok(no_repeat((struct ccrng_state *)&pbkdf2rng_ctx), "successful generation");
            ok(zero_length((struct ccrng_state *)&pbkdf2rng_ctx), "zero length generation");
        }

        // Negative testing to limits, one shot
        ok(ccrng_pbkdf2_prng_init(&pbkdf2rng_ctx, 64,
                                        14, "Test_test_test",
                                        saltlen, salt,
                                  10)==0,"Reinit context");
        ok(too_many((struct ccrng_state *)&pbkdf2rng_ctx,64,0), "too many");

        // Negative testing to limits, 2 calls
        ok(ccrng_pbkdf2_prng_init(&pbkdf2rng_ctx, 64,
                                  14, "Test_test_test",
                                  saltlen, salt,
                                  10)==0,"Reinit context");
        ok(too_many((struct ccrng_state *)&pbkdf2rng_ctx,64,1), "too many");

        // Negative testing to limits, 4 calls
        ok(ccrng_pbkdf2_prng_init(&pbkdf2rng_ctx, 64,
                                  14, "Test_test_test",
                                  saltlen, salt,
                                  10)==0,"Reinit context");
        ok(too_many((struct ccrng_state *)&pbkdf2rng_ctx,64,3), "too many");

        // Negative testing, invalid initialization
        ok(ccrng_pbkdf2_prng_init(&pbkdf2rng_ctx, sizeof(pbkdf2rng_ctx.random_buffer)+1,
                                  14, "Test_test_test",
                                  saltlen, salt,
                                  10)==CCERR_PARAMETER,"Reinit context");
        ok(too_many((struct ccrng_state *)&pbkdf2rng_ctx,0,0), "any is too many when init fails");
    }

    //==========================================================================
    //
    //      ccrng_sequence (for testing only)
    //
    //==========================================================================
    if(test_sequence) {
        if(verbose) diag("Testing sequence rng\n");
        struct ccrng_sequence_state sequence_ctx;

        status = ccrng_sequence_init(&sequence_ctx, saltlen, salt);

        ok(status == 0, "Made sequence context");
        if(status == 0) {
            ok(must_repeat((struct ccrng_state *)&sequence_ctx), "successful generation");
            ok(must_be((struct ccrng_state *)&sequence_ctx, saltlen, "000102030405060708090a0b0c0d0e0f"), "Got expected pattern");
            ok(zero_length((struct ccrng_state *)&sequence_ctx), "zero length generation");
        }
    }

    // ccrng_uniform
    ok(test_rng_uniform(), "ccrng_uniform tests");
    return 1;
}
#endif

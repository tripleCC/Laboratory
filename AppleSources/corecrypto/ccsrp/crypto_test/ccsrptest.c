/* Copyright (c) (2012-2016,2018,2019,2021) Apple Inc. All rights reserved.
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

#if (CCSRP == 0)
entryPoint(ccsrp_tests, "ccsrp test")
#else

#include <corecrypto/ccsrp.h>
#include <corecrypto/ccsrp_gp.h>
#include <corecrypto/ccsha1.h>
#include <corecrypto/ccsha2.h>
#include "ccsrp_internal.h"

struct ccsrp_vector {
    const struct ccdigest_info *(*di)(void);
    ccdh_const_gp_t (*gp)(void);
    uint32_t opt;
    const char *U;
    const char *P;
    const char *salt;
    const char *k;
    const char *x;
    const char *v;
    const char *a;
    const char *b;
    const char *A;
    const char *B;
    const char *u;
    const char *S;
    const char *K;
    const char *M;
    const char *HAMK;
};

struct ccsrp_option {
    uint32_t v;
    const char *string;
};

const struct ccsrp_vector ccsrp_vectors[] = {
#include "../test_vectors/srp.inc"
};

/*
 Appendix B.  SRP Test Vectors

 The following test vectors demonstrate calculation of the verifier
 and premaster secret.
 */
static int srp_test_vector(const struct ccsrp_vector *test, struct ccrng_state *rng)
{
    int rc = -1;
    const struct ccdigest_info *di = test->di();
    ccsrp_const_gp_t gp = test->gp();
    const char *I = test->U;
    const char *P = test->P;
    byteBuffer salt = hexStringToBytes(test->salt);
    byteBuffer k = hexStringToBytes(test->k);
    byteBuffer x = hexStringToBytes(test->x);
    byteBuffer v = hexStringToBytes(test->v);
    byteBuffer a = hexStringToBytes(test->a);
    byteBuffer b = hexStringToBytes(test->b);
    byteBuffer A = hexStringToBytes(test->A);
    byteBuffer B = hexStringToBytes(test->B);
    byteBuffer u = hexStringToBytes(test->u);
    byteBuffer S = hexStringToBytes(test->S);
    byteBuffer K = hexStringToBytes(test->K);
    byteBuffer M = hexStringToBytes(test->M);
    byteBuffer HAMK = hexStringToBytes(test->HAMK);
    rc = ccsrp_test_calculations(di,
                                 gp,
                                 rng,
                                 I,
                                 test->opt,
                                 strlen(P),
                                 P,
                                 salt->len,
                                 salt->bytes,
                                 k->len,
                                 k->bytes,
                                 x->len,
                                 x->bytes,
                                 v->len,
                                 v->bytes,
                                 a->len,
                                 a->bytes,
                                 b->len,
                                 b->bytes,
                                 A->len,
                                 A->bytes,
                                 B->len,
                                 B->bytes,
                                 u->len,
                                 u->bytes,
                                 S->len,
                                 S->bytes,
                                 K->len,
                                 K->bytes,
                                 M->len,
                                 M->bytes,
                                 HAMK->len,
                                 HAMK->bytes);
    free(salt);
    free(k);
    free(x);
    free(u);
    free(v);
    free(a);
    free(b);
    free(A);
    free(B);
    free(S);
    free(K);
    free(M);
    free(HAMK);
    return rc;
}

static int verbose = 0;

#define NITER 100
#define TEST_HASH SRP_SHA1
#define TEST_NG SRP_NG_1024

#define SRP_TEST_MAX_SESSION_KEY_LENGTH 96

static int test_srp(const struct ccdigest_info *di,
                    ccsrp_const_gp_t gp,
                    struct ccrng_state *rng,
                    uint32_t option)
{
    ccsrp_ctx_decl(di, gp, client_srp);
    ccsrp_ctx_decl(di, gp, server_srp);
    ccsrp_ctx_init_option(client_srp, di, gp, option, rng);
    ccsrp_ctx_init_option(server_srp, di, gp, option, rng);
    size_t pki_size = ccsrp_ctx_sizeof_n(client_srp);
    const char *username = "testuser";
    const char *password = "password";
    uint8_t salt[64];
    uint8_t verifier[pki_size];
    uint8_t A[pki_size];
    uint8_t B[pki_size];
    uint8_t M[ccsrp_ctx_M_HAMK_size(client_srp)];
    uint8_t bytes_HAMK[ccsrp_ctx_M_HAMK_size(client_srp)];
    size_t client_session_key_length = SRP_TEST_MAX_SESSION_KEY_LENGTH;
    size_t server_session_key_length = SRP_TEST_MAX_SESSION_KEY_LENGTH;
    size_t salt_len, password_len;

    salt_len = 64;

    password_len = strlen(password);

    if (verbose)
        diag("test_srp.0\n");

    ok_or_fail(ccsrp_generate_salt_and_verification(
                   client_srp, rng, username, password_len, password, salt_len, salt, verifier) ==
                   0,
               "Generate Salt and Verifier");

    // Generate a and A
    if (verbose)
        diag("test_srp.2\n");
    ok_or_fail(ccsrp_client_start_authentication(client_srp, rng, A) == 0,
               "Start client authentication");

    // Client sends A to server

    // Generate b and B using A
    if (verbose)
        diag("test_srp.3\n");
    ok_or_fail(ccsrp_server_start_authentication(
                   server_srp, rng, username, salt_len, salt, verifier, A, B) == 0,
               "Verifier SRP-6a safety check");

    // Client uses s and B to generate M to answer challenge
    if (verbose)
        diag("test_srp.4\n");
    ok_or_fail(ccsrp_client_process_challenge(
                   client_srp, username, password_len, password, salt_len, salt, B, M) == 0,
               "User SRP-6a safety check");

    // Verify session key.
    const void *ck = ccsrp_get_session_key(client_srp, &client_session_key_length);
    const void *sk = ccsrp_get_session_key(server_srp, &server_session_key_length);
    ok(ck && sk &&
           ccsrp_get_session_key_length(client_srp) == ccsrp_get_session_key_length(server_srp) &&
           ccsrp_get_session_key_length(client_srp) == client_session_key_length &&
           ccsrp_get_session_key_length(server_srp) == server_session_key_length &&
           memcmp(ck, sk, ccsrp_get_session_key_length(client_srp)) == 0,
       "Session Keys don't match");

    // Verify M was generated correctly - generate HAMK
    if (verbose)
        diag("test_srp.5\n");
    ok_or_fail(ccsrp_server_verify_session(server_srp, M, bytes_HAMK), "User authentication");

    // Client verifies correct HAMK
    if (verbose)
        diag("test_srp.6\n");
    ok_or_fail(ccsrp_client_verify_session(client_srp, bytes_HAMK), "Server Authentication");

    if (verbose)
        diag("test_srp.7\n");
    ok(ccsrp_is_authenticated(client_srp), "Server Authentication");
    ccsrp_ctx_clear(di, gp, client_srp);
    ccsrp_ctx_clear(di, gp, server_srp);
    return 1;
}

#define SRP_OPTION_TEST(t) \
    {                      \
        t, #t              \
    }

int ccsrp_tests(TM_UNUSED int argc, TM_UNUSED char *const *argv)
{
    struct ccrng_state *rng = global_test_rng;
    struct ccsrp_option test_options[] = { SRP_OPTION_TEST(CCSRP_OPTION_SRP6a_HASH),
                                           SRP_OPTION_TEST(CCSRP_OPTION_SRP6a_MGF1),
                                           SRP_OPTION_TEST(CCSRP_OPTION_RFC2945_INTERLEAVED) };

    plan_tests(15 + 3 * 5 * 5 * (8 + 1));
    for (size_t i = 0; i < CC_ARRAY_LEN(ccsrp_vectors); i++) {
        diag("SRP KAT Test %d", i);
        ok(srp_test_vector(&ccsrp_vectors[i], rng) == 0, "SRP KAT Test");
    }
    for (size_t i = 0; i < CC_ARRAY_LEN(test_options); i++) {
        diag("SRP 1024 tests (%s)", test_options[i].string);
        ok(test_srp(ccsha1_di(), ccsrp_gp_rfc5054_1024(), rng, test_options[i].v), "SHA1/GP1024");
        ok(test_srp(ccsha224_di(), ccsrp_gp_rfc5054_1024(), rng, test_options[i].v),
           "SHA224/GP1024");
        ok(test_srp(ccsha256_di(), ccsrp_gp_rfc5054_1024(), rng, test_options[i].v),
           "SHA256/GP1024");
        ok(test_srp(ccsha384_di(), ccsrp_gp_rfc5054_1024(), rng, test_options[i].v),
           "SHA384/GP1024");
        ok(test_srp(ccsha512_di(), ccsrp_gp_rfc5054_1024(), rng, test_options[i].v),
           "SHA512/GP1024");

        diag("SRP 2048 tests (%s)", test_options[i].string);
        ok(test_srp(ccsha1_di(), ccsrp_gp_rfc5054_2048(), rng, test_options[i].v), "SHA1/GP2048");
        ok(test_srp(ccsha224_di(), ccsrp_gp_rfc5054_2048(), rng, test_options[i].v),
           "SHA224/GP2048");
        ok(test_srp(ccsha256_di(), ccsrp_gp_rfc5054_2048(), rng, test_options[i].v),
           "SHA256/GP2048");
        ok(test_srp(ccsha384_di(), ccsrp_gp_rfc5054_2048(), rng, test_options[i].v),
           "SHA384/GP2048");
        ok(test_srp(ccsha512_di(), ccsrp_gp_rfc5054_2048(), rng, test_options[i].v),
           "SHA512/GP2048");
#if CORECRYPTO_HACK_FOR_WINDOWS_DEVELOPMENT
        diag("*skipping tests on Windows");
#else
        diag("SRP 3072 tests (%s)", test_options[i].string);
        ok(test_srp(ccsha1_di(), ccsrp_gp_rfc5054_3072(), rng, test_options[i].v), "SHA1/GP3072");
        ok(test_srp(ccsha224_di(), ccsrp_gp_rfc5054_3072(), rng, test_options[i].v),
           "SHA224/GP3072");
        ok(test_srp(ccsha256_di(), ccsrp_gp_rfc5054_3072(), rng, test_options[i].v),
           "SHA256/GP3072");
        ok(test_srp(ccsha384_di(), ccsrp_gp_rfc5054_3072(), rng, test_options[i].v),
           "SHA384/GP3072");
        ok(test_srp(ccsha512_di(), ccsrp_gp_rfc5054_3072(), rng, test_options[i].v),
           "SHA512/GP3072");

        diag("SRP 4096 tests (%s)", test_options[i].string);
        ok(test_srp(ccsha1_di(), ccsrp_gp_rfc5054_4096(), rng, test_options[i].v), "SHA1/GP4096");
        ok(test_srp(ccsha224_di(), ccsrp_gp_rfc5054_4096(), rng, test_options[i].v),
           "SHA224/GP4096");
        ok(test_srp(ccsha256_di(), ccsrp_gp_rfc5054_4096(), rng, test_options[i].v),
           "SHA256/GP4096");
        ok(test_srp(ccsha384_di(), ccsrp_gp_rfc5054_4096(), rng, test_options[i].v),
           "SHA384/GP4096");
        ok(test_srp(ccsha512_di(), ccsrp_gp_rfc5054_4096(), rng, test_options[i].v),
           "SHA512/GP4096");

        diag("SRP 8192 tests (%s)", test_options[i].string);
        ok(test_srp(ccsha1_di(), ccsrp_gp_rfc5054_8192(), rng, test_options[i].v), "SHA1/GP8192");
        ok(test_srp(ccsha224_di(), ccsrp_gp_rfc5054_8192(), rng, test_options[i].v),
           "SHA224/GP8192");
        ok(test_srp(ccsha256_di(), ccsrp_gp_rfc5054_8192(), rng, test_options[i].v),
           "SHA256/GP8192");
        ok(test_srp(ccsha384_di(), ccsrp_gp_rfc5054_8192(), rng, test_options[i].v),
           "SHA384/GP8192");
        ok(test_srp(ccsha512_di(), ccsrp_gp_rfc5054_8192(), rng, test_options[i].v),
           "SHA512/GP8192");
#endif
    }
    return 0;
}

#endif

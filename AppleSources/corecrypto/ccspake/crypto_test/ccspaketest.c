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

#include <corecrypto/ccspake.h>
#include "ccspake_internal.h"

#include "cc_priv.h"
#include "testmore.h"
#include "testbyteBuffer.h"

#include "ccec_internal.h"
#include <corecrypto/ccsha2.h>

CC_NONNULL_ALL
static void generate_point(ccspake_const_cp_t scp, uint8_t *out)
{
    ccec_const_cp_t cp = ccspake_cp_ec(scp);

    ccec_full_ctx_decl_cp(cp, full);
    ccec_ctx_init(cp, full);

    is(ccecdh_generate_key(cp, global_test_rng, full), CCERR_OK, "generate_point/ccecdh_generate_key");
    is(ccec_export_pub(ccec_ctx_pub(full), out), CCERR_OK, "generate_point/ccec_export_pub");

    ccec_full_ctx_clear_cp(cp, full);
}

CC_NONNULL_ALL
static void generate_w0_w1(ccspake_const_cp_t scp, uint8_t *w0, uint8_t *w1)
{
    struct ccrng_state *rng = global_test_rng;
    size_t w_size = ccspake_sizeof_w(scp);

    ccrng_generate(rng, w_size + 8, w0);
    ccrng_generate(rng, w_size + 8, w1);

    if (scp->var == CCSPAKE_VARIANT_RFC) {
        is(ccspake_reduce_w(scp, w_size + 8, w0, w_size, w0), CCERR_OK, "reduce w0");
        is(ccspake_reduce_w(scp, w_size + 8, w1, w_size, w1), CCERR_OK, "reduce w1");
    } else {
        ok(true, "increase test count");
        ok(true, "increase test count");
    }
}

static void test_2_rtt(ccspake_const_cp_t cp, ccspake_const_mac_t mac)
{
    struct ccrng_state *rng = global_test_rng;

    ccspake_ctx_decl(cp, ctx_p);
    ccspake_ctx_decl(cp, ctx_v);

    size_t w_size = ccspake_sizeof_w(cp);
    size_t pt_size = ccspake_sizeof_point(cp);
    size_t sk_len = mac->di()->output_size / 2;

    uint8_t w0[w_size + 8], w1[w_size + 8];
    generate_w0_w1(cp, w0, w1);

    const uint8_t context[] = "SPAKE2+ Context";

    uint8_t L[pt_size];
    is(ccspake_generate_L(cp, w_size, w1, sizeof(L), L, rng), 0, "Generate L from w1");

    is(ccspake_prover_initialize(ctx_p, cp, mac, rng, sizeof(context) - 1, context, 0, NULL, 0, NULL, w_size, w0, w1), 0, "Initialize SPAKE2+ prover");
    is(ccspake_verifier_initialize(ctx_v, cp, mac, rng, sizeof(context) - 1, context, 0, NULL, 0, NULL, w_size, w0, sizeof(L), L), 0, "Initialize SPAKE2+ verifier");

    uint8_t U[pt_size], V[pt_size];

    // Passing a wrong key share buffer length must fail.
    is(ccspake_kex_generate(ctx_p, pt_size + 1, U),
        CCERR_PARAMETER, "Passing a wrong key share buffer length must fail");

    is(ccspake_kex_generate(ctx_p, sizeof(U), U), 0, "Generate U");
    is(ccspake_kex_generate(ctx_v, sizeof(V), V), 0, "Generate V");

    is(ccspake_kex_process(ctx_p, sizeof(V), V), 0, "Process V");
    is(ccspake_kex_process(ctx_v, sizeof(U), U), 0, "Process U");

    uint8_t mac_p[mac->tag_nbytes], mac_v[mac->tag_nbytes];

    // Passing an invalid tag length must fail.
    isnt(ccspake_mac_compute(ctx_p, sizeof(mac_p) + 1, mac_p), CCERR_OK, "Generate mac_p");

    is(ccspake_mac_compute(ctx_p, sizeof(mac_p), mac_p), 0, "Generate mac_p");
    is(ccspake_mac_compute(ctx_v, sizeof(mac_v), mac_v), 0, "Generate mac_v");

    uint8_t sk_p[sk_len], sk_v[sk_len];

    if (cp->var == CCSPAKE_VARIANT_CCC_V1) {
        // Passing the wrong shared key length must fail.
        is(ccspake_mac_verify_and_get_session_key(ctx_p, sizeof(mac_v), mac_v, sk_len + 1, sk_p),
            CCERR_PARAMETER, "Passing the wrong shared key length must fail");
    } else {
        ok(true, "increase test count");
    }

    // Passing an invalid tag length must fail.
    isnt(ccspake_mac_verify_and_get_session_key(ctx_p, sizeof(mac_v) + 1, mac_v, sizeof(sk_p), sk_p),
        CCERR_OK, "Passing an excessive tag length must fail");

    is(ccspake_mac_verify_and_get_session_key(ctx_p, sizeof(mac_v), mac_v, sizeof(sk_p), sk_p), 0, "Verify mac_v");
    is(ccspake_mac_verify_and_get_session_key(ctx_v, sizeof(mac_p), mac_p, sizeof(sk_v), sk_v), 0, "Verify mac_p");

    ok_memcmp(sk_p, sk_v, sizeof(sk_p), "Shared keys don't match");

    ccspake_ctx_clear(cp, ctx_p);
    ccspake_ctx_clear(cp, ctx_v);
}

static void test_1p5_rtt(ccspake_const_cp_t cp, ccspake_const_mac_t mac)
{
    struct ccrng_state *rng = global_test_rng;

    ccspake_ctx_decl(cp, ctx_p);
    ccspake_ctx_decl(cp, ctx_v);

    size_t w_size = ccspake_sizeof_w(cp);
    size_t pt_size = ccspake_sizeof_point(cp);
    size_t sk_len = mac->di()->output_size / 2;

    uint8_t w0[w_size + 8], w1[w_size + 8];
    generate_w0_w1(cp, w0, w1);

    const uint8_t context[] = "SPAKE2+ Context";

    is(ccspake_prover_initialize(ctx_p, cp, mac, rng, sizeof(context) - 1, context, 0, NULL, 0, NULL, w_size, w0, w1), 0, "Initialize SPAKE2+ prover");

    uint8_t U[pt_size];
    is(ccspake_kex_generate(ctx_p, sizeof(U), U), 0, "Generate U");

    // SEND FLIGHT 1/3

    uint8_t L[pt_size];
    is(ccspake_generate_L(cp, w_size, w1, sizeof(L), L, rng), 0, "Generate L from w1");
    is(ccspake_verifier_initialize(ctx_v, cp, mac, rng, sizeof(context) - 1, context, 0, NULL, 0, NULL, w_size, w0, sizeof(L), L), 0, "Initialize SPAKE2+ verifier");
    is(ccspake_kex_process(ctx_v, sizeof(U), U), 0, "Process U");

    uint8_t V[pt_size];
    is(ccspake_kex_generate(ctx_v, sizeof(V), V), 0, "Generate V");

    uint8_t mac_v[mac->tag_nbytes];
    is(ccspake_mac_compute(ctx_v, sizeof(mac_v), mac_v), 0, "Generate mac_v");

    // SEND FLIGHT 2/3

    is(ccspake_kex_process(ctx_p, sizeof(V), V), 0, "Process V");

    uint8_t sk_p[sk_len];
    is(ccspake_mac_verify_and_get_session_key(ctx_p, sizeof(mac_v), mac_v, sizeof(sk_p), sk_p), 0, "Verify mac_v");

    uint8_t mac_p[mac->tag_nbytes];
    is(ccspake_mac_compute(ctx_p, sizeof(mac_p), mac_p), 0, "Generate mac_p");

    // SEND FLIGHT 3/3

    uint8_t sk_v[sk_len];
    is(ccspake_mac_verify_and_get_session_key(ctx_v, sizeof(mac_p), mac_p, sizeof(sk_v), sk_v), 0, "Verify mac_p");

    ok_memcmp(sk_p, sk_v, sizeof(sk_p), "Shared keys don't match");

    ccspake_ctx_clear(cp, ctx_p);
    ccspake_ctx_clear(cp, ctx_v);
}

static void test_initialize(ccspake_const_cp_t cp, ccspake_const_mac_t mac)
{
    struct ccrng_state *rng = global_test_rng;

    ccspake_ctx_decl(cp, ctx_p);
    ccspake_ctx_decl(cp, ctx_v);

    size_t w_size = ccspake_sizeof_w(cp);
    size_t pt_size = ccspake_sizeof_point(cp);

    uint8_t w0[w_size + 8], w1[w_size + 8];
    generate_w0_w1(cp, w0, w1);

    const uint8_t context[] = "SPAKE2+ RFC";
    const uint8_t id_prover[] = "client";
    const uint8_t id_verifier[] = "server";

    uint8_t L[pt_size];
    is(ccspake_generate_L(cp, w_size, w1, sizeof(L), L, rng), 0, "Generate L from w1");

    // Passing the wrong w1 length must fail.
    is(ccspake_generate_L(cp, w_size + 1, w1, sizeof(L), L, rng),
        CCERR_PARAMETER, "Passing the wrong w1 length must fail");

    // Passing the wrong L length must fail.
    is(ccspake_generate_L(cp, w_size, w1, pt_size + 1, L, rng),
        CCERR_PARAMETER, "Passing the wrong L length must fail");

    // Passing the wrong w length must fail.
    is(ccspake_prover_initialize(ctx_p, cp, mac, rng, sizeof(context) - 1, context, 0, NULL, 0, NULL, w_size + 1, w0, w1),
        CCERR_PARAMETER, "Passing the wrong w length must fail");

    // Passing the wrong w0 length must fail.
    is(ccspake_verifier_initialize(ctx_v, cp, mac, rng, sizeof(context) - 1, context, 0, NULL, 0, NULL, w_size + 1, w0, sizeof(L), L),
        CCERR_PARAMETER, "Passing the wrong w0 length must fail");

    // Passing the wrong L length must fail.
    is(ccspake_verifier_initialize(ctx_v, cp, mac, rng, sizeof(context) - 1, context, 0, NULL, 0, NULL, w_size, w0, pt_size + 1, L),
        CCERR_PARAMETER, "Passing the wrong L length must fail");

    if (cp->var == CCSPAKE_VARIANT_RFC) {
        // Fail when no context is given for RFC variant.
        is(ccspake_prover_initialize(ctx_p, cp, mac, rng,
                                     0, context,
                                     sizeof(id_prover) - 1, id_prover,
                                     sizeof(id_verifier) - 1, id_verifier,
                                     w_size, w0, w1),
            CCERR_PARAMETER, "Initializing prover should fail");

        // Fail when no context is given for RFC variant.
        is(ccspake_verifier_initialize(ctx_v, cp, mac, rng,
                                       0, context,
                                       sizeof(id_prover) - 1, id_prover,
                                       sizeof(id_verifier) - 1, id_verifier,
                                       w_size, w0,
                                       sizeof(L), L),
            CCERR_PARAMETER, "Initializing verifier should fail");

        ok(true, "increase test count");
        ok(true, "increase test count");
    }

    if (cp->var == CCSPAKE_VARIANT_CCC_V1) {
        // Fail when identities are passed to the CCC variant.
        is(ccspake_prover_initialize(ctx_p, cp, mac, rng,
                                     sizeof(context) - 1, context,
                                     sizeof(id_prover) - 1, id_prover,
                                     sizeof(id_verifier) - 1, id_verifier,
                                     w_size, w0, w1),
            CCERR_PARAMETER, "Initializing prover should fail");

        // Fail when identities are passed to the CCC variant.
        is(ccspake_verifier_initialize(ctx_v, cp, mac, rng,
                                       sizeof(context) - 1, context,
                                       sizeof(id_prover) - 1, id_prover,
                                       sizeof(id_verifier) - 1, id_verifier,
                                       w_size, w0,
                                       sizeof(L), L),
            CCERR_PARAMETER, "Initializing verifier should fail");

        // Passing an excessive AAD length must fail.
        is(ccspake_prover_initialize(ctx_p, cp, mac, rng, sizeof(ctx_p->aad) + 1, context, 0, NULL, 0, NULL, w_size, w0, w1),
            CCERR_PARAMETER, "Passing an excessive AAD length must fail");

        // Passing an excessive AAD length must fail.
        is(ccspake_verifier_initialize(ctx_v, cp, mac, rng, sizeof(ctx_v->aad) + 1, context, 0, NULL, 0, NULL, w_size, w0, sizeof(L), L),
            CCERR_PARAMETER, "Passing an excessive AAD length must fail");
    }
}

static void test_identities(ccspake_const_cp_t cp, ccspake_const_mac_t mac)
{
    struct ccrng_state *rng = global_test_rng;
    const struct ccdigest_info *di = mac->di();

    ccspake_ctx_decl(cp, ctx_p);
    ccspake_ctx_decl(cp, ctx_v);

    size_t w_size = ccspake_sizeof_w(cp);
    size_t pt_size = ccspake_sizeof_point(cp);

    uint8_t w0[w_size + 8], w1[w_size + 8];
    generate_w0_w1(cp, w0, w1);

    const uint8_t context[] = "SPAKE2+ RFC";
    const uint8_t id_prover[] = "client";
    const uint8_t id_verifier[] = "server";

    is(ccspake_prover_initialize(ctx_p, cp, mac, rng,
                                 sizeof(context) - 1, context,
                                 sizeof(id_prover) - 1, id_prover,
                                 sizeof(id_verifier) - 1, id_verifier,
                                 w_size, w0, w1), 0, "Initialize SPAKE2+ prover");

    uint8_t L[pt_size];
    is(ccspake_generate_L(cp, w_size, w1, sizeof(L), L, rng), 0, "Generate L from w1");
    is(ccspake_verifier_initialize(ctx_v, cp, mac, rng,
                                   sizeof(context) - 1, context,
                                   sizeof(id_prover) - 1, id_prover,
                                   sizeof(id_verifier) - 1, id_verifier,
                                   w_size, w0,
                                   sizeof(L), L), 0, "Initialize SPAKE2+ verifier");

    uint8_t U[pt_size], V[pt_size];
    is(ccspake_kex_generate(ctx_p, sizeof(U), U), 0, "Generate U");
    is(ccspake_kex_generate(ctx_v, sizeof(V), V), 0, "Generate V");

    is(ccspake_kex_process(ctx_p, sizeof(V), V), 0, "Process V");
    is(ccspake_kex_process(ctx_v, sizeof(U), U), 0, "Process U");

    uint8_t mac_p[mac->tag_nbytes], mac_v[mac->tag_nbytes];
    is(ccspake_mac_compute(ctx_p, sizeof(mac_p), mac_p), 0, "Generate mac_p");
    is(ccspake_mac_compute(ctx_v, sizeof(mac_v), mac_v), 0, "Generate mac_v");

    uint8_t sk_p[di->output_size], sk_v[di->output_size];
    is(ccspake_mac_verify_and_get_session_key(ctx_p, sizeof(mac_v), mac_v, sizeof(sk_p), sk_p), 0, "Verify mac_v");
    is(ccspake_mac_verify_and_get_session_key(ctx_v, sizeof(mac_p), mac_p, sizeof(sk_v), sk_v), 0, "Verify mac_p");

    ok_memcmp(sk_p, sk_v, sizeof(sk_p), "Shared keys don't match");

    ccspake_ctx_clear(cp, ctx_p);
    ccspake_ctx_clear(cp, ctx_v);
}

static void test_identities_mismatch(ccspake_const_cp_t cp, ccspake_const_mac_t mac)
{
    struct ccrng_state *rng = global_test_rng;
    const struct ccdigest_info *di = mac->di();

    ccspake_ctx_decl(cp, ctx_p);
    ccspake_ctx_decl(cp, ctx_v);

    size_t w_size = ccspake_sizeof_w(cp);
    size_t pt_size = ccspake_sizeof_point(cp);

    uint8_t w0[w_size + 8], w1[w_size + 8];
    generate_w0_w1(cp, w0, w1);

    const uint8_t context[] = "SPAKE2+ RFC";
    const uint8_t id_prover[] = "client";
    const uint8_t id_verifier[] = "server";
    const uint8_t id_verifier2[] = "servuh";

    is(ccspake_prover_initialize(ctx_p, cp, mac, rng,
                                 sizeof(context) - 1, context,
                                 sizeof(id_prover) - 1, id_prover,
                                 sizeof(id_verifier) - 1, id_verifier,
                                 w_size, w0, w1), 0, "Initialize SPAKE2+ prover");

    uint8_t L[pt_size];
    is(ccspake_generate_L(cp, w_size, w1, sizeof(L), L, rng), 0, "Generate L from w1");
    is(ccspake_verifier_initialize(ctx_v, cp, mac, rng,
                                   sizeof(context) - 1, context,
                                   sizeof(id_prover) - 1, id_prover,
                                   sizeof(id_verifier2) - 1, id_verifier2,
                                   w_size, w0,
                                   sizeof(L), L), 0, "Initialize SPAKE2+ verifier");

    uint8_t U[pt_size], V[pt_size];
    is(ccspake_kex_generate(ctx_p, sizeof(U), U), 0, "Generate U");
    is(ccspake_kex_generate(ctx_v, sizeof(V), V), 0, "Generate V");

    is(ccspake_kex_process(ctx_p, sizeof(V), V), 0, "Process V");
    is(ccspake_kex_process(ctx_v, sizeof(U), U), 0, "Process U");

    uint8_t mac_p[mac->tag_nbytes], mac_v[mac->tag_nbytes];
    is(ccspake_mac_compute(ctx_p, sizeof(mac_p), mac_p), 0, "Generate mac_p");
    is(ccspake_mac_compute(ctx_v, sizeof(mac_v), mac_v), 0, "Generate mac_v");

    uint8_t sk_p[di->output_size], sk_v[di->output_size];
    isnt(ccspake_mac_verify_and_get_session_key(ctx_p, sizeof(mac_v), mac_v, sizeof(sk_p), sk_p), 0, "Verify mac_v should fail");
    isnt(ccspake_mac_verify_and_get_session_key(ctx_v, sizeof(mac_p), mac_p, sizeof(sk_v), sk_v), 0, "Verify mac_p should fail");

    ccspake_ctx_clear(cp, ctx_p);
    ccspake_ctx_clear(cp, ctx_v);
}

static void test_bogus_points(ccspake_const_cp_t cp)
{
    struct ccrng_state *rng = global_test_rng;

    ccspake_ctx_decl(cp, ctx);
    ccspake_const_mac_t mac = ccspake_mac_hkdf_hmac_sha256();

    size_t w_size = ccspake_sizeof_w(cp);
    size_t pt_size = ccspake_sizeof_point(cp);

    uint8_t w0[w_size + 8], w1[w_size + 8];
    generate_w0_w1(cp, w0, w1);

    const uint8_t context[] = "SPAKE2+ Context";

    uint8_t L[pt_size];
    is(ccspake_generate_L(cp, w_size, w1, sizeof(L), L, rng), 0, "Generate L from w1");

    // Reject points that are not on the curve.
    uint8_t B1[pt_size], B2[pt_size];

    memcpy(B1, L, pt_size); // B1 = L with altered y coefficient
    B1[pt_size - 1] ^= 0x55;
    is(ccspake_verifier_initialize(ctx, cp, mac, rng, sizeof(context) - 1, context, 0, NULL, 0, NULL, w_size, w0, sizeof(B1), B1), CCERR_PARAMETER,
               "Initialize SPAKE2+ verifier should fail");

    B2[0] = 0x04; // B2 = (0, 0)
    cc_clear(pt_size - 1, B2 + 1);
    is(ccspake_verifier_initialize(ctx, cp, mac, rng, sizeof(context) - 1, context, 0, NULL, 0, NULL, w_size, w0, sizeof(B2), B2), CCERR_PARAMETER,
               "Initialize SPAKE2+ verifier should fail");

    // Reject the point at infinity.
    uint8_t Z[] = {0};
    is(ccspake_verifier_initialize(ctx, cp, mac, rng, sizeof(context) - 1, context, 0, NULL, 0, NULL, w_size, w0, sizeof(Z), Z), CCERR_PARAMETER,
               "Initialize SPAKE2+ verifier should fail");

    is(ccspake_verifier_initialize(ctx, cp, mac, rng, sizeof(context) - 1, context, 0, NULL, 0, NULL, w_size, w0, sizeof(L), L), 0, "Initialize SPAKE2+ verifier");

    uint8_t V[pt_size];
    is(ccspake_kex_generate(ctx, sizeof(V), V), 0, "Generate V");

    // We shouldn't get the same point back.
    is(ccspake_kex_process(ctx, sizeof(V), V), CCERR_PARAMETER, "Process V should fail");

    // Reject points that aren't on the curve.
    is(ccspake_kex_process(ctx, sizeof(B1), B1), CCERR_PARAMETER, "Process B1 should fail");
    is(ccspake_kex_process(ctx, sizeof(B2), B2), CCERR_PARAMETER, "Process B2 should fail");

    // Reject the point at infinity.
    is(ccspake_kex_process(ctx, sizeof(Z), Z), CCERR_PARAMETER, "Process Z should fail");

    // Reject invalid point lengths.
    is(ccspake_kex_process(ctx, sizeof(B1) - 1, B1), CCERR_PARAMETER, "Process B1-1 should fail");

    ccspake_ctx_clear(cp, ctx);
}

static void test_mac_mismatch(ccspake_const_cp_t cp, ccspake_const_mac_t mac)
{
    struct ccrng_state *rng = global_test_rng;

    ccspake_ctx_decl(cp, ctx_p);
    ccspake_ctx_decl(cp, ctx_v);

    size_t w_size = ccspake_sizeof_w(cp);
    size_t pt_size = ccspake_sizeof_point(cp);

    uint8_t w0[w_size + 8], w1[w_size + 8];
    generate_w0_w1(cp, w0, w1);

    const uint8_t context[] = "SPAKE2+ Context";

    uint8_t L[pt_size];
    is(ccspake_generate_L(cp, w_size, w1, sizeof(L), L, rng), 0, "Generate L from w1");

    is(ccspake_prover_initialize(ctx_p, cp, mac, rng, sizeof(context) - 1, context, 0, NULL, 0, NULL, w_size, w0, w1), 0, "Initialize SPAKE2+ prover");
    is(ccspake_verifier_initialize(ctx_v, cp, mac, rng, sizeof(context) - 1, context, 0, NULL, 0, NULL, w_size, w0, sizeof(L), L), 0, "Initialize SPAKE2+ verifier");

    uint8_t U[pt_size], V[pt_size];
    is(ccspake_kex_generate(ctx_p, sizeof(U), U), 0, "Generate U");
    is(ccspake_kex_generate(ctx_v, sizeof(V), V), 0, "Generate V");

    is(ccspake_kex_process(ctx_p, sizeof(V), V), 0, "Process V");
    is(ccspake_kex_process(ctx_v, sizeof(U), U), 0, "Process U");

    uint8_t mac_p[mac->tag_nbytes], mac_v[mac->tag_nbytes];
    is(ccspake_mac_compute(ctx_p, sizeof(mac_p), mac_p), 0, "Generate mac_p");
    is(ccspake_mac_compute(ctx_v, sizeof(mac_v), mac_v), 0, "Generate mac_v");

    mac_p[mac->tag_nbytes - 1] ^= 0x55;
    mac_v[mac->tag_nbytes - 1] ^= 0x55;

    uint8_t sk_p[16], sk_v[16];
    isnt(ccspake_mac_verify_and_get_session_key(ctx_p, sizeof(mac_v), mac_v, sizeof(sk_p), sk_p), 0, "Verify mac_v should fail");
    isnt(ccspake_mac_verify_and_get_session_key(ctx_v, sizeof(mac_p), mac_p, sizeof(sk_v), sk_v), 0, "Verify mac_p should fail");

    ccspake_ctx_clear(cp, ctx_p);
    ccspake_ctx_clear(cp, ctx_v);
}

static void test_w0_mismatch(ccspake_const_cp_t cp, ccspake_const_mac_t mac)
{
    struct ccrng_state *rng = global_test_rng;

    ccspake_ctx_decl(cp, ctx_p);
    ccspake_ctx_decl(cp, ctx_v);

    size_t w_size = ccspake_sizeof_w(cp);
    size_t pt_size = ccspake_sizeof_point(cp);

    uint8_t w0[w_size + 8], w1[w_size + 8];
    generate_w0_w1(cp, w0, w1);

    const uint8_t context[] = "SPAKE2+ Context";

    uint8_t L[pt_size];
    is(ccspake_generate_L(cp, w_size, w1, sizeof(L), L, rng), 0, "Generate L from w1");

    is(ccspake_prover_initialize(ctx_p, cp, mac, rng, sizeof(context) - 1, context, 0, NULL, 0, NULL, w_size, w0, w1), 0, "Initialize SPAKE2+ prover");

    w0[w_size - 1] ^= 0x55;
    is(ccspake_verifier_initialize(ctx_v, cp, mac, rng, sizeof(context) - 1, context, 0, NULL, 0, NULL, w_size, w0, sizeof(L), L), 0, "Initialize SPAKE2+ verifier");

    uint8_t U[pt_size], V[pt_size];
    is(ccspake_kex_generate(ctx_p, sizeof(U), U), 0, "Generate U");
    is(ccspake_kex_generate(ctx_v, sizeof(V), V), 0, "Generate V");

    is(ccspake_kex_process(ctx_p, sizeof(V), V), 0, "Process V");
    is(ccspake_kex_process(ctx_v, sizeof(U), U), 0, "Process U");

    uint8_t mac_p[mac->tag_nbytes], mac_v[mac->tag_nbytes];
    is(ccspake_mac_compute(ctx_p, sizeof(mac_p), mac_p), 0, "Generate mac_p");
    is(ccspake_mac_compute(ctx_v, sizeof(mac_v), mac_v), 0, "Generate mac_v");

    uint8_t sk_p[16], sk_v[16];
    isnt(ccspake_mac_verify_and_get_session_key(ctx_p, sizeof(mac_v), mac_v, sizeof(sk_p), sk_p), 0, "Verify mac_v should fail");
    isnt(ccspake_mac_verify_and_get_session_key(ctx_v, sizeof(mac_p), mac_p, sizeof(sk_v), sk_v), 0, "Verify mac_p should fail");

    ccspake_ctx_clear(cp, ctx_p);
    ccspake_ctx_clear(cp, ctx_v);
}

static void test_w1_mismatch(ccspake_const_cp_t cp, ccspake_const_mac_t mac)
{
    struct ccrng_state *rng = global_test_rng;

    ccspake_ctx_decl(cp, ctx_p);
    ccspake_ctx_decl(cp, ctx_v);

    size_t w_size = ccspake_sizeof_w(cp);
    size_t pt_size = ccspake_sizeof_point(cp);

    uint8_t w0[w_size + 8], w1[w_size + 8];
    generate_w0_w1(cp, w0, w1);

    const uint8_t context[] = "SPAKE2+ Context";

    uint8_t L[pt_size];
    is(ccspake_generate_L(cp, w_size, w1, sizeof(L), L, rng), 0, "Generate L from w1");

    w1[w_size - 1] ^= 0x55;
    is(ccspake_prover_initialize(ctx_p, cp, mac, rng, sizeof(context) - 1, context, 0, NULL, 0, NULL, w_size, w0, w1), 0, "Initialize SPAKE2+ prover");
    is(ccspake_verifier_initialize(ctx_v, cp, mac, rng, sizeof(context) - 1, context, 0, NULL, 0, NULL, w_size, w0, sizeof(L), L), 0, "Initialize SPAKE2+ verifier");

    uint8_t U[pt_size], V[pt_size];
    is(ccspake_kex_generate(ctx_p, sizeof(U), U), 0, "Generate U");
    is(ccspake_kex_generate(ctx_v, sizeof(V), V), 0, "Generate V");

    is(ccspake_kex_process(ctx_p, sizeof(V), V), 0, "Process V");
    is(ccspake_kex_process(ctx_v, sizeof(U), U), 0, "Process U");

    uint8_t mac_p[mac->tag_nbytes], mac_v[mac->tag_nbytes];
    is(ccspake_mac_compute(ctx_p, sizeof(mac_p), mac_p), 0, "Generate mac_p");
    is(ccspake_mac_compute(ctx_v, sizeof(mac_v), mac_v), 0, "Generate mac_v");

    uint8_t sk_p[16], sk_v[16];
    isnt(ccspake_mac_verify_and_get_session_key(ctx_p, sizeof(mac_v), mac_v, sizeof(sk_p), sk_p), 0, "Verify mac_v should fail");
    isnt(ccspake_mac_verify_and_get_session_key(ctx_v, sizeof(mac_p), mac_p, sizeof(sk_v), sk_v), 0, "Verify mac_p should fail");

    ccspake_ctx_clear(cp, ctx_p);
    ccspake_ctx_clear(cp, ctx_v);
}

static void test_context_mismatch(ccspake_const_cp_t cp, ccspake_const_mac_t mac)
{
    struct ccrng_state *rng = global_test_rng;

    ccspake_ctx_decl(cp, ctx_p);
    ccspake_ctx_decl(cp, ctx_v);

    size_t w_size = ccspake_sizeof_w(cp);
    size_t pt_size = ccspake_sizeof_point(cp);

    uint8_t w0[w_size + 8], w1[w_size + 8];
    generate_w0_w1(cp, w0, w1);

    const uint8_t context1[] = "SPAKE2+ Context 1";
    const uint8_t context2[] = "SPAKE2+ Context 2";

    is(ccspake_prover_initialize(ctx_p, cp, mac, rng,
                                 sizeof(context1) - 1, context1, 0, NULL, 0, NULL,
                                 w_size, w0, w1), 0, "Initialize SPAKE2+ prover");

    uint8_t L[pt_size];
    is(ccspake_generate_L(cp, w_size, w1, sizeof(L), L, rng), 0, "Generate L from w1");
    is(ccspake_verifier_initialize(ctx_v, cp, mac, rng,
                                   sizeof(context2) - 1, context2, 0, NULL, 0, NULL,
                                   w_size, w0, sizeof(L), L), 0, "Initialize SPAKE2+ verifier");

    uint8_t U[pt_size], V[pt_size];
    is(ccspake_kex_generate(ctx_p, sizeof(U), U), 0, "Generate U");
    is(ccspake_kex_generate(ctx_v, sizeof(V), V), 0, "Generate V");

    is(ccspake_kex_process(ctx_p, sizeof(V), V), 0, "Process V");
    is(ccspake_kex_process(ctx_v, sizeof(U), U), 0, "Process U");

    uint8_t mac_p[mac->tag_nbytes], mac_v[mac->tag_nbytes];
    is(ccspake_mac_compute(ctx_p, sizeof(mac_p), mac_p), 0, "Generate mac_p");
    is(ccspake_mac_compute(ctx_v, sizeof(mac_v), mac_v), 0, "Generate mac_v");

    uint8_t sk_p[16], sk_v[16];
    isnt(ccspake_mac_verify_and_get_session_key(ctx_p, sizeof(mac_v), mac_v, sizeof(sk_p), sk_p), 0, "Verify mac_v should fail");
    isnt(ccspake_mac_verify_and_get_session_key(ctx_v, sizeof(mac_p), mac_p, sizeof(sk_v), sk_v), 0, "Verify mac_p should fail");

    ccspake_ctx_clear(cp, ctx_p);
    ccspake_ctx_clear(cp, ctx_v);
}

static void test_bogus_kex(ccspake_const_cp_t cp, ccspake_const_mac_t mac)
{
    struct ccrng_state *rng = global_test_rng;

    ccspake_ctx_decl(cp, ctx_p);
    ccspake_ctx_decl(cp, ctx_v);

    size_t w_size = ccspake_sizeof_w(cp);
    size_t pt_size = ccspake_sizeof_point(cp);

    uint8_t w0[w_size + 8], w1[w_size + 8];
    generate_w0_w1(cp, w0, w1);

    const uint8_t context[] = "SPAKE2+ Context";

    uint8_t L[pt_size];
    is(ccspake_generate_L(cp, w_size, w1, sizeof(L), L, rng), 0, "Generate L from w1");

    is(ccspake_prover_initialize(ctx_p, cp, mac, rng, sizeof(context) - 1, context, 0, NULL, 0, NULL, w_size, w0, w1), 0, "Initialize SPAKE2+ prover");
    is(ccspake_verifier_initialize(ctx_v, cp, mac, rng, sizeof(context) - 1, context, 0, NULL, 0, NULL, w_size, w0, sizeof(L), L), 0, "Initialize SPAKE2+ verifier");

    uint8_t U[pt_size], V[pt_size];
    is(ccspake_kex_generate(ctx_p, sizeof(U), U), 0, "Generate U");
    is(ccspake_kex_generate(ctx_v, sizeof(V), V), 0, "Generate V");

    generate_point(cp, V);

    is(ccspake_kex_process(ctx_p, sizeof(V), V), 0, "Process V");
    is(ccspake_kex_process(ctx_v, sizeof(U), U), 0, "Process U");

    uint8_t mac_p[mac->tag_nbytes], mac_v[mac->tag_nbytes];
    is(ccspake_mac_compute(ctx_p, sizeof(mac_p), mac_p), 0, "Generate mac_p");
    is(ccspake_mac_compute(ctx_v, sizeof(mac_v), mac_v), 0, "Generate mac_v");

    uint8_t sk_p[16], sk_v[16];
    isnt(ccspake_mac_verify_and_get_session_key(ctx_p, sizeof(mac_v), mac_v, sizeof(sk_p), sk_p), 0, "Verify mac_v should fail");
    isnt(ccspake_mac_verify_and_get_session_key(ctx_v, sizeof(mac_p), mac_p, sizeof(sk_v), sk_v), 0, "Verify mac_p should fail");

    ccspake_ctx_clear(cp, ctx_p);
    ccspake_ctx_clear(cp, ctx_v);
}

static void test_state_machine(void)
{
    ccspake_const_cp_t cp = ccspake_cp_256();
    struct ccrng_state *rng = global_test_rng;

    ccspake_ctx_decl(cp, ctx_p);
    ccspake_ctx_decl(cp, ctx_v);

    ccspake_const_mac_t mac = ccspake_mac_hkdf_hmac_sha256();

    size_t w_size = ccspake_sizeof_w(cp);
    size_t pt_size = ccspake_sizeof_point(cp);

    uint8_t w0[w_size], w1[w_size];
    ccrng_generate(rng, sizeof(w0), w0);
    ccrng_generate(rng, sizeof(w1), w1);

    uint8_t aad[16];
    ccrng_generate(rng, sizeof(aad), aad);

    uint8_t L[pt_size];
    is(ccspake_generate_L(cp, sizeof(w1), w1, sizeof(L), L, rng), 0, "Generate L from w1");

    is(ccspake_prover_init(ctx_p, cp, mac, rng, sizeof(aad), aad, sizeof(w0), w0, w1), 0, "Initialize SPAKE2+ prover");
    is(ccspake_verifier_init(ctx_v, cp, mac, rng, sizeof(aad), aad, sizeof(w0), w0, sizeof(L), L), 0, "Initialize SPAKE2+ verifier");

    // P=STATE_INIT, V=STATE_INIT

    uint8_t U[pt_size];
    is(ccspake_kex_generate(ctx_p, sizeof(U), U), 0, "Generate U");
    is(ccspake_kex_generate(ctx_p, sizeof(U), U), CCERR_CALL_SEQUENCE, "Generate U twice should fail");
    is(ccspake_kex_process(ctx_v, sizeof(U), U), 0, "Process U");
    is(ccspake_kex_process(ctx_v, sizeof(U), U), CCERR_CALL_SEQUENCE, "Process U twice should fail");

    // P=STATE_KEX_GENERATE, V=STATE_KEX_PROCESS

    uint8_t mac_p[mac->tag_nbytes], mac_v[mac->tag_nbytes];
    is(ccspake_mac_compute(ctx_p, sizeof(mac_p), mac_p), CCERR_CALL_SEQUENCE, "Generate mac_p should fail");
    is(ccspake_mac_compute(ctx_v, sizeof(mac_v), mac_v), CCERR_CALL_SEQUENCE, "Generate mac_v should fail");

    uint8_t sk_p[16], sk_v[16];
    is(ccspake_mac_verify_and_get_session_key(ctx_p, sizeof(mac_v), mac_v, sizeof(sk_p), sk_p), CCERR_CALL_SEQUENCE, "Verify mac_v should fail");
    is(ccspake_mac_verify_and_get_session_key(ctx_v, sizeof(mac_p), mac_p, sizeof(sk_v), sk_v), CCERR_CALL_SEQUENCE, "Verify mac_p should fail");

    uint8_t V[pt_size];
    is(ccspake_kex_generate(ctx_v, sizeof(V), V), 0, "Generate V");
    isnt(ccspake_kex_generate(ctx_v, sizeof(V), V), 0, "Generate V twice should fail");
    is(ccspake_kex_process(ctx_p, sizeof(V), V), 0, "Process V");
    isnt(ccspake_kex_process(ctx_p, sizeof(V), V), 0, "Process V twice should fail");

    // P=STATE_KEX_BOTH, V=STATE_KEX_BOTH

    is(ccspake_mac_compute(ctx_p, sizeof(mac_p), mac_p), 0, "Generate mac_p");
    is(ccspake_mac_compute(ctx_p, sizeof(mac_p), mac_p), CCERR_CALL_SEQUENCE, "Generate mac_p twice should fail");
    is(ccspake_mac_verify_and_get_session_key(ctx_v, sizeof(mac_p), mac_p, sizeof(sk_v), sk_v), 0, "Verify mac_p");
    is(ccspake_mac_verify_and_get_session_key(ctx_v, sizeof(mac_p), mac_p, sizeof(sk_v), sk_v), CCERR_CALL_SEQUENCE, "Verify mac_p twice should fail");

    // P=STATE_MAC_GENERATE, V=STATE_MAC_VERIFY

    is(ccspake_mac_compute(ctx_v, sizeof(mac_v), mac_v), 0, "Generate mac_v");
    is(ccspake_mac_compute(ctx_v, sizeof(mac_v), mac_v), CCERR_CALL_SEQUENCE, "Generate mac_v twice should fail");
    is(ccspake_mac_verify_and_get_session_key(ctx_p, sizeof(mac_v), mac_v, sizeof(sk_p), sk_p), 0, "Verify mac_v");
    is(ccspake_mac_verify_and_get_session_key(ctx_p, sizeof(mac_v), mac_v, sizeof(sk_p), sk_p), CCERR_CALL_SEQUENCE, "Verify mac_v twice should fail");

    // P=STATE_MAC_BOTH, V=STATE_MAC_BOTH

    ok_memcmp(sk_p, sk_v, sizeof(sk_p), "MACs don't match");

    ccspake_ctx_clear(cp, ctx_p);
    ccspake_ctx_clear(cp, ctx_v);
}

static void iterated_hash(const struct ccdigest_info *di, size_t seed_len, const uint8_t *seed, size_t n, uint8_t *out)
{
    ccdigest(di, seed_len, seed, out);

    for (size_t i = 1; i < n; i++) {
        ccdigest(di, di->output_size, out, out);
    }
}

static void bighash(size_t seed_len, const uint8_t *seed, uint16_t start, size_t sz, uint8_t *out)
{
    const struct ccdigest_info *di = ccsha256_di();

    size_t n = cc_ceiling(sz, di->output_size);
    uint8_t digest[di->output_size];

    for (size_t i = 0; i < n - 1; i++) {
        iterated_hash(di, seed_len, seed, i + start, digest);
        memcpy(out, digest, sizeof(digest));
        out += sizeof(digest);
    }

    iterated_hash(di, seed_len, seed, n - 1 + start, digest);
    memcpy(out, digest, sz - di->output_size * (n - 1));
}

static int test_fixed_point(ccec_const_cp_t cp, size_t seed_len, const uint8_t *seed, const cc_unit *xy)
{
    cc_size n = ccec_cp_n(cp);
    const cc_unit *q = cczp_prime(ccec_cp_zq(cp));

    uint8_t encoded[1 + ccec_cp_prime_size(cp)];

    ccec_point_decl_cp(cp, r);
    ccec_point_decl_cp(cp, s);

    for (uint16_t i = 1; i < 1000; i++) {
        CC_DECL_WORKSPACE_TEST(ws);

        // Derive a pseudo-random point.
        bighash(seed_len, seed, i, sizeof(encoded), encoded);

        // Turn the first byte into either 0x02 or 0x03 (compressed format).
        encoded[0] = (encoded[0] & 1) | 2;

        cc_unit x[n];
        is(ccn_read_uint(n, x, sizeof(encoded) - 1, encoded + 1), CCERR_OK, "Reading x failed");

        // Try to reconstruct a point from the given x-coordinate.
        if (ccec_affine_point_from_x_ws(ws, cp, (ccec_affine_point_t)s, x) != CCERR_OK) {
            goto loop;
        }

        if (ccec_validate_point_and_projectify_ws(ws, cp, r, (ccec_const_affine_point_t)s, NULL) != CCERR_OK) {
            goto loop;
        }

        // Check that (r * #E) is a point on the curve.
        if (ccec_mult_ws(ws, cp, s, q, ccec_cp_order_bitlen(cp), r) != CCERR_OK || !ccec_is_point_ws(ws, cp, s)) {
            goto loop;
        }

        if (ccec_affinify_ws(ws, cp, (ccec_affine_point_t)r, r) != 0) {
            goto loop;
        }

        // Compare the x-coordinate to the curve parameters.
        ok_ccn_cmp(n, xy, ccec_point_x(r, cp), "Wrong x-coordinate");

        cc_unit *y = ccec_point_y(r, cp);

        // Compute (p - y) if we have the wrong y.
        if ((encoded[0] == 0x02) != (ccn_bit(y, 0) == 0)) {
            ccn_sub_ws(ws, n, y, cczp_prime(ccec_cp_zp(cp)), y);
        }

        // Compare the y-coordinate to the curve parameters.
        ok_ccn_cmp(n, xy + n, y, "Wrong y-coordinate");

        CC_FREE_WORKSPACE(ws);
        return 0;

loop:
        CC_FREE_WORKSPACE(ws);
    }

    return -1;
}

/*
 * Points for common groups as defined by RFC 9383, section 4.
 *
 * Ensure the fixed points given by the spec were derived as stated and match
 * the uncompressed versions listed in our SPAKE2+ curve parameter definitions.
 */

static void test_points_m_n(void)
{
    const uint8_t seed256_m[] = "1.2.840.10045.3.1.7 point generation seed (M)";
    const uint8_t seed256_n[] = "1.2.840.10045.3.1.7 point generation seed (N)";

    const uint8_t seed384_m[] = "1.3.132.0.34 point generation seed (M)";
    const uint8_t seed384_n[] = "1.3.132.0.34 point generation seed (N)";

    const uint8_t seed521_m[] = "1.3.132.0.35 point generation seed (M)";
    const uint8_t seed521_n[] = "1.3.132.0.35 point generation seed (N)";

    ccspake_const_cp_t scp256 = ccspake_cp_256();
    ccec_const_cp_t cp256 = ccspake_cp_ec(scp256);

    is(test_fixed_point(cp256, sizeof(seed256_m) - 1, seed256_m, scp256->m), 0, "Verifying M for P-256 failed");
    is(test_fixed_point(cp256, sizeof(seed256_n) - 1, seed256_n, scp256->n), 0, "Verifying N for P-256 failed");

    ccspake_const_cp_t scp384 = ccspake_cp_384();
    ccec_const_cp_t cp384 = ccspake_cp_ec(scp384);

    is(test_fixed_point(cp384, sizeof(seed384_m) - 1, seed384_m, scp384->m), 0, "Verifying M for P-384 failed");
    is(test_fixed_point(cp384, sizeof(seed384_n) - 1, seed384_n, scp384->n), 0, "Verifying N for P-384 failed");

    ccspake_const_cp_t scp521 = ccspake_cp_521();
    ccec_const_cp_t cp521 = ccspake_cp_ec(scp521);

    is(test_fixed_point(cp521, sizeof(seed521_m) - 1, seed521_m, scp521->m), 0, "Verifying M for P-521 failed");
    is(test_fixed_point(cp521, sizeof(seed521_n) - 1, seed521_n, scp521->n), 0, "Verifying N for P-521 failed");
}

const struct ccspake_ccc_rfc_test_vector {
    ccspake_const_cp_t (*scp)(void);
    ccspake_const_mac_t (*mac)(void);
    const char *id_p;
    const char *id_v;
    const char *w0;
    const char *w1;
    const char *L;
    const char *x;
    const char *X;
    const char *y;
    const char *Y;
    const char *mac_p;
    const char *mac_v;
    const char *sk;
    const char *ctx;
} ccspake_ccc_rfc_test_vectors[] = {
#include "../test_vectors/spake2-ccc-rfc.kat"
};

const size_t ccspake_ccc_rfc_test_vectors_num =
    CC_ARRAY_LEN(ccspake_ccc_rfc_test_vectors);

static void test_kat(void)
{
    struct ccrng_state *rng = global_test_rng;

    for (unsigned i = 0; i < ccspake_ccc_rfc_test_vectors_num; i++) {
        const struct ccspake_ccc_rfc_test_vector *test =
            &ccspake_ccc_rfc_test_vectors[i];

        ccspake_const_cp_t scp = test->scp();
        ccec_const_cp_t cp = ccspake_cp_ec(scp);
        cc_size n = ccec_cp_n(cp);

        ccspake_const_mac_t mac = test->mac();

        size_t id_prover_nbytes = strlen(test->id_p);
        const uint8_t *id_prover = NULL;
        if (id_prover_nbytes) {
            id_prover = (const uint8_t *)test->id_p;
        }

        size_t id_verifier_nbytes = strlen(test->id_v);
        const uint8_t *id_verifier = NULL;
        if (id_verifier_nbytes) {
            id_verifier = (const uint8_t *)test->id_v;
        }

        byteBuffer tv_w0 = hexStringToBytes(test->w0);
        byteBuffer tv_w1 = hexStringToBytes(test->w1);
        byteBuffer tv_L = hexStringToBytes(test->L);
        byteBuffer tv_x = hexStringToBytes(test->x);
        byteBuffer tv_X = hexStringToBytes(test->X);
        byteBuffer tv_y = hexStringToBytes(test->y);
        byteBuffer tv_Y = hexStringToBytes(test->Y);
        byteBuffer tv_mac_p = hexStringToBytes(test->mac_p);
        byteBuffer tv_mac_v = hexStringToBytes(test->mac_v);
        byteBuffer tv_sk = hexStringToBytes(test->sk);
        byteBuffer tv_ctx = hexStringToBytes(test->ctx);

        ccspake_ctx_decl(scp, ctx_p);
        ccspake_ctx_decl(scp, ctx_v);

        size_t coord_nbytes = ccec_cp_prime_size(cp);
        uint8_t L[1 + 2 * coord_nbytes];
        is(ccspake_generate_L(scp, tv_w1->len, tv_w1->bytes, sizeof(L), L, rng), CCERR_OK, "Generate L from w1");
        ok_memcmp(L, tv_L->bytes, tv_L->len, "L ≠ L_tv");

        is(ccspake_prover_initialize(ctx_p, scp, mac, rng,
                                     tv_ctx->len, tv_ctx->bytes,
                                     id_prover_nbytes, id_prover,
                                     id_verifier_nbytes, id_verifier,
                                     tv_w0->len, tv_w0->bytes, tv_w1->bytes),
            CCERR_OK, "Initialize SPAKE2+ prover");

        is(ccspake_verifier_initialize(ctx_v, scp, mac, rng,
                                       tv_ctx->len, tv_ctx->bytes,
                                       id_prover_nbytes, id_prover,
                                       id_verifier_nbytes, id_verifier,
                                       tv_w0->len, tv_w0->bytes, sizeof(L), L),
            CCERR_OK, "Initialize SPAKE2+ verifier");

        // Advance the state machine.
        uint8_t tmp[1 + 2 * coord_nbytes];
        is(ccspake_kex_generate(ctx_p, sizeof(tmp), tmp), CCERR_OK, "Generate U");
        is(ccspake_kex_generate(ctx_v, sizeof(tmp), tmp), CCERR_OK, "Generate V");

        // Override x and X = G * x.
        is(ccn_read_uint(n, ccspake_ctx_xy(ctx_p), tv_x->len, tv_x->bytes), CCERR_OK, "Reading x failed");
        is(ccn_read_uint(n, ccspake_ctx_XY_x(ctx_p), coord_nbytes, tv_X->bytes + 1), CCERR_OK, "Reading x(X) failed");
        is(ccn_read_uint(n, ccspake_ctx_XY_y(ctx_p), coord_nbytes, tv_X->bytes + 1 + coord_nbytes), CCERR_OK, "Reading y(X) failed");

        // Override y and Y = G * y.
        is(ccn_read_uint(n, ccspake_ctx_xy(ctx_v), tv_y->len, tv_y->bytes), CCERR_OK, "Reading y failed");
        is(ccn_read_uint(n, ccspake_ctx_XY_x(ctx_v), coord_nbytes, tv_Y->bytes + 1), CCERR_OK, "Reading x(Y) failed");
        is(ccn_read_uint(n, ccspake_ctx_XY_y(ctx_v), coord_nbytes, tv_Y->bytes + 1 + coord_nbytes), CCERR_OK, "Reading y(Y) failed");

        is(ccspake_kex_process(ctx_p, tv_Y->len, tv_Y->bytes), CCERR_OK, "Process Y");
        is(ccspake_kex_process(ctx_v, tv_X->len, tv_X->bytes), CCERR_OK, "Process X");

        uint8_t mac_p[tv_mac_p->len], mac_v[tv_mac_p->len];
        is(ccspake_mac_compute(ctx_p, sizeof(mac_p), mac_p), CCERR_OK, "Generate mac_p");
        is(ccspake_mac_compute(ctx_v, sizeof(mac_v), mac_v), CCERR_OK, "Generate mac_v");

        // Check MACs.
        ok_memcmp(mac_p, tv_mac_p->bytes, tv_mac_p->len, "MAC_p ≠ MAC_p_tv");
        ok_memcmp(mac_v, tv_mac_v->bytes, tv_mac_v->len, "MAC_v ≠ MAC_v_tv");

        uint8_t sk_p[tv_sk->len], sk_v[tv_sk->len];
        is(ccspake_mac_verify_and_get_session_key(ctx_p, sizeof(mac_v), mac_v, sizeof(sk_p), sk_p), CCERR_OK, "Verify mac_v");
        is(ccspake_mac_verify_and_get_session_key(ctx_v, sizeof(mac_p), mac_p, sizeof(sk_v), sk_v), CCERR_OK, "Verify mac_p");

        ok_memcmp(sk_p, sk_v, sizeof(sk_p), "Shared keys don't match");
        ok_memcmp(sk_p, tv_sk->bytes, tv_sk->len, "SK ≠ SK_tv");

        free(tv_w0);
        free(tv_w1);
        free(tv_L);
        free(tv_x);
        free(tv_X);
        free(tv_y);
        free(tv_Y);
        free(tv_mac_p);
        free(tv_mac_v);
        free(tv_sk);
        free(tv_ctx);
    }
}

static void test_kex_process_empty_message(void)
{
    ccspake_const_cp_t cp = ccspake_cp_256();
    ccspake_ctx_decl(cp, ctx_p);
    
    size_t w_size = ccspake_sizeof_w(cp);
    uint8_t w0[w_size], w1[w_size];
    generate_w0_w1(cp, w0, w1);

    is(ccspake_prover_init(ctx_p, cp, ccspake_mac_hkdf_hmac_sha256(), global_test_rng, 0, NULL, w_size, w0, w1), 0, "prover_init");

    uint8_t out_buf[ccspake_sizeof_point(cp)];
    is(ccspake_kex_generate(ctx_p, sizeof(out_buf), out_buf), 0, "kex generate");

    const uint8_t *deadbeef = (const uint8_t *)0xdeadbeef;
    is(ccspake_kex_process(ctx_p, 0, deadbeef), CCERR_PARAMETER, "ccspake_kex_process 0-length should fail");
}

int ccspake_tests(TM_UNUSED int argc, TM_UNUSED char *const *argv)
{
    ccspake_const_cp_t all_curves[] = {
        ccspake_cp_256(), ccspake_cp_384(), ccspake_cp_521(),
        ccspake_cp_256_rfc(), ccspake_cp_384_rfc(), ccspake_cp_521_rfc()
    };

    ccspake_const_cp_t rfc_curves[] = {
        ccspake_cp_256_rfc(), ccspake_cp_384_rfc(), ccspake_cp_521_rfc()
    };

    ccspake_const_mac_t hkdf_cmac_sha256 = ccspake_mac_hkdf_cmac_aes128_sha256();
    ccspake_const_mac_t hkdf_hmac_sha256 = ccspake_mac_hkdf_hmac_sha256();
    ccspake_const_mac_t hkdf_hmac_sha512 = ccspake_mac_hkdf_hmac_sha512();

    ccspake_const_mac_t macs[] = {
        hkdf_cmac_sha256, hkdf_hmac_sha256, hkdf_hmac_sha512
    };

    int num_tests = 0;
    num_tests += 18; // test_2_rtt
    num_tests += 14; // test_1p5_rtt
    num_tests += 12; // test_initialize
    num_tests += 13; // test_context_mismatch
    num_tests += 13; // test_w0_mismatch
    num_tests += 13; // test_w1_mismatch
    num_tests += 13; // test_mac_mismatch
    num_tests += 15; // test_bogus_kex
    num_tests *= CC_ARRAY_LEN(macs);

    num_tests += 13; // test_bogus_points
    num_tests *= CC_ARRAY_LEN(all_curves);

    // test_identities(_mismatch)
    num_tests += (14 + 13) * CC_ARRAY_LEN(rfc_curves) * CC_ARRAY_LEN(macs);

    num_tests += 24;  // test_state_machine
    num_tests += 741; // test_points_m_n
    num_tests += 22 * ccspake_ccc_rfc_test_vectors_num; // test_kat
    num_tests += 5; // test_kex_process_empty_message
    plan_tests(num_tests);

    // Tests for all curves and variants.
    for (size_t i = 0; i < CC_ARRAY_LEN(all_curves); i++) {
        ccspake_const_cp_t cp = all_curves[i];

        for (size_t j = 0; j < CC_ARRAY_LEN(macs); j++) {
            ccspake_const_mac_t mac = macs[j];

            test_1p5_rtt(cp, mac);
            test_2_rtt(cp, mac);
            test_initialize(cp, mac);
            test_context_mismatch(cp, mac);
            test_w0_mismatch(cp, mac);
            test_w1_mismatch(cp, mac);
            test_mac_mismatch(cp, mac);
            test_bogus_kex(cp, mac);
        }

        test_bogus_points(cp);
    }

    // Tests for all curves with only the RFC variant.
    for (size_t i = 0; i < CC_ARRAY_LEN(rfc_curves); i++) {
        ccspake_const_cp_t cp = rfc_curves[i];

        for (size_t j = 0; j < CC_ARRAY_LEN(macs); j++) {
            ccspake_const_mac_t mac = macs[j];

            test_identities(cp, mac);
            test_identities_mismatch(cp, mac);
        }
    }

    test_state_machine();
    test_points_m_n();
    test_kat();
    test_kex_process_empty_message();

    return 0;
}

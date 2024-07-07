/* Copyright (c) (2018,2019,2021,2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */
#include "ccperf.h"
#include <corecrypto/ccsha2.h>
#include <corecrypto/ccspake.h>
#include "ccspake_internal.h"

static ccspake_const_cp_t curve_params(cc_size bits)
{
    if (bits == 256) {
        return ccspake_cp_256();
    }

    if (bits == 384) {
        return ccspake_cp_384();
    }

    if (bits == 521) {
        return ccspake_cp_521();
    }

    cc_abort("Unsupported curve size");
    return NULL;
}

static void generate_point(ccspake_const_cp_t scp, uint8_t *out)
{
    ccec_const_cp_t cp = ccspake_cp_ec(scp);

    ccec_full_ctx_decl_cp(cp, full);
    ccec_ctx_init(cp, full);

    if (ccecdh_generate_key(cp, rng, full)) {
        abort();
    }

    ccec_export_pub(ccec_ctx_pub(full), out);

    ccec_full_ctx_clear_cp(cp, full);
}

static double perf_ccspake_test_init_prover(size_t loops, cc_size nbits)
{
    ccspake_const_cp_t cp = curve_params(nbits);

    ccspake_ctx_decl(cp, ctx_p);

    ccspake_const_mac_t mac = ccspake_mac_hkdf_hmac_sha256();

    size_t w_size = ccspake_sizeof_w(cp);

    uint8_t w0[w_size], w1[w_size];
    ccrng_generate(rng, sizeof(w0), w0);
    ccrng_generate(rng, sizeof(w1), w1);

    double t;

    perf_start();
    do {
        if (ccspake_prover_init(ctx_p, cp, mac, rng, 0, NULL, sizeof(w0), w0, w1)) {
            abort();
        }
    } while (--loops != 0);
    t = perf_seconds();

    ccspake_ctx_clear(cp, ctx_p);

    return t;
}

static double perf_ccspake_test_init_verifier(size_t loops, cc_size nbits)
{
    ccspake_const_cp_t cp = curve_params(nbits);

    ccspake_ctx_decl(cp, ctx_v);

    ccspake_const_mac_t mac = ccspake_mac_hkdf_hmac_sha256();

    size_t w_size = ccspake_sizeof_w(cp);
    size_t pt_size = ccspake_sizeof_point(cp);

    uint8_t w0[w_size], w1[w_size];
    ccrng_generate(rng, sizeof(w0), w0);
    ccrng_generate(rng, sizeof(w1), w1);

    double t;

    perf_start();
    do {
        uint8_t L[pt_size];
        if (ccspake_generate_L(cp, sizeof(w1), w1, sizeof(L), L, rng)) {
            abort();
        }

        if (ccspake_verifier_init(ctx_v, cp, mac, rng, 0, NULL, sizeof(w0), w0, sizeof(L), L)) {
            abort();
        }
    } while (--loops != 0);
    t = perf_seconds();

    ccspake_ctx_clear(cp, ctx_v);

    return t;
}

static double perf_ccspake_test_hkdf_hmac_prover(size_t loops, cc_size nbits)
{
    ccspake_const_cp_t cp = curve_params(nbits);

    ccspake_ctx_decl(cp, ctx_p);

    ccspake_const_mac_t mac = ccspake_mac_hkdf_hmac_sha256();

    size_t w_size = ccspake_sizeof_w(cp);
    size_t pt_size = ccspake_sizeof_point(cp);

    uint8_t w0[w_size], w1[w_size];
    ccrng_generate(rng, sizeof(w0), w0);
    ccrng_generate(rng, sizeof(w1), w1);

    uint8_t aad[16];
    ccrng_generate(rng, sizeof(aad), aad);

    if (ccspake_prover_init(ctx_p, cp, mac, rng, sizeof(aad), aad, sizeof(w0), w0, w1)) {
        abort();
    }

    uint8_t Y[pt_size];
    generate_point(cp, Y);

    double t;

    perf_start();
    do {
        uint8_t X[pt_size];
        ccspake_ctx_state(ctx_p) = CCSPAKE_STATE_INIT;
        if (ccspake_kex_generate(ctx_p, sizeof(X), X)) {
            abort();
        }

        if (ccspake_kex_process(ctx_p, sizeof(Y), Y)) {
            abort();
        }

        uint8_t mac_p[mac->tag_nbytes];
        if (ccspake_mac_compute(ctx_p, sizeof(mac_p), mac_p)) {
            abort();
        }

        uint8_t sk_p[16], mac_v[mac->tag_nbytes];
        ccspake_mac_verify_and_get_session_key(ctx_p, sizeof(mac_v), mac_v, sizeof(sk_p), sk_p);
    } while (--loops != 0);
    t = perf_seconds();

    ccspake_ctx_clear(cp, ctx_p);

    return t;
}

static double perf_ccspake_test_hkdf_hmac_verifier(size_t loops, cc_size nbits)
{
    ccspake_const_cp_t cp = curve_params(nbits);

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
    if (ccspake_generate_L(cp, sizeof(w1), w1, sizeof(L), L, rng)) {
        abort();
    }

    if (ccspake_verifier_init(ctx_v, cp, mac, rng, sizeof(aad), aad, sizeof(w0), w0, sizeof(L), L)) {
        abort();
    }

    uint8_t X[pt_size];
    generate_point(cp, X);

    double t;

    perf_start();
    do {
        uint8_t Y[pt_size];
        ccspake_ctx_state(ctx_v) = CCSPAKE_STATE_INIT;
        if (ccspake_kex_generate(ctx_v, sizeof(Y), Y)) {
            abort();
        }

        if (ccspake_kex_process(ctx_v, sizeof(X), X)) {
            abort();
        }

        uint8_t mac_v[mac->tag_nbytes];
        if (ccspake_mac_compute(ctx_v, sizeof(mac_v), mac_v)) {
            abort();
        }

        uint8_t sk_v[16], mac_p[mac->tag_nbytes];
        ccspake_mac_verify_and_get_session_key(ctx_v, sizeof(mac_p), mac_p, sizeof(sk_v), sk_v);
    } while (--loops != 0);
    t = perf_seconds();

    ccspake_ctx_clear(cp, ctx_v);

    return t;
}

static double perf_ccspake_test_hkdf_cmac_prover(size_t loops, cc_size nbits)
{
    ccspake_const_cp_t cp = curve_params(nbits);

    ccspake_ctx_decl(cp, ctx_p);

    ccspake_const_mac_t mac = ccspake_mac_hkdf_cmac_aes128_sha256();

    size_t w_size = ccspake_sizeof_w(cp);
    size_t pt_size = ccspake_sizeof_point(cp);

    uint8_t w0[w_size], w1[w_size];
    ccrng_generate(rng, sizeof(w0), w0);
    ccrng_generate(rng, sizeof(w1), w1);

    uint8_t aad[16];
    ccrng_generate(rng, sizeof(aad), aad);

    if (ccspake_prover_init(ctx_p, cp, mac, rng, sizeof(aad), aad, sizeof(w0), w0, w1)) {
        abort();
    }

    uint8_t Y[pt_size];
    generate_point(cp, Y);

    double t;

    perf_start();
    do {
        uint8_t X[pt_size];
        ccspake_ctx_state(ctx_p) = CCSPAKE_STATE_INIT;
        if (ccspake_kex_generate(ctx_p, sizeof(X), X)) {
            abort();
        }

        if (ccspake_kex_process(ctx_p, sizeof(Y), Y)) {
            abort();
        }

        uint8_t mac_p[16];
        if (ccspake_mac_compute(ctx_p, sizeof(mac_p), mac_p)) {
            abort();
        }

        uint8_t sk_p[16], mac_v[16] = { 0 };
        ccspake_mac_verify_and_get_session_key(ctx_p, sizeof(mac_v), mac_v, sizeof(sk_p), sk_p);
    } while (--loops != 0);
    t = perf_seconds();

    ccspake_ctx_clear(cp, ctx_p);

    return t;
}

static double perf_ccspake_test_hkdf_cmac_verifier(size_t loops, cc_size nbits)
{
    ccspake_const_cp_t cp = curve_params(nbits);

    ccspake_ctx_decl(cp, ctx_v);

    ccspake_const_mac_t mac = ccspake_mac_hkdf_cmac_aes128_sha256();

    size_t w_size = ccspake_sizeof_w(cp);
    size_t pt_size = ccspake_sizeof_point(cp);

    uint8_t w0[w_size], w1[w_size];
    ccrng_generate(rng, sizeof(w0), w0);
    ccrng_generate(rng, sizeof(w1), w1);

    uint8_t aad[16];
    ccrng_generate(rng, sizeof(aad), aad);

    uint8_t L[pt_size];
    if (ccspake_generate_L(cp, sizeof(w1), w1, sizeof(L), L, rng)) {
        abort();
    }

    if (ccspake_verifier_init(ctx_v, cp, mac, rng, sizeof(aad), aad, sizeof(w0), w0, sizeof(L), L)) {
        abort();
    }

    uint8_t X[pt_size];
    generate_point(cp, X);

    double t;

    perf_start();
    do {
        uint8_t Y[pt_size];
        ccspake_ctx_state(ctx_v) = CCSPAKE_STATE_INIT;
        if (ccspake_kex_generate(ctx_v, sizeof(Y), Y)) {
            abort();
        }

        if (ccspake_kex_process(ctx_v, sizeof(X), X)) {
            abort();
        }

        uint8_t mac_v[16];
        if (ccspake_mac_compute(ctx_v, sizeof(mac_v), mac_v)) {
            abort();
        }

        uint8_t sk_v[16], mac_p[16] = { 0 };
        ccspake_mac_verify_and_get_session_key(ctx_v, sizeof(mac_p), mac_p, sizeof(sk_v), sk_v);
    } while (--loops != 0);
    t = perf_seconds();

    ccspake_ctx_clear(cp, ctx_v);

    return t;
}

#define _TEST(_x)                      \
    {                                  \
        .name = #_x, .func = perf_##_x \
    }
static struct ccspake_perf_test {
    const char *name;
    double (*func)(size_t loops, cc_size nbits);
} ccspake_perf_tests[] = {
    _TEST(ccspake_test_init_prover),        _TEST(ccspake_test_init_verifier),    _TEST(ccspake_test_hkdf_hmac_prover),
    _TEST(ccspake_test_hkdf_hmac_verifier), _TEST(ccspake_test_hkdf_cmac_prover), _TEST(ccspake_test_hkdf_cmac_verifier),
};

static double perf_ccspake(size_t loops, size_t *psize, const void *arg)
{
    const struct ccspake_perf_test *test = arg;
    return test->func(loops, *psize);
}

static struct ccperf_family family;

struct ccperf_family *ccperf_family_ccspake(int argc, char *argv[])
{
    F_GET_ALL(family, ccspake);
    static const size_t group_nbits[] = { 256, 384, 521 };
    F_SIZES_FROM_ARRAY(family, group_nbits);
    family.size_kind = ccperf_size_bits;
    return &family;
}

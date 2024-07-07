/* Copyright (c) (2011,2012,2014-2021,2023) Apple Inc. All rights reserved.
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
#include "cczp_internal.h"
#include "ccec_internal.h"
#include <corecrypto/ccec.h>
#include <corecrypto/ccec_priv.h>
#include "ccperf_ccec_cp.h"

static struct ccec_full_ctx* gkey=NULL;

static void update_gkey(ccec_const_cp_t cp) {
    if (gkey==NULL || (ccec_cp_prime_bitlen(ccec_ctx_cp(gkey))!=ccec_cp_prime_bitlen(cp))) {
        gkey = realloc(gkey, ccec_full_ctx_size(ccec_ccn_size(cp)));
        int status=ccec_generate_key_internal_fips(cp, rng, gkey);
        if (status) cc_abort("Failure in ccec_generate_key_internal_fips");
    }
}

static double perf_ccec_compact_import_pub(size_t loops, ccec_const_cp_t cp)
{
    update_gkey(cp);

    size_t  export_pubsize = ccec_compact_export_size(0, ccec_ctx_pub(gkey));
    uint8_t exported_pubkey[export_pubsize];
    ccec_pub_ctx_decl_cp(ccec_ctx_cp(gkey), reconstituted_pub);
    ccec_compact_export(0, exported_pubkey, gkey);
    
    perf_start();
    do {
        int status=ccec_compact_import_pub(ccec_ctx_cp(gkey), export_pubsize, exported_pubkey, reconstituted_pub);
        if (status) cc_abort("Failure in ccec_compact_import_pub");
    } while (--loops != 0);
    return perf_seconds();
}

static double perf_ccec_generate_key_legacy(size_t loops, ccec_const_cp_t cp)
{
    ccec_full_ctx_decl_cp(cp, key);

    perf_start();
    do {
        int status=ccec_generate_key_legacy(cp, rng, key);
        if (status) cc_abort("Failure in ccec_generate_key_legacy");
    } while (--loops != 0);
    return perf_seconds();
}

static double perf_ccec_generate_key_fips(size_t loops, ccec_const_cp_t cp)
{
    ccec_full_ctx_decl_cp(cp, key);

    perf_start();
    do {
        int status=ccec_generate_key_fips(cp, rng, key);
        if (status) cc_abort("Failure in ccec_generate_key_fips");
    } while (--loops != 0);
    return perf_seconds();
}

static double perf_ccec_compact_generate_key(size_t loops, ccec_const_cp_t cp)
{
    ccec_full_ctx_decl_cp(cp, key);

    perf_start();
    do {
        int status=ccec_compact_generate_key(cp, rng, key);
        if (status) cc_abort("Failure in ccec_compact_generate_key");
    } while (--loops != 0);
    return perf_seconds();
}

static double perf_ccec_generate_key_internal_fips(size_t loops, ccec_const_cp_t cp)
{
    ccec_full_ctx_decl_cp(cp, key);

    perf_start();
    do {
        int status=ccec_generate_key_internal_fips(cp, rng, key);
        if (status) cc_abort("Failure in ccec_generate_key_internal_fips");
    } while (--loops != 0);
    return perf_seconds();
}

static double perf_ccec_sign(size_t loops, ccec_const_cp_t cp)
{
    size_t original_siglen = ccec_sign_max_size(cp);
    size_t siglen = original_siglen;
    uint8_t sig[siglen];
    uint8_t digest[24] = "012345678912345678901234";

    update_gkey(cp);

    perf_start();
    do {
        siglen = original_siglen;
        int status=ccec_sign(gkey, sizeof(digest), digest, &siglen, sig, rng);
        if (status) cc_abort("Failure in ccec_sign");
    } while (--loops != 0);
    return perf_seconds();
}

static double perf_ccec_verify(size_t loops, ccec_const_cp_t cp)
{
    size_t siglen = ccec_sign_max_size(cp);
    uint8_t sig[siglen];
    uint8_t digest[24] = "012345678912345678901234";
    bool ok;

    update_gkey(cp);

    ccec_sign(gkey, sizeof(digest), digest, &siglen, sig, rng);

    perf_start();
    do {
        int status=ccec_verify(ccec_ctx_pub(gkey), sizeof(digest), digest, siglen, sig, &ok);
        if (status) cc_abort("Failure in ccec_verify");
    } while (--loops != 0);
    return perf_seconds();
}

static double perf_ccecdh_compute_shared_secret(size_t loops, ccec_const_cp_t cp)
{
    ccec_full_ctx_decl_cp(cp, key2);
    uint8_t out1[ccec_ccn_size(cp)];
    size_t out1_len;

    // Key 1
    update_gkey(cp);

    // Key 2
    int status=ccec_generate_key_internal_fips(cp, rng, key2);
    if (status) cc_abort("ccec_generate_key_internal_fips");

    perf_start();
    do {
        out1_len=sizeof(out1);
        status=ccecdh_compute_shared_secret(gkey, ccec_ctx_pub(key2), &out1_len, out1, NULL);
        if (status) cc_abort("Failure in ccecdh_compute_shared_secret");
    } while (--loops != 0);
    return perf_seconds();
}

static double perf_ccecdh_generate_key(size_t loops, ccec_const_cp_t cp)
{
    ccec_full_ctx_decl_cp(cp, key);
    ccec_ctx_init(cp, key);

    perf_start();
    do {
        if (ccecdh_generate_key(cp, rng, key)) {
            cc_abort("Failure in ccecdh_generate_key");
        }
    } while (--loops != 0);

    return perf_seconds();
}

static double perf_ccec_diversify_pub_twin(size_t loops, ccec_const_cp_t cp)
{
    ccec_pub_ctx_decl_cp(cp, pub_out);
    ccec_ctx_init(cp, pub_out);

    ccec_full_ctx_decl_cp(cp, full);
    ccec_ctx_init(cp, full);

    if (ccec_generate_key(cp, rng, full)) {
        cc_abort("Failure in ccec_generate_key");
    }

    uint8_t entropy[ccec_diversify_min_entropy_len(cp) * 2];
    if (ccrng_generate(rng, sizeof(entropy), entropy)) {
        cc_abort("Failure in ccrng_generate");
    }

    perf_start();
    do {
        if (ccec_diversify_pub_twin(cp, ccec_ctx_pub(full), sizeof(entropy), entropy, rng, pub_out)) {
            cc_abort("Failure in ccec_diversify_pub_twin");
        }
    } while (--loops != 0);

    return perf_seconds();
}

static double perf_ccec_cczp_mul(size_t loops, ccec_const_cp_t cp)
{
    cczp_const_t zp = (cczp_const_t)cp;
    cc_size n = cczp_n(zp);

    cc_unit a[n], r[n * 2];
    cczp_generate_non_zero_element(zp, rng, a);

    CC_DECL_WORKSPACE_TEST(ws);

    perf_start();
    do {
        cczp_mul_ws(ws, zp, r, a, a);
    } while (--loops != 0);

    CC_FREE_WORKSPACE(ws);

    return perf_seconds();
}

static double perf_ccec_cczp_inv_mod_p(size_t loops, ccec_const_cp_t cp)
{
    cczp_const_t zp = ccec_cp_zp(cp);
    cc_size n = cczp_n(zp);

    cc_unit a[n], r[n];
    cczp_generate_non_zero_element(zp, rng, a);

    CC_DECL_WORKSPACE_TEST(ws);

    perf_start();
    do {
        if (cczp_inv_ws(ws, zp, r, a)) {
            cc_abort("Failure in cczp_inv");
        }
    } while (--loops != 0);

    CC_FREE_WORKSPACE(ws);

    return perf_seconds();
}

static double perf_ccec_cczp_inv_mod_q(size_t loops, ccec_const_cp_t cp)
{
    cczp_const_t zq = ccec_cp_zq(cp);
    cc_size n = cczp_n(zq);

    cc_unit a[n], r[n];
    ccn_random_bits(ccec_cp_prime_bitlen(cp), a, rng);

    CC_DECL_WORKSPACE_TEST(ws);

    perf_start();
    do {
        if (cczp_inv_ws(ws, zq, r, a)) {
            cc_abort("Failure in cczp_inv");
        }
    } while (--loops != 0);

    CC_FREE_WORKSPACE(ws);

    return perf_seconds();
}

static double perf_ccec_cczp_sqrt(size_t loops, ccec_const_cp_t cp)
{
    cczp_const_t zp = (cczp_const_t)cp;
    cc_size n = cczp_n(zp);

    cc_unit a[n], r[n];
    cczp_generate_non_zero_element(zp, rng, a);

    perf_start();
    do {
        cczp_sqrt(zp, r, a);
    } while (--loops != 0);

    return perf_seconds();
}

static double perf_ccec_affinify(size_t loops, ccec_const_cp_t cp) {
    ccec_full_ctx_decl_cp(cp, full);
    ccec_ctx_init(cp, full);

    int status = ccec_generate_key(cp, rng, full);
    if (status) cc_abort("Failure in ccec_generate_key");
    
    CC_DECL_WORKSPACE_TEST(ws);
    ccec_affine_point_t output = (ccec_affine_point_t) CCEC_ALLOC_POINT_WS(ws, ccec_cp_n(cp));
    
    perf_start();
    while (loops--) {
        status = ccec_affinify_ws(ws, cp, output, ccec_ctx_point(full));
        if (status) cc_abort("Failure in ccec_affinity_ws");
    }
    double total_time = perf_seconds();
    CC_FREE_WORKSPACE(ws);
    return total_time;
}

static double perf_ccec_affinify_100_points(size_t loops, ccec_const_cp_t cp) {
    cc_size npoints = 100;
    cc_size n = ccec_cp_n(cp);
    ccec_projective_point_t input[npoints];
    ccec_affine_point_t output[npoints];
    ccec_full_ctx_t keys[npoints];
    
    CC_DECL_WORKSPACE_TEST(ws);
    for (cc_size i = 0; i < npoints; i++) {
        keys[i] = (ccec_full_ctx_t)CC_ALLOC_WS(ws, ccec_full_ctx_size(n));
        input[i] = CCEC_ALLOC_POINT_WS(ws, n);
        output[i] = (ccec_affine_point_t)CCEC_ALLOC_POINT_WS(ws, n);
    }
    
    int status = CCERR_OK;
    for (cc_size i = 0; i < npoints; i++) {
        status |= ccec_generate_key_internal_fips_ws(ws, cp, rng, keys[i]);
        status |= ccec_projectify_ws(ws, cp, input[i], (ccec_const_affine_point_t)ccec_ctx_point(keys[i]), rng);
    }
    if (status) cc_abort("Failure in ccec_generate_key_internal_fips or ccec_projectify");
    
    double total_time = 0.0;
    while (loops--) {
        perf_start();
        status = ccec_affinify_points_ws(ws, cp, npoints, output, input);
        total_time += perf_seconds();
        if (status) cc_abort("Failure in ccec_affinify_points");
    }
    CC_FREE_WORKSPACE(ws);
    return total_time;
}

static double perf_ccec_full_add(size_t loops, ccec_const_cp_t cp)
{
    ccec_full_ctx_decl_cp(cp, key1);
    ccec_ctx_init(cp, key1);

    ccec_full_ctx_decl_cp(cp, key2);
    ccec_ctx_init(cp, key2);

    ccec_point_decl_cp(cp, r);

    int status = ccec_generate_key(cp, rng, key1);
    if (status) {
        cc_abort("ccec_generate_key() failed");
    }

    status = ccec_generate_key(cp, rng, key2);
    if (status) {
        cc_abort("ccec_generate_key() failed");
    }

    perf_start();

    while (loops--) {
        status = ccec_full_add(cp, r, ccec_ctx_point(key1), ccec_ctx_point(key2));
        if (status) {
            cc_abort("ccec_full_add() failed");
        }
    }

    return perf_seconds();
}

#define _TEST(_x) { .name = #_x, .func = perf_ ## _x}
static struct ccec_perf_test {
    const char *name;
    double(*func)(size_t loops, ccec_const_cp_t cp);
} ccec_perf_tests[] = {
    _TEST(ccec_generate_key_internal_fips),
    _TEST(ccec_generate_key_fips),
    _TEST(ccec_generate_key_legacy),
    _TEST(ccec_compact_generate_key),
    _TEST(ccec_sign),
    _TEST(ccec_verify),
    _TEST(ccec_compact_import_pub),
    _TEST(ccecdh_generate_key),
    _TEST(ccecdh_compute_shared_secret),
    _TEST(ccec_diversify_pub_twin),
    _TEST(ccec_cczp_mul),
    _TEST(ccec_cczp_sqrt),
    _TEST(ccec_cczp_inv_mod_p),
    _TEST(ccec_cczp_inv_mod_q),
    _TEST(ccec_affinify),
    _TEST(ccec_affinify_100_points),
    _TEST(ccec_full_add),
};

static double perf_ccec(size_t loops, size_t *pnbits, const void *arg)
{
    const struct ccec_perf_test *test=arg;
    return test->func(loops, ccec_cp(*pnbits));
}

static struct ccperf_family family;

struct ccperf_family *ccperf_family_ccec(int argc, char *argv[])
{
    F_GET_ALL(family, ccec);

    static const size_t sizes[]={192,224,256,384,521};
    F_SIZES_FROM_ARRAY(family,sizes);

    family.size_kind=ccperf_size_bits;
    return &family;
}

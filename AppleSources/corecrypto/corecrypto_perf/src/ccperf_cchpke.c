/* Copyright (c) (2019) Apple Inc. All rights reserved.
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
#include <corecrypto/ccrng.h>
#include <corecrypto/cchpke_priv.h>

static double perf_cchpke_test_seal(size_t loops, cc_size n)
{
    cchpke_const_params_t params = cchpke_params_x25519_AESGCM128_HKDF_SHA256();

    uint8_t info[8] = {};
    uint8_t aad[32] = {};
    uint8_t pkR[cchpke_params_sizeof_kem_pk(params)];
    uint8_t skR[cchpke_params_sizeof_kem_sk(params)];
    uint8_t pt[n];
    uint8_t ct[n];
    uint8_t tag[cchpke_params_sizeof_aead_tag(params)];
    uint8_t enc[cchpke_params_sizeof_kem_enc(params)];

    struct ccrng_state *rng = ccrng(NULL);
    ccrng_generate(rng, sizeof(info), info);
    ccrng_generate(rng, sizeof(aad), aad);
    ccrng_generate(rng, sizeof(pt), pt);
    ccrng_generate(rng, sizeof(ct), ct);
    ccrng_generate(rng, sizeof(tag), tag);

    int result = cchpke_kem_generate_key_pair(params, rng, sizeof(skR), skR, sizeof(pkR), pkR);
    if (result != CCERR_OK) {
        abort();
    }

    perf_start();
    do {
        int seal_result = cchpke_initiator_seal(params, rng, sizeof(pkR), pkR, sizeof(info), info,
                                                sizeof(aad), aad, sizeof(pt), pt, ct,
                                                sizeof(tag), tag, sizeof(enc), enc);
        if (seal_result != CCERR_OK) {
            abort();
        }
    } while (--loops != 0);

    return perf_seconds();
}

static double perf_cchpke_test_seal_multiple(size_t loops, cc_size n)
{
    cchpke_const_params_t params = cchpke_params_x25519_AESGCM128_HKDF_SHA256();

    uint8_t info[8] = {};
    uint8_t aad[32] = {};
    uint8_t pkR[cchpke_params_sizeof_kem_pk(params)];
    uint8_t skR[cchpke_params_sizeof_kem_sk(params)];
    uint8_t pt[n];
    uint8_t ct[n];
    uint8_t tag[cchpke_params_sizeof_aead_tag(params)];
    uint8_t enc[cchpke_params_sizeof_kem_enc(params)];

    struct ccrng_state *rng = ccrng(NULL);
    ccrng_generate(rng, sizeof(info), info);
    ccrng_generate(rng, sizeof(aad), aad);
    ccrng_generate(rng, sizeof(pt), pt);
    ccrng_generate(rng, sizeof(ct), ct);
    ccrng_generate(rng, sizeof(tag), tag);

    int result = cchpke_kem_generate_key_pair(params, rng, sizeof(skR), skR, sizeof(pkR), pkR);
    if (result != CCERR_OK) {
        abort();
    }

    struct cchpke_initiator initiator;
    result = cchpke_initiator_setup(&initiator, params, rng, sizeof(pkR), pkR, sizeof(info), info, sizeof(enc), enc);
    if (result != CCERR_OK) {
        abort();
    }

    perf_start();
    do {
        int encrypt_result = cchpke_initiator_encrypt(&initiator, sizeof(aad), aad, sizeof(pt), pt, ct, sizeof(tag), tag);
        if (encrypt_result != CCERR_OK) {
            abort();
        }
    } while (--loops != 0);

    return perf_seconds();
}

static double perf_cchpke_test_open(size_t loops, cc_size n)
{
    cchpke_const_params_t params = cchpke_params_x25519_AESGCM128_HKDF_SHA256();

    uint8_t info[8] = {};
    uint8_t aad[32] = {};
    uint8_t pkR[cchpke_params_sizeof_kem_pk(params)];
    uint8_t skR[cchpke_params_sizeof_kem_sk(params)];
    uint8_t pt[n];
    uint8_t pt2[n];
    uint8_t ct[n];
    uint8_t tag[cchpke_params_sizeof_aead_tag(params)];
    uint8_t enc[cchpke_params_sizeof_kem_enc(params)];

    struct ccrng_state *rng = ccrng(NULL);
    ccrng_generate(rng, sizeof(info), info);
    ccrng_generate(rng, sizeof(aad), aad);
    ccrng_generate(rng, sizeof(pt), pt);
    ccrng_generate(rng, sizeof(ct), ct);
    ccrng_generate(rng, sizeof(tag), tag);

    int result = cchpke_kem_generate_key_pair(params, rng, sizeof(skR), skR, sizeof(pkR), pkR);
    if (result != CCERR_OK) {
        abort();
    }

    // First, encrypt something
    int seal_result = cchpke_initiator_seal(params, rng, sizeof(pkR), pkR, sizeof(info), info,
                                            sizeof(aad), aad, sizeof(pt), pt, ct,
                                            sizeof(tag), tag, sizeof(enc), enc);
    if (seal_result != CCERR_OK) {
        abort();
    }

    perf_start();
    do {
        int open_result = cchpke_responder_open(params, sizeof(skR), skR, sizeof(info), info,
                                                sizeof(aad), aad, sizeof(ct), ct, sizeof(tag), tag,
                                                sizeof(enc), enc, pt2);
        if (open_result != CCERR_OK) {
            abort();
        }
    } while (--loops != 0);

    return perf_seconds();
}

static double perf_cchpke_test_seal_open_multiple(size_t loops, cc_size n)
{
    cchpke_const_params_t params = cchpke_params_x25519_AESGCM128_HKDF_SHA256();

    uint8_t info[8] = {};
    uint8_t aad[32] = {};
    uint8_t pkR[cchpke_params_sizeof_kem_pk(params)];
    uint8_t skR[cchpke_params_sizeof_kem_sk(params)];
    uint8_t pt[n];
    uint8_t ct[n];
    uint8_t tag[cchpke_params_sizeof_aead_tag(params)];
    uint8_t enc[cchpke_params_sizeof_kem_enc(params)];

    struct ccrng_state *rng = ccrng(NULL);
    ccrng_generate(rng, sizeof(info), info);
    ccrng_generate(rng, sizeof(aad), aad);
    ccrng_generate(rng, sizeof(pt), pt);
    ccrng_generate(rng, sizeof(ct), ct);
    ccrng_generate(rng, sizeof(tag), tag);

    int result = cchpke_kem_generate_key_pair(params, rng, sizeof(skR), skR, sizeof(pkR), pkR);
    if (result != CCERR_OK) {
        abort();
    }

    struct cchpke_initiator initiator;
    result = cchpke_initiator_setup(&initiator, params, rng, sizeof(pkR), pkR, sizeof(info), info, sizeof(enc), enc);
    if (result != CCERR_OK) {
        abort();
    }

    struct cchpke_responder responder;
    result = cchpke_responder_setup(&responder, params, sizeof(skR), skR, sizeof(info), info, sizeof(enc), enc);
    if (result != CCERR_OK) {
        abort();
    }

    perf_start();
    do {
        int encrypt_result = cchpke_initiator_encrypt(&initiator, sizeof(aad), aad, sizeof(pt), pt, ct, sizeof(tag), tag);
        if (encrypt_result != CCERR_OK) {
            abort();
        }

        int decrypt_result = cchpke_responder_decrypt(&responder, sizeof(aad), aad, sizeof(ct), ct, sizeof(tag), tag, pt);
        if (decrypt_result != CCERR_OK) {
            abort();
        }
    } while (--loops != 0);

    return perf_seconds();
}

#define _TEST(_x) { .name = #_x, .func = perf_ ## _x}
static struct cchpke_perf_test {
    const char *name;
    double (*func)(size_t loops, cc_size n);
} cchpke_perf_tests[] = {
    _TEST(cchpke_test_seal),
    _TEST(cchpke_test_seal_multiple),
    _TEST(cchpke_test_open),
    _TEST(cchpke_test_seal_open_multiple),
};

static double perf_cchpke(size_t loops, size_t *psize, const void *arg)
{
    const struct cchpke_perf_test *test = arg;
    return test->func(loops, *psize);
}

static struct ccperf_family family;

struct ccperf_family *ccperf_family_cchpke(int argc, char *argv[])
{
    F_GET_ALL(family, cchpke);
    static const size_t group_nbits[] = { 32, 64, 128, 256, 512, 1024 };
    F_SIZES_FROM_ARRAY(family, group_nbits);
    family.size_kind = ccperf_size_bits;
    return &family;
}

/* Copyright (c) (2018-2021) Apple Inc. All rights reserved.
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
#include "ccsae.h"
#include "ccsae_priv.h"
#include "ccsae_internal.h"

static ccec_const_cp_t ccec_cp(size_t nbits) {
    switch (nbits) {
        case (192):
            return ccec_cp_192();
        case (224):
            return ccec_cp_224();
        case (256):
            return ccec_cp_256();
        case (384):
            return ccec_cp_384();
        case (521): /* -- 544 = 521 rounded up to the nearest multiple of 32*/
            return ccec_cp_521();
        default:
            return (ccec_const_cp_t)(const struct cczp* )0;
    }
}

static double perf_ccsae_test_generate_commitment(size_t loops, cc_size n)
{
    ccec_const_cp_t cp = ccec_cp(n);
    const struct ccdigest_info *di = ccsha256_di();
    
    uint8_t password[] = "mekmitasdigoat";
    uint8_t identifier[] = "psk4internet";
    const uint8_t A[6] = {0x82, 0x7b, 0x91, 0x9d, 0xd4, 0xb9};
    const uint8_t B[6] = {0x1e, 0xec, 0x49, 0xea, 0x64, 0x88};
    
    ccsae_ctx_decl(cp, ctx);
    ccsae_init(ctx, cp, rng, di);
    
    size_t commit_size = ccsae_sizeof_commitment(ctx);
    uint8_t commitment[commit_size];
    
    perf_start();
    do {
        int status = ccsae_generate_commitment(ctx, A, 6, B, 6, password, strlen((char *) password), identifier, strlen((char *) identifier), commitment);
        ccsae_ctx_state(ctx) = CCSAE_STATE_INIT;
        if (status != 0) abort();
    } while (--loops != 0);
    return perf_seconds();
}

static double perf_ccsae_test_verify_commitment(size_t loops, cc_size nn)
{
    ccec_const_cp_t cp = ccec_cp(nn);
    const struct ccdigest_info *di = ccsha256_di();
    
    uint8_t password[] = "mekmitasdigoat";
    uint8_t identifier[] = "psk4internet";
    const uint8_t A[6] = {0x82, 0x7b, 0x91, 0x9d, 0xd4, 0xb9};
    const uint8_t B[6] = {0x1e, 0xec, 0x49, 0xea, 0x64, 0x88};
    
    ccsae_ctx_decl(cp, ctxA);
    ccsae_ctx_decl(cp, ctxB);
    ccsae_init(ctxA, cp, rng, di);
    ccsae_init(ctxB, cp, rng, di);
    
    size_t commit_size = ccsae_sizeof_commitment(ctxA);
    uint8_t commitment[commit_size];
    
    int status = ccsae_generate_commitment(ctxB, A, 6, B, 6, password, strlen((char *) password), identifier, strlen((char *) identifier), commitment);
    if (status != 0) abort();
    status = ccsae_generate_commitment(ctxA, A, 6, B, 6, password, strlen((char *) password), identifier, strlen((char *) identifier), commitment);
    if (status != 0) abort();
    
    perf_start();
    do {
        status = ccsae_verify_commitment(ctxB, commitment);
        ccsae_ctx_state(ctxB) = CCSAE_STATE_COMMIT_GENERATED;
        if (status != 0) abort();
    } while (--loops != 0);
    return perf_seconds();
}

static double perf_ccsae_test_generate_confirmation(size_t loops, cc_size nn)
{
    ccec_const_cp_t cp = ccec_cp(nn);
    const struct ccdigest_info *di = ccsha256_di();
    
    uint8_t password[] = "mekmitasdigoat";
    uint8_t identifier[] = "psk4internet";
    const uint8_t A[6] = {0x82, 0x7b, 0x91, 0x9d, 0xd4, 0xb9};
    const uint8_t B[6] = {0x1e, 0xec, 0x49, 0xea, 0x64, 0x88};
    
    ccsae_ctx_decl(cp, ctxA);
    ccsae_ctx_decl(cp, ctxB);
    ccsae_init(ctxA, cp, rng, di);
    ccsae_init(ctxB, cp, rng, di);
    
    size_t commit_size = ccsae_sizeof_commitment(ctxA);
    size_t confirmation_size = ccsae_sizeof_confirmation(ctxA);
    uint8_t commitment[commit_size];
    uint8_t confirmation[confirmation_size];
    uint8_t send_confirm_counter[2] = { 0 };
    
    int status = ccsae_generate_commitment(ctxB, A, 6, B, 6, password, strlen((char *) password), identifier, strlen((char *) identifier), commitment);
    if (status != 0) abort();
    status = ccsae_generate_commitment(ctxA, A, 6, B, 6, password, strlen((char *) password), identifier, strlen((char *) identifier), commitment);
    if (status != 0) abort();
    
    status = ccsae_verify_commitment(ctxB, commitment);
    if (status != 0) abort();
    
    perf_start();
    do {
        status = ccsae_generate_confirmation(ctxB, send_confirm_counter, confirmation);
        ccsae_ctx_state(ctxB) = CCSAE_STATE_COMMIT_BOTH;
        if (status != 0) abort();
    } while (--loops != 0);
    return perf_seconds();
}

static double perf_ccsae_test_verify_confirmation(size_t loops, cc_size nn)
{
    ccec_const_cp_t cp = ccec_cp(nn);
    const struct ccdigest_info *di = ccsha256_di();
    
    uint8_t password[] = "mekmitasdigoat";
    uint8_t identifier[] = "psk4internet";
    const uint8_t A[6] = {0x82, 0x7b, 0x91, 0x9d, 0xd4, 0xb9};
    const uint8_t B[6] = {0x1e, 0xec, 0x49, 0xea, 0x64, 0x88};
    
    ccsae_ctx_decl(cp, ctxA);
    ccsae_ctx_decl(cp, ctxB);
    ccsae_init(ctxA, cp, rng, di);
    ccsae_init(ctxB, cp, rng, di);
    
    size_t commit_size = ccsae_sizeof_commitment(ctxA);
    size_t confirmation_size = ccsae_sizeof_confirmation(ctxA);
    uint8_t commitmentA[commit_size];
    uint8_t commitmentB[commit_size];
    uint8_t confirmationA[confirmation_size];
    uint8_t send_confirm_counter[2] = { 0 };
    
    int status = ccsae_generate_commitment(ctxB, A, 6, B, 6, password, strlen((char *) password), identifier, strlen((char *) identifier), commitmentB);
    if (status != 0) abort();
    status = ccsae_generate_commitment(ctxA, A, 6, B, 6, password, strlen((char *) password), identifier, strlen((char *) identifier), commitmentA);
    if (status != 0) abort();
    
    status = ccsae_verify_commitment(ctxB, commitmentA);
    if (status != 0) abort();
    status = ccsae_verify_commitment(ctxA, commitmentB);
    if (status != 0) abort();
    
    status = ccsae_generate_confirmation(ctxA, send_confirm_counter, confirmationA);
    if (status != 0) abort();
    
    perf_start();
    do {
        status = ccsae_verify_confirmation(ctxB, send_confirm_counter, confirmationA);
        ccsae_ctx_state(ctxB) = CCSAE_STATE_CONFIRMATION_GENERATED;
        if (status != 0) abort();
    } while (--loops != 0);
    return perf_seconds();
}

#define _TEST(_x) { .name = #_x, .func = perf_ ## _x}
static struct ccsae_perf_test {
    const char *name;
    double (*func)(size_t loops, cc_size n);
} ccsae_perf_tests[] = {
    _TEST(ccsae_test_generate_commitment),
    _TEST(ccsae_test_verify_commitment),
    _TEST(ccsae_test_generate_confirmation),
    _TEST(ccsae_test_verify_confirmation)
};

static double perf_ccsae(size_t loops, size_t *psize, const void *arg)
{
    const struct ccsae_perf_test *test=arg;
    return test->func(loops, *psize);
}

static struct ccperf_family family;

struct ccperf_family *ccperf_family_ccsae(int argc, char *argv[])
{
    F_GET_ALL(family, ccsae);
    static const size_t group_nbits[] = { 192, 224, 256, 384, 521 };
    F_SIZES_FROM_ARRAY(family, group_nbits);
    family.size_kind = ccperf_size_bits;
    return &family;
}

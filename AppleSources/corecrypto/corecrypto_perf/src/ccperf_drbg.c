/* Copyright (c) (2017-2019,2021,2023) Apple Inc. All rights reserved.
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
#include <corecrypto/ccdrbg.h>
#include <corecrypto/ccaes.h>
#include <corecrypto/ccsha2.h>

static ccdrbg_df_bc_ctx_t df_ctx;
static struct ccdrbg_nistctr_custom  custom_ctr; // DRBG - NIST CTR
static struct ccdrbg_nisthmac_custom custom_hmac; // DRBG - NIST HMAC

const char drbg_init_salt[] ="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"; // 64bytes
const char drbg_init_nonce[]="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"; // 32bytes
const char drbg_init_personalization[]="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"; // 32bytes

static double perf_f_ccdrbg_hmac_sha256_reseed(size_t loops, size_t nbytes)
 {
     CC_UNUSED int status;
     uint8_t *results = malloc(nbytes);
     double time;

     struct ccdrbg_info info;
     ccdrbg_factory_nisthmac(&info, &custom_hmac);
     struct ccdrbg_state *state = malloc(info.size);
     status = ccdrbg_init(&info, state,
         sizeof(drbg_init_salt), drbg_init_salt,
         sizeof(drbg_init_nonce), drbg_init_nonce,
         sizeof(drbg_init_personalization), drbg_init_personalization
         );
     cc_assert(status==0);
     perf_start();
     memset(results,'b',nbytes);
     do {
         status = ccdrbg_reseed(&info,state, nbytes, results,0,NULL);
         cc_assert(status==0);
     } while (--loops != 0);
     time=perf_seconds();
     free(state);
     free(results);
     return time;
 }

static double perf_f_ccdrbg_hmac_sha256_generate(size_t loops, size_t nbytes)
{
    CC_UNUSED int status;
    uint8_t *results = malloc(nbytes);
    double time;

    struct ccdrbg_info info;
    ccdrbg_factory_nisthmac(&info, &custom_hmac);
    struct ccdrbg_state *state = malloc(info.size);
    status = ccdrbg_init(&info, state,
                         sizeof(drbg_init_salt), drbg_init_salt,
                         sizeof(drbg_init_nonce), drbg_init_nonce,
                         sizeof(drbg_init_personalization), drbg_init_personalization
                         );
    cc_assert(status==0);
    perf_start();
    do {
        status = ccdrbg_generate(&info,state, nbytes, results,0,NULL);
        cc_assert(status==0);
    } while (--loops != 0);
    time=perf_seconds();
    free(state);
    free(results);
    return time;
}
static double perf_f_ccdrbg_hmac_sha256_oneshot(size_t loops, size_t nbytes)
{
    CC_UNUSED int status;
    uint8_t *results = malloc(nbytes);
    double time;

    struct ccdrbg_info info;
    ccdrbg_factory_nisthmac(&info, &custom_hmac);
    struct ccdrbg_state *state = malloc(info.size);
    perf_start();
    do {
        status = ccdrbg_init(&info, state,
                             sizeof(drbg_init_salt), drbg_init_salt,
                             sizeof(drbg_init_nonce), drbg_init_nonce,
                             sizeof(drbg_init_personalization), drbg_init_personalization
                             );
        cc_assert(status==0);
        status = ccdrbg_generate(&info,state, nbytes, results,0,NULL);
        cc_assert(status==0);
    } while (--loops != 0);
    time=perf_seconds();
    free(state);
    free(results);
    return time;
}


static double perf_f_ccdrbg_ctr_aes256_reseed(size_t loops, size_t nbytes)
{
    CC_UNUSED int status;
    uint8_t *results = malloc(nbytes);
    double time;

    struct ccdrbg_info info;
    ccdrbg_factory_nistctr(&info, &custom_ctr);
    struct ccdrbg_state *state = malloc(info.size);
    status = ccdrbg_init(&info, state,
        sizeof(drbg_init_salt), drbg_init_salt,
        sizeof(drbg_init_nonce), drbg_init_nonce,
        sizeof(drbg_init_personalization), drbg_init_personalization
        );
    cc_assert(status==0);
    perf_start();
    memset(results,'b',nbytes);
    do {
        status = ccdrbg_reseed(&info,state, nbytes, results,0,NULL);
        cc_assert(status==0);
    } while (--loops != 0);
    time=perf_seconds();
    free(state);
    free(results);
    return time;
}


static double perf_f_ccdrbg_ctr_aes256_generate(size_t loops, size_t nbytes)
{
    CC_UNUSED int status;
    uint8_t *results = malloc(nbytes);
    double time;

    struct ccdrbg_info info;
    ccdrbg_factory_nistctr(&info, &custom_ctr);
    struct ccdrbg_state *state = malloc(info.size);
    status = ccdrbg_init(&info, state,
                         sizeof(drbg_init_salt), drbg_init_salt,
                         sizeof(drbg_init_nonce), drbg_init_nonce,
                         sizeof(drbg_init_personalization), drbg_init_personalization
                         );
    cc_assert(status==0);
    perf_start();
    do {
        status = ccdrbg_generate(&info,state, nbytes, results,0,NULL);
        cc_assert(status==0);
    } while (--loops != 0);
    time=perf_seconds();
    free(state);
    free(results);
    return time;
}

static double perf_f_ccdrbg_ctr_aes256_oneshot(size_t loops, size_t nbytes)
{
    CC_UNUSED int status;
    uint8_t *results = malloc(nbytes);
    double time;

    struct ccdrbg_info info;
    ccdrbg_factory_nistctr(&info, &custom_ctr);
    struct ccdrbg_state *state = malloc(info.size);
    perf_start();
    do {
        status = ccdrbg_init(&info, state,
                             sizeof(drbg_init_salt), drbg_init_salt,
                             sizeof(drbg_init_nonce), drbg_init_nonce,
                             sizeof(drbg_init_personalization), drbg_init_personalization
                             );
        cc_assert(status==0);
        status = ccdrbg_generate(&info,state, nbytes, results,0,NULL);
        cc_assert(status==0);
    } while (--loops != 0);
    time=perf_seconds();
    free(state);
    free(results);
    return time;
}

#define _TEST(_x) { .name = #_x, .func = perf_f_ ## _x}
static struct ccdrbg_perf_test {
    const char *name;
    double(*func)(size_t loops, cc_size nbytes);
} ccdrbg_perf_tests[] = {
    _TEST(ccdrbg_ctr_aes256_reseed),
    _TEST(ccdrbg_ctr_aes256_generate),
    _TEST(ccdrbg_ctr_aes256_oneshot),
    _TEST(ccdrbg_hmac_sha256_reseed),
    _TEST(ccdrbg_hmac_sha256_generate),
    _TEST(ccdrbg_hmac_sha256_oneshot),
};

static double perf_ccdrbg(size_t loops, size_t *psize, const void *arg)
{
    const struct ccdrbg_perf_test *test=arg;
    return test->func(loops, *psize);
}

static struct ccperf_family family;


struct ccperf_family *ccperf_family_ccdrbg(int argc, char *argv[])
{
    CC_UNUSED int status;

    (void)ccdrbg_df_bc_init(&df_ctx,
                            ccaes_cbc_encrypt_mode(),
                            32);

    // DRBG - NIST CTR
    struct ccdrbg_nistctr_custom drbg_ctr = {
        .ctr_info = ccaes_ctr_crypt_mode(),
        .keylen = 32,
        .strictFIPS = 0,
        .df_ctx = &df_ctx.df_ctx,
    };

    // DRBG - NIST HMAC
    struct ccdrbg_nisthmac_custom drbg_hmac = {
        .di = ccsha256_di(),
        .strictFIPS = 0,
    };

    memcpy(&custom_ctr,&drbg_ctr,sizeof(custom_ctr));
    memcpy(&custom_hmac,&drbg_hmac,sizeof(custom_hmac));

        F_GET_ALL(family, ccdrbg);
    static const size_t sizes[]={16,32,256,1024,32*1024};
    F_SIZES_FROM_ARRAY(family,sizes);
    family.size_kind=ccperf_size_bytes;
    return &family;
}


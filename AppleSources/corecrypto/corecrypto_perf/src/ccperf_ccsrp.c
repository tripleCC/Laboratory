/* Copyright (c) (2013,2014,2015,2016,2018,2019) Apple Inc. All rights reserved.
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
#include <corecrypto/ccsrp.h>
#include <corecrypto/ccsrp_gp.h>
#include <corecrypto/ccsha1.h>
#include <corecrypto/ccsha2.h>

static struct ccsrp_ctx *
create_context(const struct ccdigest_info *di, cc_size bits)
{
    struct ccsrp_ctx * srp;
    ccdh_const_gp_t gp;
    
    if (bits == 1024)
        gp = ccsrp_gp_rfc5054_1024();
    else if (bits == 2048)
        gp = ccsrp_gp_rfc5054_2048();
    else if (bits == 3072)
        gp = ccsrp_gp_rfc5054_3072();
    else if (bits == 4096)
        gp = ccsrp_gp_rfc5054_4096();
    else {
        printf("unknow bits: %d\n", (int)bits);
        abort();
    }

    srp = malloc(ccsrp_sizeof_srp(di, gp));
    if (srp == NULL)
        return NULL;

    ccsrp_ctx_init(srp, di, gp);
    return srp;
}


static double internal_ccsrp_generate_verifier(const struct ccdigest_info *di, size_t loops, cc_size nbits)
{
    struct ccsrp_ctx *srp = create_context(di, nbits);
    char *password = "password";
    size_t password_len = strlen(password);
    char *salt = "random-salt-1234567890";
    size_t salt_len = strlen(salt);
    uint8_t verifier[ccsrp_ctx_sizeof_n(srp)];
    double t;

    perf_start();
    do {
        ccsrp_generate_verifier(srp, "username", password_len, password, salt_len, salt, verifier);
    } while (--loops != 0);
    t = perf_seconds();
    free(srp);
    return t;
}

static double perf_ccsrp_generate_verifier_sha1(size_t loops, cc_size nbits)
{
    return internal_ccsrp_generate_verifier(ccsha1_di(), loops, nbits);
}

static double perf_ccsrp_generate_verifier_sha256(size_t loops, cc_size nbits)
{
    return internal_ccsrp_generate_verifier(ccsha256_di(), loops, nbits);
}

static double perf_ccsrp_generate_verifier_sha512(size_t loops, cc_size nbits)
{
    return internal_ccsrp_generate_verifier(ccsha512_di(), loops, nbits);
}

static double internal_ccsrp_client_start(const struct ccdigest_info *di, size_t loops, cc_size nbits)
{
    struct ccsrp_ctx *srp = create_context(di, nbits);
    char *username = "username";
    char *password = "password";
    size_t password_len = strlen(password);
    char *salt = "random-salt-1234567890";
    size_t salt_len = strlen(salt);
    uint8_t verifier[ccsrp_ctx_sizeof_n(srp)];
    uint8_t A[ccsrp_ctx_sizeof_n(srp)];
    double t;
    
    ccsrp_generate_verifier(srp, username, password_len, password, salt_len, salt, verifier);
    
    perf_start();
    do {
        ccsrp_client_start_authentication(srp, rng, A);
    } while (--loops != 0);
    t = perf_seconds();
    free(srp);
    return t;
}

static double perf_ccsrp_client_start_sha1(size_t loops, cc_size nbits)
{
    return internal_ccsrp_client_start(ccsha1_di(), loops, nbits);
}

static double perf_ccsrp_client_start_sha256(size_t loops, cc_size nbits)
{
    return internal_ccsrp_client_start(ccsha256_di(), loops, nbits);
}

static double perf_ccsrp_client_start_sha512(size_t loops, cc_size nbits)
{
    return internal_ccsrp_client_start(ccsha512_di(), loops, nbits);
}


static double internal_ccsrp_validate_verifier(const struct ccdigest_info *di, size_t loops, cc_size nbits)
{
    struct ccsrp_ctx *client_srp = create_context(di, nbits);
    struct ccsrp_ctx *server_srp = create_context(di, nbits);
    char *username = "username";
    char *password = "password";
    size_t password_len = strlen(password);
    char *salt = "random-salt-1234567890";
    size_t salt_len = strlen(salt);
    uint8_t verifier[ccsrp_ctx_sizeof_n(client_srp)];
    uint8_t A[ccsrp_ctx_sizeof_n(client_srp)];
    uint8_t B[ccsrp_ctx_sizeof_n(client_srp)];
    double t;
    
    ccsrp_generate_verifier(server_srp, username, password_len, password, salt_len, salt, verifier);
    ccsrp_client_start_authentication(client_srp, rng, A);

    perf_start();
    do {
        ccsrp_server_start_authentication(server_srp, rng, username, salt_len, salt, verifier, A, B);
    } while (--loops != 0);
    t = perf_seconds();
    free(client_srp);
    free(server_srp);
    return t;
}

static double perf_ccsrp_validate_verifier_sha1(size_t loops, cc_size nbits)
{
    return internal_ccsrp_validate_verifier(ccsha1_di(), loops, nbits);
}

static double perf_ccsrp_validate_verifier_sha256(size_t loops, cc_size nbits)
{
    return internal_ccsrp_validate_verifier(ccsha256_di(), loops, nbits);
}

static double perf_ccsrp_validate_verifier_sha512(size_t loops, cc_size nbits)
{
    return internal_ccsrp_validate_verifier(ccsha512_di(), loops, nbits);
}



#define _TEST(_x) { .name = #_x, .func = perf_ ## _x}
static struct ccsrp_perf_test {
    const char *name;
    double(*func)(size_t loops, cc_size nbits);
} ccsrp_perf_tests[] = {
    _TEST(ccsrp_generate_verifier_sha1),
    _TEST(ccsrp_generate_verifier_sha256),
    _TEST(ccsrp_generate_verifier_sha512),
    _TEST(ccsrp_client_start_sha1),
    _TEST(ccsrp_client_start_sha256),
    _TEST(ccsrp_client_start_sha512),
    _TEST(ccsrp_validate_verifier_sha1),
    _TEST(ccsrp_validate_verifier_sha256),
    _TEST(ccsrp_validate_verifier_sha512),
};

static double perf_ccsrp(size_t loops, size_t *psize, const void *arg)
{
    const struct ccsrp_perf_test *test=arg;
    return test->func(loops, *psize);
}

static struct ccperf_family family;

struct ccperf_family *ccperf_family_ccsrp(int argc, char *argv[])
{
    F_GET_ALL(family, ccsrp);
    family.nsizes=3;
    static const size_t group_nbits[]={2048,3072,4096};
    F_SIZES_FROM_ARRAY(family,group_nbits);
    family.size_kind=ccperf_size_bits;
    return &family;
}

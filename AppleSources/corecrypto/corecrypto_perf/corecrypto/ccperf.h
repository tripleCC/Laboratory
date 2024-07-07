/* Copyright (c) (2010,2011,2013-2019,2021-2023) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CCPERF_H_
#define _CORECRYPTO_CCPERF_H_

#include <corecrypto/ccn.h>
#include <corecrypto/ccrng.h>
#include "cctime.h"
#include "ccstats.h"
#include <stdlib.h>
#include "cc_priv.h"

/** RNG instance used for perf tests */
extern struct ccrng_state *rng;


struct ccperf_test {
    const char *name;
    size_t size;
};

/** perf family **/

enum ccperf_size_kind {
    ccperf_size_bytes = 0,
    ccperf_size_bits,
    ccperf_size_iterations,
    ccperf_size_units,
};

struct ccperf_family {
    const char *name;
    // Pointer to size so that it can be update from the test by the tested function (cf. ccdh)
    double(*func)(size_t loops, size_t *size, const void *test);
    struct ccperf_test **tests;
    size_t ntests;
    size_t *sizes;
    size_t nsizes;
    size_t loops;
    enum ccperf_size_kind size_kind;
    size_t nruns;
    double run_time;
    /// Pointer to function to teardown
    void (*teardown)(void);
};

// Stop iterating after reaching timeout
#define RUN_TIMEOUT 10.0

/* Some macros used by family factories */

#define F_ARGS(_f) _f##_perf_tests
#define F_FUNC(_f) perf_##_f
#define F_SZ(_f) sizeof(F_ARGS(_f)[0])
#define F_N(_f) CC_ARRAY_LEN(F_ARGS(_f))

#define F_GET_ALL(_family, _f)                                                  \
do {                                                                            \
    _family.name = #_f;                                                         \
    _family.func=F_FUNC(_f);                                                    \
    ccperf_family_select(&_family, F_N(_f), F_ARGS(_f), F_SZ(_f), argc, argv);  \
    _family.loops=1;                                                            \
} while(0)

#define F_GET_ALL2(_family, _f, _func)                                          \
do {                                                                            \
    _family.name = #_func;                                                      \
    _family.func=F_FUNC(_func);                                                 \
    ccperf_family_select(&_family, F_N(_f), F_ARGS(_f), F_SZ(_f), argc, argv);  \
    _family.loops=1;                                                            \
} while(0)

#define F_SIZE(_family, _n) {\
    _family.nsizes=1; \
    _family.sizes=malloc(sizeof(*(_family.sizes))); \
    _family.sizes[0]=_n; \
}

#define F_SIZES_FROM_ARRAY(_family, _const_array) {\
    assert(sizeof(*(_family.sizes))==sizeof(_const_array[0])); \
    _family.nsizes=CC_ARRAY_LEN(_const_array); \
    _family.sizes=malloc(sizeof(_const_array)); \
    memcpy(_family.sizes,_const_array,sizeof(_const_array));\
    }

#define F_DEFINE(_fam, _oper, _kind, _n)                                        \
static struct ccperf_family _fam##_##_oper##_family;                            \
struct ccperf_family *ccperf_family_##_fam##_##_oper(int argc, char *argv[])    \
{                                                                               \
    ccperf_family_##_fam##_once(argc, argv);                                    \
    F_GET_ALL2(_fam##_##_oper##_family, _fam, _fam##_##_oper);                  \
    F_SIZE(_fam##_##_oper##_family, _n);                                        \
    _fam##_##_oper##_family.size_kind=_kind;                                    \
    return &_fam##_##_oper##_family;                                            \
}

#define F_DEFINE_SIZE_ARRAY(_fam, _oper, _kind, _size_array)                    \
static struct ccperf_family _fam##_##_oper##_family;                            \
struct ccperf_family *ccperf_family_##_fam##_##_oper(int argc, char *argv[])    \
{                                                                               \
ccperf_family_##_fam##_once(argc, argv);                                    \
F_GET_ALL2(_fam##_##_oper##_family, _fam, _fam##_##_oper);                  \
F_SIZES_FROM_ARRAY(_fam##_##_oper##_family, _size_array);                   \
_fam##_##_oper##_family.size_kind=_kind;                                    \
return &_fam##_##_oper##_family;                                            \
}

/* family factories */
struct ccperf_family *ccperf_family_ccecb_init(int argc, char *argv[]);
struct ccperf_family *ccperf_family_ccecb_update(int argc, char *argv[]);
struct ccperf_family *ccperf_family_ccecb_one_shot(int argc, char *argv[]);
struct ccperf_family *ccperf_family_cccbc_init(int argc, char *argv[]);
struct ccperf_family *ccperf_family_cccbc_update(int argc, char *argv[]);
struct ccperf_family *ccperf_family_cccbc_one_shot(int argc, char *argv[]);
struct ccperf_family *ccperf_family_cccfb8_init(int argc, char *argv[]);
struct ccperf_family *ccperf_family_cccfb8_update(int argc, char *argv[]);
struct ccperf_family *ccperf_family_cccfb8_one_shot(int argc, char *argv[]);
struct ccperf_family *ccperf_family_cccfb_init(int argc, char *argv[]);
struct ccperf_family *ccperf_family_cccfb_update(int argc, char *argv[]);
struct ccperf_family *ccperf_family_cccfb_one_shot(int argc, char *argv[]);
struct ccperf_family *ccperf_family_ccctr_init(int argc, char *argv[]);
struct ccperf_family *ccperf_family_ccctr_update(int argc, char *argv[]);
struct ccperf_family *ccperf_family_ccctr_one_shot(int argc, char *argv[]);
struct ccperf_family *ccperf_family_ccgcm_init(int argc, char *argv[]);
struct ccperf_family *ccperf_family_ccgcm_aad(int argc, char *argv[]);
struct ccperf_family *ccperf_family_ccgcm_set_iv(int argc, char *argv[]);
struct ccperf_family *ccperf_family_ccgcm_update(int argc, char *argv[]);
struct ccperf_family *ccperf_family_ccgcm_finalize(int argc, char *argv[]);
struct ccperf_family *ccperf_family_ccgcm_one_shot(int argc, char *argv[]);
struct ccperf_family *ccperf_family_ccccm_init(int argc, char *argv[]);
struct ccperf_family *ccperf_family_ccccm_cbcmac(int argc, char *argv[]);
struct ccperf_family *ccperf_family_ccccm_set_iv(int argc, char *argv[]);
struct ccperf_family *ccperf_family_ccccm_update(int argc, char *argv[]);
struct ccperf_family *ccperf_family_ccccm_finalize(int argc, char *argv[]);
struct ccperf_family *ccperf_family_ccccm_one_shot(int argc, char *argv[]);
struct ccperf_family *ccperf_family_ccofb_init(int argc, char *argv[]);
struct ccperf_family *ccperf_family_ccofb_update(int argc, char *argv[]);
struct ccperf_family *ccperf_family_ccofb_one_shot(int argc, char *argv[]);
struct ccperf_family *ccperf_family_ccxts_init(int argc, char *argv[]);
struct ccperf_family *ccperf_family_ccxts_set_tweak(int argc, char *argv[]);
struct ccperf_family *ccperf_family_ccxts_update(int argc, char *argv[]);
struct ccperf_family *ccperf_family_ccxts_one_shot(int argc, char *argv[]);
struct ccperf_family *ccperf_family_ccchacha_init(int argc, char *argv[]);
struct ccperf_family *ccperf_family_ccchacha_update(int argc, char *argv[]);
struct ccperf_family *ccperf_family_ccchacha_one_shot(int argc, char *argv[]);
struct ccperf_family *ccperf_family_ccpoly_init(int argc, char *argv[]);
struct ccperf_family *ccperf_family_ccpoly_update(int argc, char *argv[]);
struct ccperf_family *ccperf_family_ccpoly_one_shot(int argc, char *argv[]);
struct ccperf_family *ccperf_family_ccchachapoly_encrypt_and_sign(int argc, char *argv[]);
struct ccperf_family *ccperf_family_ccchachapoly_decrypt_and_verify(int argc, char *argv[]);
struct ccperf_family *ccperf_family_ccsiv_init(int argc, char *argv[]);
struct ccperf_family *ccperf_family_ccsiv_aad_or_nonce(int argc, char *argv[]);
struct ccperf_family *ccperf_family_ccsiv_one_shot(int argc, char *argv[]);
struct ccperf_family *ccperf_family_ccdigest(int argc, char *argv[]);
struct ccperf_family *ccperf_family_cchmac(int argc, char *argv[]);
struct ccperf_family *ccperf_family_ccn(int argc, char *argv[]);
struct ccperf_family *ccperf_family_cczp(int argc, char *argv[]);
struct ccperf_family *ccperf_family_ccec(int argc, char *argv[]);
struct ccperf_family *ccperf_family_ccec25519(int argc, char *argv[]);
struct ccperf_family *ccperf_family_ccec448(int argc, char *argv[]);
struct ccperf_family *ccperf_family_ccrsa(int argc, char *argv[]);
struct ccperf_family *ccperf_family_ccrsabssa(int argc, char *argv[]);
struct ccperf_family *ccperf_family_ccrsa_keygen(int argc, char *argv[]);
struct ccperf_family *ccperf_family_ccpbkdf2(int argc, char *argv[]);
struct ccperf_family *ccperf_family_ccsrp(int argc, char *argv[]);
struct ccperf_family *ccperf_family_ccansikdf(int argc, char *argv[]);
struct ccperf_family *ccperf_family_cccmac(int argc, char *argv[]);
struct ccperf_family *ccperf_family_ccrng(int argc, char *argv[]);
struct ccperf_family *ccperf_family_ccdrbg(int argc, char *argv[]);
struct ccperf_family *ccperf_family_cckprng_init(int argc, char *argv[]);
struct ccperf_family *ccperf_family_cckprng_generate(int argc, char *argv[]);
struct ccperf_family *ccperf_family_cckprng_reseed(int argc, char *argv[]);
struct ccperf_family *ccperf_family_cckprng_refresh(int argc, char *argv[]);
struct ccperf_family *ccperf_family_ccdh_generate_key(int argc, char *argv[]);
struct ccperf_family *ccperf_family_ccdh_compute_shared_secret(int argc, char *argv[]);
struct ccperf_family *ccperf_family_cczp_inv(int argc, char *argv[]);
struct ccperf_family *ccperf_family_ccscrypt(int argc, char *argv[]);
struct ccperf_family *ccperf_family_ccspake(int argc, char *argv[]);
struct ccperf_family *ccperf_family_ccsae(int argc, char *argv[]);
struct ccperf_family *ccperf_family_ccvrf(int argc, char *argv[]);
struct ccperf_family *ccperf_family_ccpolyzp_po2cyc(int argc, char *argv[]);
struct ccperf_family *ccperf_family_cche_bfv(int argc, char *argv[]);
struct ccperf_family *ccperf_family_cche_bgv(int argc, char *argv[]);
struct ccperf_family *ccperf_family_ccprime(int argc, char *argv[]);
struct ccperf_family *ccperf_family_cchpke(int argc, char *argv[]);
struct ccperf_family *ccperf_family_cch2c(int argc, char *argv[]);
struct ccperf_family *ccperf_family_cckeccak(int argc, char *argv[]);
struct ccperf_family *ccperf_family_cckem(int argc, char *argv[]);

/* utility functions */

double histogram_sieve(struct ccperf_family *f, size_t *size, const void *arg);
void ccperf_family_select(struct ccperf_family *f, size_t ntests, void *tests, size_t testsz, int argc, char **argv);
int ccperf_main(int argc, char **argv);

/* in place so we can compare algorithms */
/* Max is greater than 16KB to trigger HW AES when available */
static const size_t symmetric_crypto_data_nbytes[]={16,256,8*1024,24*1024};

#endif /* _CORECRYPTO_CCPERF_H_ */

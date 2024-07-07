/* Copyright (c) (2012-2023) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/ccdigest.h>
#include <corecrypto/ccmd5.h>
#include <corecrypto/ccsha1.h>
#include <corecrypto/ccsha2.h>
#include <corecrypto/cchmac.h>
#include <corecrypto/ccmode.h>
#include <corecrypto/ccmode_factory.h>
#include <corecrypto/ccaes.h>
#include <corecrypto/ccdes.h>
#include <corecrypto/ccpad.h>
#include <corecrypto/ccblowfish.h>
#include <corecrypto/cccast.h>
#include <corecrypto/ccchacha20poly1305.h>
#include "cckprng_internal.h"
#include <corecrypto/ccrng.h>
#include <corecrypto/ccrng_priv.h>
#include "ccrng_cryptographic.h"
#include "ccdrbg_internal.h"
#include "ccrng_crypto.h"
#include "ccrng_rdrand.h"
#include "cc_runtime_config.h"

#include <kern/debug.h>
#include <mach/mach_types.h>
#include <mach-o/loader.h>
#include <libkern/crypto/register_crypto.h>
#include <prng/random.h>

kern_return_t corecrypto_kext_start(kmod_info_t *ki, void *d);
kern_return_t corecrypto_kext_stop(kmod_info_t *ki, void *d);

#include "fipspost.h"

#include <libkern/libkern.h>
#include <pexpert/pexpert.h>

#include "cc_memory.h"

#include <sys/sysctl.h>

static CC_READ_ONLY_LATE(struct crypto_functions) kpis;

static const struct ccchacha20poly1305_fns ccchacha20poly1305_fns = { .info = ccchacha20poly1305_info,
                                                                      .init = ccchacha20poly1305_init,
                                                                      .reset = ccchacha20poly1305_reset,
                                                                      .setnonce = ccchacha20poly1305_setnonce,
                                                                      .incnonce = ccchacha20poly1305_incnonce,
                                                                      .aad = ccchacha20poly1305_aad,
                                                                      .encrypt = ccchacha20poly1305_encrypt,
                                                                      .finalize = ccchacha20poly1305_finalize,
                                                                      .decrypt = ccchacha20poly1305_decrypt,
                                                                      .verify = ccchacha20poly1305_verify };

static struct cckprng_ctx kprng_ctx;
static struct ccrng_state kext_rng_ctx;

static int
ccrng_kext_generate(CC_UNUSED struct ccrng_state *ctx,
                    size_t nbytes,
                    void *rand)
{
    cckprng_generate(&kprng_ctx, 0, nbytes, rand);
    return CCERR_OK;
}

struct ccrng_state *
ccrng(int *error)
{
    if (error) {
        *error = CCERR_OK;
    }

    kext_rng_ctx.generate = ccrng_kext_generate;
    return &kext_rng_ctx;
}

struct ccrng_state *
ccrng_trng(int *error)
{
    if (error) {
        *error = CCERR_NOT_SUPPORTED;
    }

    return NULL;
}

struct ccrng_state *
ccrng_prng(int *error)
{
    return ccrng(error);
}

static struct {
    struct ccdrbg_nistctr_custom drbg_custom;
    struct ccdrbg_info drbg_info;
    ccrng_schedule_constant_ctx_t rng_schedule;
} cc_kext_random_kmem_info;

typedef struct cc_kext_random_kmem {
    ccrng_crypto_ctx_t rng_ctx;
    struct ccdrbg_nistctr_state drbg_ctx;
    uint8_t cache[64];
} cc_kext_random_kmem_t;

// See libkern/crypto/rand.h for CRYPTO_RANDOM_MAX_CTX_SIZE.
cc_static_assert(sizeof(struct cc_kext_random_kmem) <= CRYPTO_RANDOM_MAX_CTX_SIZE, "cc_kext_random_kmem_t too big");
cc_static_assert(sizeof(ccrng_rdrand) <= CRYPTO_RANDOM_MAX_CTX_SIZE, "ccrng_rdrand too big");

static void
cc_kext_random_generate(crypto_random_ctx_t ctx,
                        void *random,
                        size_t random_size)
{
    struct ccrng_state *rng_ctx = (struct ccrng_state *)ctx;
    int err = ccrng_generate(rng_ctx, random_size, random);
    cc_abort_if(err != CCERR_OK, "cc_kext_random_generate: ccrng_generate()");
}

static void
cc_kext_random_uniform(crypto_random_ctx_t ctx,
                       uint64_t bound,
                       uint64_t *random)
{
    struct ccrng_state *rng_ctx = (struct ccrng_state *)ctx;
    int err = ccrng_uniform(rng_ctx, bound, random);
    cc_abort_if(err != CCERR_OK, "cc_kext_random_uniform: ccrng_uniform()");
}

static size_t
cc_kext_random_kmem_ctx_size(void)
{
#if defined(__x86_64__)
    if (CC_HAS_RDRAND()) {
        return sizeof(ccrng_rdrand);
    }
#endif

    return sizeof(cc_kext_random_kmem_t);
}

static void
cc_kext_random_kmem_init(crypto_random_ctx_t ctx)
{
#if defined(__x86_64__)
    if (CC_HAS_RDRAND()) {
        cc_memcpy(ctx, &ccrng_rdrand, sizeof(ccrng_rdrand));
        return;
    }
#endif

    cc_kext_random_kmem_t *rng_ctx = (cc_kext_random_kmem_t *)ctx;

    uint8_t entropy[32];
    int err = ccrng_generate(ccrng(NULL), sizeof(entropy), entropy);
    cc_abort_if(err != CCERR_OK, "cc_kext_random_kmem_init: ccrng_generate()");

    static const char *ps = "cc_kext_random_kmem";
    err = ccdrbg_init(&cc_kext_random_kmem_info.drbg_info,
                      (struct ccdrbg_state *)&rng_ctx->drbg_ctx,
                      sizeof(entropy), entropy,
                      0, NULL,
                      sizeof(ps)-1, ps);
    cc_abort_if(err != CCERR_OK, "cc_kext_random_kmem_init: ccrng_generate()");

    cc_clear(sizeof(entropy), entropy);

    err = ccrng_crypto_init(&rng_ctx->rng_ctx,
                            NULL,
                            (ccrng_schedule_ctx_t *)&cc_kext_random_kmem_info.rng_schedule,
                            NULL,
                            &cc_kext_random_kmem_info.drbg_info,
                            (struct ccdrbg_state *)&rng_ctx->drbg_ctx,
                            1024,
                            32,
                            sizeof(rng_ctx->cache),
                            rng_ctx->cache);
    cc_abort_if(err != CCERR_OK, "cc_kext_random_kmem_init: ccrng_crypto_init()");
}

static void
cc_kext_random_init(void)
{
#if defined(__x86_64__)
    static struct ccmode_ctr ctr_info;
    ccmode_factory_ctr_crypt(&ctr_info, &ccaes_ltc_ecb_encrypt_mode);
    cc_kext_random_kmem_info.drbg_custom.ctr_info = &ctr_info;
#else
    cc_kext_random_kmem_info.drbg_custom.ctr_info = ccaes_ctr_crypt_mode();
#endif
    cc_kext_random_kmem_info.drbg_custom.keylen = CCAES_KEY_SIZE_128;
    cc_kext_random_kmem_info.drbg_custom.strictFIPS = 0;
    cc_kext_random_kmem_info.drbg_custom.df_ctx = NULL;
    ccdrbg_factory_nistctr(&cc_kext_random_kmem_info.drbg_info,
                           &cc_kext_random_kmem_info.drbg_custom);
    ccrng_schedule_constant_init(&cc_kext_random_kmem_info.rng_schedule,
                                 CCRNG_SCHEDULE_CONTINUE);

    // Basic self-tests
    uint8_t random_kmem_ctx[CRYPTO_RANDOM_MAX_CTX_SIZE];
    size_t random_kmem_ctx_size = cc_kext_random_kmem_ctx_size();
    cc_abort_if(random_kmem_ctx_size > CRYPTO_RANDOM_MAX_CTX_SIZE, "cc_kext_random_init: cc_kext_random_kmem_ctx_size()");

    cc_kext_random_kmem_init(random_kmem_ctx);

    uint64_t random;
    cc_kext_random_generate(random_kmem_ctx, &random, sizeof(random));
    cc_kext_random_uniform(random_kmem_ctx, UINT64_MAX, &random);
}

SYSCTL_NODE(_kern, OID_AUTO, prng, CTLFLAG_RD, 0, NULL);

// SYSCTL_QUAD(_kern_prng, OID_AUTO, user_reseed_count, CTLFLAG_RD, &kprng_ctx.fortuna_ctx.userreseed_nreseeds, NULL);
SYSCTL_QUAD(_kern_prng, OID_AUTO, scheduled_reseed_count, CTLFLAG_RD, &kprng_ctx.fortuna_ctx.nreseeds, NULL);
SYSCTL_QUAD(_kern_prng, OID_AUTO, scheduled_reseed_max_sample_count, CTLFLAG_RD, &kprng_ctx.fortuna_ctx.schedreseed_nsamples_max, NULL);
SYSCTL_QUAD(_kern_prng, OID_AUTO, entropy_max_sample_count, CTLFLAG_RD, &kprng_ctx.fortuna_ctx.addentropy_nsamples_max, NULL);

#define SYSCTL_PRNG_POOL(pool_id)                                           \
    SYSCTL_NODE(_kern_prng, OID_AUTO, pool_##pool_id, CTLFLAG_RD, 0, NULL); \
    SYSCTL_QUAD(_kern_prng_pool_##pool_id, OID_AUTO, sample_count, CTLFLAG_RD, &kprng_ctx.fortuna_ctx.pools[pool_id].nsamples, NULL); \
    SYSCTL_QUAD(_kern_prng_pool_##pool_id, OID_AUTO, drain_count, CTLFLAG_RD, &kprng_ctx.fortuna_ctx.pools[pool_id].ndrains, NULL); \
    SYSCTL_QUAD(_kern_prng_pool_##pool_id, OID_AUTO, max_sample_count, CTLFLAG_RD, &kprng_ctx.fortuna_ctx.pools[pool_id].nsamples_max, NULL) \

SYSCTL_PRNG_POOL(0);
SYSCTL_PRNG_POOL(1);
SYSCTL_PRNG_POOL(2);
SYSCTL_PRNG_POOL(3);
SYSCTL_PRNG_POOL(4);
SYSCTL_PRNG_POOL(5);
SYSCTL_PRNG_POOL(6);
SYSCTL_PRNG_POOL(7);
SYSCTL_PRNG_POOL(8);
SYSCTL_PRNG_POOL(9);
SYSCTL_PRNG_POOL(10);
SYSCTL_PRNG_POOL(11);
SYSCTL_PRNG_POOL(12);
SYSCTL_PRNG_POOL(13);
SYSCTL_PRNG_POOL(14);
SYSCTL_PRNG_POOL(15);
SYSCTL_PRNG_POOL(16);
SYSCTL_PRNG_POOL(17);
SYSCTL_PRNG_POOL(18);
SYSCTL_PRNG_POOL(19);
SYSCTL_PRNG_POOL(20);
SYSCTL_PRNG_POOL(21);
SYSCTL_PRNG_POOL(22);
SYSCTL_PRNG_POOL(23);
SYSCTL_PRNG_POOL(24);
SYSCTL_PRNG_POOL(25);
SYSCTL_PRNG_POOL(26);
SYSCTL_PRNG_POOL(27);
SYSCTL_PRNG_POOL(28);
SYSCTL_PRNG_POOL(29);
SYSCTL_PRNG_POOL(30);
SYSCTL_PRNG_POOL(31);

SYSCTL_NODE(_kern, OID_AUTO, crypto, CTLFLAG_RD, 0,
            "Implementations of cryptographic functions");

static char sha1_impl_name[64];
SYSCTL_STRING(_kern_crypto, OID_AUTO, sha1, CTLFLAG_RD, (void *)&sha1_impl_name, 0,
              "SHA1 implementation");

static char sha256_impl_name[64];
SYSCTL_STRING(_kern_crypto, OID_AUTO, sha256, CTLFLAG_RD, (void *)&sha256_impl_name, 0,
              "SHA256 implementation");

static char sha384_impl_name[64];
SYSCTL_STRING(_kern_crypto, OID_AUTO, sha384, CTLFLAG_RD, (void *)&sha384_impl_name, 0,
              "SHA384 implementation");

static char sha512_impl_name[64];
SYSCTL_STRING(_kern_crypto, OID_AUTO, sha512, CTLFLAG_RD, (void *)&sha512_impl_name, 0,
              "SHA512 implementation");

SYSCTL_NODE(_kern_crypto, OID_AUTO, aes, CTLFLAG_RD, 0,
            "Implementations of AES modes");

SYSCTL_NODE(_kern_crypto_aes, OID_AUTO, ecb, CTLFLAG_RD, 0,
            "Implementations of AES-ECB");

static char aes_ecb_encrypt_impl_name[64];
SYSCTL_STRING(_kern_crypto_aes_ecb, OID_AUTO, encrypt, CTLFLAG_RD, (void *)&aes_ecb_encrypt_impl_name, 0,
              "AES-ECB encryption implementation");

static char aes_ecb_decrypt_impl_name[64];
SYSCTL_STRING(_kern_crypto_aes_ecb, OID_AUTO, decrypt, CTLFLAG_RD, (void *)&aes_ecb_decrypt_impl_name, 0,
              "AES-ECB decryption implementation");

SYSCTL_NODE(_kern_crypto_aes, OID_AUTO, xts, CTLFLAG_RD, 0,
            "Implementations of AES-XTS");

static char aes_xts_encrypt_impl_name[64];
SYSCTL_STRING(_kern_crypto_aes_xts, OID_AUTO, encrypt, CTLFLAG_RD, (void *)&aes_xts_encrypt_impl_name, 0,
              "AES-XTS encryption implementation");

static char aes_xts_decrypt_impl_name[64];
SYSCTL_STRING(_kern_crypto_aes_xts, OID_AUTO, decrypt, CTLFLAG_RD, (void *)&aes_xts_decrypt_impl_name, 0,
              "AES-XTS decryption implementation");

static void set_sysctl_impl_names(void)
{
    strlcpy(sha1_impl_name, cc_impl_name(kpis.ccsha1_di->impl), sizeof(sha1_impl_name));
    strlcpy(sha256_impl_name, cc_impl_name(kpis.ccsha256_di->impl), sizeof(sha256_impl_name));
    strlcpy(sha384_impl_name, cc_impl_name(kpis.ccsha384_di->impl), sizeof(sha384_impl_name));
    strlcpy(sha512_impl_name, cc_impl_name(kpis.ccsha512_di->impl), sizeof(sha512_impl_name));

    strlcpy(aes_ecb_encrypt_impl_name, cc_impl_name(kpis.ccaes_ecb_encrypt->impl), sizeof(aes_ecb_encrypt_impl_name));
    strlcpy(aes_ecb_decrypt_impl_name, cc_impl_name(kpis.ccaes_ecb_decrypt->impl), sizeof(aes_ecb_decrypt_impl_name));

    strlcpy(aes_xts_encrypt_impl_name, cc_impl_name(kpis.ccaes_xts_encrypt->impl), sizeof(aes_xts_encrypt_impl_name));
    strlcpy(aes_xts_decrypt_impl_name, cc_impl_name(kpis.ccaes_xts_decrypt->impl), sizeof(aes_xts_decrypt_impl_name));
}

kern_return_t corecrypto_kext_start(kmod_info_t *ki, void *d)
{
#pragma unused(d)

#if CC_FIPSPOST_TRACE
    kprintf("corecrypto_kext_start (tracing enabled)\n");
#else
    kprintf("corecrypto_kext_start (tracing disabled)\n");
#endif

    uint32_t fips_mode;
    if (!PE_parse_boot_argn("fips_mode", &fips_mode, sizeof(fips_mode))) {
        fips_mode = 0;
    }

    int fips_result = fipspost_post(fips_mode, (struct mach_header *)ki->address);
    if (fips_result != CCERR_OK) {
        panic("FIPS Kernel POST Failed (%d)!", fips_result);
    }

    /* Set SIV mode before it is read-only */
    ccaes_siv_encrypt_mode();
    ccaes_siv_decrypt_mode();

    /* Register KPIs */

    /* digests common functions */
    kpis.ccdigest_init_fn = &ccdigest_init;
    kpis.ccdigest_update_fn = &ccdigest_update;
    kpis.ccdigest_fn = &ccdigest;
    /* digest implementations */
    kpis.ccmd5_di = ccmd5_di();
    kpis.ccsha1_di = ccsha1_di();
    kpis.ccsha256_di = ccsha256_di();
    kpis.ccsha384_di = ccsha384_di();
    kpis.ccsha512_di = ccsha512_di();

    /* hmac common function */
    kpis.cchmac_init_fn = &cchmac_init;
    kpis.cchmac_update_fn = &cchmac_update;
    kpis.cchmac_final_fn = &cchmac_final;
    kpis.cchmac_fn = &cchmac;

    /* ciphers modes implementations */
    /* AES, ecb, cbc and xts */
    kpis.ccaes_ecb_encrypt = ccaes_ecb_encrypt_mode();
    kpis.ccaes_ecb_decrypt = ccaes_ecb_decrypt_mode();
    kpis.ccaes_cbc_encrypt = ccaes_cbc_encrypt_mode();
    kpis.ccaes_cbc_decrypt = ccaes_cbc_decrypt_mode();
    kpis.ccaes_ctr_crypt = ccaes_ctr_crypt_mode();
    kpis.ccaes_gcm_encrypt = ccaes_gcm_encrypt_mode();
    kpis.ccaes_gcm_decrypt = ccaes_gcm_decrypt_mode();

    kpis.ccgcm_init_with_iv_fn = &ccgcm_init_with_iv;
    kpis.ccgcm_inc_iv_fn = &ccgcm_inc_iv;

    kpis.ccchacha20poly1305_fns = &ccchacha20poly1305_fns;

    kpis.ccaes_xts_encrypt = ccaes_xts_encrypt_mode();
    kpis.ccaes_xts_decrypt = ccaes_xts_decrypt_mode();
    /* DES, ecb and cbc */
    kpis.ccdes_ecb_encrypt = ccdes_ecb_encrypt_mode();
    kpis.ccdes_ecb_decrypt = ccdes_ecb_decrypt_mode();
    kpis.ccdes_cbc_encrypt = ccdes_cbc_encrypt_mode();
    kpis.ccdes_cbc_decrypt = ccdes_cbc_decrypt_mode();
    /* TDES, ecb and cbc */
    kpis.cctdes_ecb_encrypt = ccdes3_ecb_encrypt_mode();
    kpis.cctdes_ecb_decrypt = ccdes3_ecb_decrypt_mode();
    kpis.cctdes_cbc_encrypt = ccdes3_cbc_encrypt_mode();
    kpis.cctdes_cbc_decrypt = ccdes3_cbc_decrypt_mode();
    /* DES key helper functions */
    kpis.ccdes_key_is_weak_fn = &ccdes_key_is_weak;
    kpis.ccdes_key_set_odd_parity_fn = &ccdes_key_set_odd_parity;
    /* CTS3 padding+encrypt */
    kpis.ccpad_cts3_encrypt_fn = &ccpad_cts3_encrypt;
    kpis.ccpad_cts3_decrypt_fn = &ccpad_cts3_decrypt;

    /* rng */
    kpis.ccrng_fn = &ccrng;

    /* rsa */
    kpis.ccrsa_make_pub_fn = &ccrsa_make_pub;
    kpis.ccrsa_verify_pkcs1v15_fn = &ccrsa_verify_pkcs1v15;

    // Random functions
    kpis.random_generate_fn = cc_kext_random_generate;
    kpis.random_uniform_fn = cc_kext_random_uniform;
    kpis.random_kmem_ctx_size_fn = cc_kext_random_kmem_ctx_size;
    kpis.random_kmem_init_fn = cc_kext_random_kmem_init;

    set_sysctl_impl_names();

    register_crypto_functions(&kpis);

    sysctl_register_oid(&sysctl__kern_prng);
    sysctl_register_oid(&sysctl__kern_prng_scheduled_reseed_count);
    sysctl_register_oid(&sysctl__kern_prng_scheduled_reseed_max_sample_count);
    sysctl_register_oid(&sysctl__kern_prng_entropy_max_sample_count);

#define SYSCTL_REGISTER_OID_PRNG_POOL(pool_id)                          \
    do {                                                                \
        sysctl_register_oid(&sysctl__kern_prng_pool_##pool_id); \
        sysctl_register_oid(&sysctl__kern_prng_pool_##pool_id##_sample_count); \
        sysctl_register_oid(&sysctl__kern_prng_pool_##pool_id##_drain_count); \
        sysctl_register_oid(&sysctl__kern_prng_pool_##pool_id##_max_sample_count); \
    } while (0)                                                         \

    SYSCTL_REGISTER_OID_PRNG_POOL(0);
    SYSCTL_REGISTER_OID_PRNG_POOL(1);
    SYSCTL_REGISTER_OID_PRNG_POOL(2);
    SYSCTL_REGISTER_OID_PRNG_POOL(3);
    SYSCTL_REGISTER_OID_PRNG_POOL(4);
    SYSCTL_REGISTER_OID_PRNG_POOL(5);
    SYSCTL_REGISTER_OID_PRNG_POOL(6);
    SYSCTL_REGISTER_OID_PRNG_POOL(7);
    SYSCTL_REGISTER_OID_PRNG_POOL(8);
    SYSCTL_REGISTER_OID_PRNG_POOL(9);
    SYSCTL_REGISTER_OID_PRNG_POOL(10);
    SYSCTL_REGISTER_OID_PRNG_POOL(11);
    SYSCTL_REGISTER_OID_PRNG_POOL(12);
    SYSCTL_REGISTER_OID_PRNG_POOL(13);
    SYSCTL_REGISTER_OID_PRNG_POOL(14);
    SYSCTL_REGISTER_OID_PRNG_POOL(15);
    SYSCTL_REGISTER_OID_PRNG_POOL(16);
    SYSCTL_REGISTER_OID_PRNG_POOL(17);
    SYSCTL_REGISTER_OID_PRNG_POOL(18);
    SYSCTL_REGISTER_OID_PRNG_POOL(19);
    SYSCTL_REGISTER_OID_PRNG_POOL(20);
    SYSCTL_REGISTER_OID_PRNG_POOL(21);
    SYSCTL_REGISTER_OID_PRNG_POOL(22);
    SYSCTL_REGISTER_OID_PRNG_POOL(23);
    SYSCTL_REGISTER_OID_PRNG_POOL(24);
    SYSCTL_REGISTER_OID_PRNG_POOL(25);
    SYSCTL_REGISTER_OID_PRNG_POOL(26);
    SYSCTL_REGISTER_OID_PRNG_POOL(27);
    SYSCTL_REGISTER_OID_PRNG_POOL(28);
    SYSCTL_REGISTER_OID_PRNG_POOL(29);
    SYSCTL_REGISTER_OID_PRNG_POOL(30);
    SYSCTL_REGISTER_OID_PRNG_POOL(31);

    sysctl_register_oid(&sysctl__kern_crypto);
    sysctl_register_oid(&sysctl__kern_crypto_sha1);
    sysctl_register_oid(&sysctl__kern_crypto_sha256);
    sysctl_register_oid(&sysctl__kern_crypto_sha384);
    sysctl_register_oid(&sysctl__kern_crypto_sha512);
    sysctl_register_oid(&sysctl__kern_crypto_aes);
    sysctl_register_oid(&sysctl__kern_crypto_aes_ecb);
    sysctl_register_oid(&sysctl__kern_crypto_aes_ecb_encrypt);
    sysctl_register_oid(&sysctl__kern_crypto_aes_ecb_decrypt);
    sysctl_register_oid(&sysctl__kern_crypto_aes_xts);
    sysctl_register_oid(&sysctl__kern_crypto_aes_xts_encrypt);
    sysctl_register_oid(&sysctl__kern_crypto_aes_xts_decrypt);

    const struct cckprng_funcs kprng_funcs = {
        .init = cckprng_init,
        .initgen = cckprng_initgen,
        .reseed = cckprng_reseed,
        .refresh = cckprng_refresh,
        .generate = cckprng_generate,
        .init_with_getentropy = cckprng_init_with_getentropy,
    };

    /* Install the kernel PRNG */
    register_and_init_prng(&kprng_ctx, &kprng_funcs);

    // Initialize bespoke RNGs (e.g. for kmem)
    cc_kext_random_init();

    kprintf("corecrypto_kext_start completed successfully\n");

    return KERN_SUCCESS;
}

kern_return_t corecrypto_kext_stop(kmod_info_t *ki CC_UNUSED, void *d CC_UNUSED)
{
    // Corecrypto kext is never unloaded
    return KERN_SUCCESS;
}

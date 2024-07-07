/* Copyright (c) (2022-2024) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/cc_config.h>

#include <corecrypto/cc_priv.h>
#include <corecrypto/ccdigest.h>
#include <corecrypto/cckyber.h>
#include <corecrypto/ccrng_drbg.h>
#include <corecrypto/ccaes.h>
#include "cckem_internal.h"

#include "cckyber_internal.h"

#include "testmore.h"
#include "testbyteBuffer.h"

typedef enum {
    CCKYBER_KAT_TYPE_RND = 0,
    CCKYBER_KAT_TYPE_ENC = 1,
    CCKYBER_KAT_TYPE_DEC = 2,
    CCKYBER_KAT_TYPE_KEY = 3
} cckyber_kat_type;

typedef enum {
    CCKYBER_KAT_RV_PASS = 0,
    CCKYBER_KAT_RV_FAIL = 1
} cckyber_kat_rv;

struct cckyber_kat {
    cckyber_kat_type ty;
    cckyber_kat_rv rv;
    char *seed;
    char *pubkey;
    char *privkey;
    char *msg;
    char *ek;
    char *sk;
    char *dz;
};

struct cckyber_suite {
    const struct cckem_info *info;
    size_t count;
    const struct cckyber_kat *tvs;
};

// https://csrc.nist.gov/Projects/post-quantum-cryptography/post-quantum-cryptography-standardization/example-files
static const struct cckyber_kat kyber768_kat_nist[] = {
#include "./kat/kyber768_nist.inc"
};

static const struct cckyber_kat kyber1024_kat_nist[] = {
#include "./kat/kyber1024_nist.inc"
};

// https://github.com/C2SP/CCTV/tree/main/ML-KEM
static const struct cckyber_kat kyber768_kat_cctv[] = {
#include "./kat/kyber768_cctv.inc"
};

static const struct cckyber_kat kyber1024_kat_cctv[] = {
#include "./kat/kyber1024_cctv.inc"
};

// https://groups.google.com/a/list.nist.gov/g/pqc-forum/c/aCAX-2QrUFw/m/hy5gwcESAAAJ
static const struct cckyber_kat kyber768_kat_bssl[] = {
#include "./kat/kyber768_bssl.inc"
};

static const struct cckyber_kat kyber1024_kat_bssl[] = {
#include "./kat/kyber1024_bssl.inc"
};

// https://github.com/pq-crystals/kyber/tree/standard/ref
static const struct cckyber_kat kyber768_kat_ref[] = {
#include "./kat/kyber768_ref.inc"
};

static const struct cckyber_kat kyber1024_kat_ref[] = {
#include "./kat/kyber1024_ref.inc"
};

static const cckyber_params_t* get_kyber_params(const struct cckem_info *info)
{
    if (info == cckem_kyber1024()) {
        return &cckyber1024_params;
    }

    if (info == cckem_kyber768()) {
        return &cckyber768_params;
    }

    cc_assert(false);
    return NULL;
}

static void cckyber_kat_key(const struct cckyber_suite *suite,
                            const struct cckyber_kat *kat)
{
    const struct cckem_info *info = suite->info;
    const cckyber_params_t *params = get_kyber_params(info);

    byteBuffer kat_dz_buf = hexStringToBytes(kat->dz);
    byteBuffer kat_pubkey_buf = hexStringToBytes(kat->pubkey);
    byteBuffer kat_privkey_buf = hexStringToBytes(kat->privkey);

    uint8_t pubkey[cckem_pubkey_nbytes_info(info)];
    uint8_t privkey[cckem_privkey_nbytes_info(info)];
    int rv = cckyber_kem_keypair_coins(params, pubkey, privkey, kat_dz_buf->bytes);
    is(rv, CCERR_OK, "cckyber_kem_keypair_coins(): Key generation error");

    byteBuffer pubkey_buf = bytesToBytes(pubkey, sizeof(pubkey));
    ok(bytesAreEqual(kat_pubkey_buf, pubkey_buf), "Public key mismatch");

    byteBuffer privkey_buf = bytesToBytes(privkey, sizeof(privkey));
    ok(bytesAreEqual(kat_privkey_buf, privkey_buf), "Private key mismatch");

    cc_assert(kat->rv == CCKYBER_KAT_RV_PASS);
}

static void cckyber_kat_enc(const struct cckyber_suite *suite,
                            const struct cckyber_kat *kat)
{
    const struct cckem_info *info = suite->info;
    const cckyber_params_t *params = get_kyber_params(info);

    byteBuffer kat_pubkey_buf = hexStringToBytes(kat->pubkey);
    byteBuffer kat_msg_buf = hexStringToBytes(kat->msg);
    byteBuffer kat_ek_buf = hexStringToBytes(kat->ek);
    byteBuffer kat_sk_buf = hexStringToBytes(kat->sk);

    uint8_t ek[cckem_encapsulated_key_nbytes_info(info)];
    uint8_t sk[cckem_shared_key_nbytes_info(info)];
    int rv = cckyber_kem_encapsulate_msg(params, kat_pubkey_buf->bytes, ek, sk, kat_msg_buf->bytes);

    if (kat->rv == CCKYBER_KAT_RV_PASS) {
        is(rv, CCERR_OK, "cckyber_kem_encapsulate_msg(): Encapsulation error");

        byteBuffer ek_buf = bytesToBytes(ek, sizeof(ek));
        ok(bytesAreEqual(kat_ek_buf, ek_buf), "Encapsulated key mismatch");

        byteBuffer sk_buf = bytesToBytes(sk, sizeof(sk));
        ok(bytesAreEqual(kat_sk_buf, sk_buf), "Shared key mismatch");
    } else {
        isnt(rv, CCERR_OK, "cckyber_kem_encapsulate_msg(): Encapsulation should fail");
        ok(true, "Three tests per type.");
        ok(true, "Three tests per type.");
    }
}

static void cckyber_kat_dec(const struct cckyber_suite *suite,
                            const struct cckyber_kat *kat)
{
    const struct cckem_info *info = suite->info;
    const cckyber_params_t *params = get_kyber_params(info);

    byteBuffer kat_privkey_buf = hexStringToBytes(kat->privkey);
    byteBuffer kat_ek_buf = hexStringToBytes(kat->ek);
    byteBuffer kat_sk_buf = hexStringToBytes(kat->sk);

    uint8_t sk[cckem_shared_key_nbytes_info(info)];
    int rv = cckyber_kem_decapsulate(params, kat_privkey_buf->bytes, kat_ek_buf->bytes, sk);
    is(rv, CCERR_OK, "cckyber_kem_decapsulate(): Decapsulation error");

    byteBuffer sk_buf = bytesToBytes(sk, sizeof(sk));
    bool sk_eq = bytesAreEqual(kat_sk_buf, sk_buf);

    if (kat->rv == CCKYBER_KAT_RV_PASS) {
        ok(sk_eq, "Shared key mismatch");
    } else {
        ok(!sk_eq, "Shared keys shouldn't match");
    }

    ok(true, "Three tests per type.");
}

static void cckyber_kat(const struct cckyber_suite *suite)
{
    const struct cckyber_kat *kats = suite->tvs;

    for (size_t i = 0; i < suite->count; i++) {
        if (kats[i].ty == CCKYBER_KAT_TYPE_KEY) {
            cckyber_kat_key(suite, &kats[i]);
        } else if (kats[i].ty == CCKYBER_KAT_TYPE_ENC) {
            cckyber_kat_enc(suite, &kats[i]);
        } else if (kats[i].ty == CCKYBER_KAT_TYPE_DEC) {
            cckyber_kat_dec(suite, &kats[i]);
        } else {
            cc_assert(0);
        }
    }
}

static void cckyber_kat_ref(const struct cckyber_suite *suite)
{
    const struct cckem_info *info = suite->info;
    const struct cckyber_kat *kats = suite->tvs;

    cckem_full_ctx_decl(info, ctx);

    for (size_t i = 0; i < suite->count; i++) {
        // Initialize RNG
        byteBuffer seed_buf = hexStringToBytes(kats[i].seed);

        struct ccdrbg_nistctr_custom custom = {
            .ctr_info = ccaes_ctr_crypt_mode(),
            .keylen = 32,
            .strictFIPS = 0,
            .df_ctx = NULL,
        };
        static struct ccdrbg_info drbg_info;
        ccdrbg_factory_nistctr(&drbg_info, &custom);
        uint8_t state[drbg_info.size];
        struct ccdrbg_state *drbg_state = (struct ccdrbg_state *)state;
        ok(ccdrbg_init(&drbg_info, drbg_state, 48, seed_buf->bytes, 0, NULL, 0, NULL) == CCERR_OK, "ccdrbg_init failed");
        struct ccrng_drbg_state drbg_ctx;
        ok(ccrng_drbg_init_withdrbg(&drbg_ctx, &drbg_info, drbg_state) == CCERR_OK, "ccrng_drbg_init_withdrbg failed");
        struct ccrng_state *det_rng = (struct ccrng_state *)&drbg_ctx;

        // Generate key
        cckem_full_ctx_init(ctx, info);

        is(cckem_generate_key(ctx, det_rng), CCERR_OK, "cckem_generate_key failed");

        byteBuffer kat_pubkey_buf = hexStringToBytes(kats[i].pubkey);

        is(info->pubkey_nbytes, kat_pubkey_buf->len, "KAT public key incorrect size");
        byteBuffer pubkey_buf = bytesToBytes(cckem_ctx_pubkey(cckem_public_ctx(ctx)), info->pubkey_nbytes);

        ok(bytesAreEqual(kat_pubkey_buf, pubkey_buf), "Public key mismatch");
        byteBuffer kat_privkey_buf = hexStringToBytes(kats[i].privkey);
        is(info->fullkey_nbytes - info->pubkey_nbytes, kat_privkey_buf->len, "KAT private key incorrect size");

        byteBuffer privkey_buf = bytesToBytes(cckem_ctx_privkey(ctx), info->fullkey_nbytes - info->pubkey_nbytes);
        ok(bytesAreEqual(kat_privkey_buf, privkey_buf), "Private key mismatch");

        // Encapsulate
        byteBuffer kat_ek_buf = hexStringToBytes(kats[i].ek);
        is(cckem_encapsulated_key_nbytes_info(info), kat_ek_buf->len, "KAT encapsulated key incorrect size");

        byteBuffer kat_sk_buf = hexStringToBytes(kats[i].sk);
        is(cckem_shared_key_nbytes_info(info), kat_sk_buf->len, "KAT shared key incorrect size");

        uint8_t ek[cckem_encapsulated_key_nbytes_info(info)];
        uint8_t sk_enc[cckem_shared_key_nbytes_info(info)];

        is(cckem_encapsulate(cckem_public_ctx(ctx), cckem_encapsulated_key_nbytes_info(info), ek, cckem_shared_key_nbytes_info(info), sk_enc, det_rng),
           CCERR_OK,
           "cckem_encapsulate: Encapsulation error");

        byteBuffer sk_enc_buf = bytesToBytes(sk_enc, cckem_shared_key_nbytes_info(info));
        ok(bytesAreEqual(kat_sk_buf, sk_enc_buf), "Shared key mismatch during encapsulation");

        byteBuffer ek_buf = bytesToBytes(ek, cckem_encapsulated_key_nbytes_info(info));
        ok(bytesAreEqual(kat_ek_buf, ek_buf), "Encapsulated key mismatch");

        // Decapsulate
        uint8_t sk_dec[cckem_shared_key_nbytes_info(info)];
        is(cckem_decapsulate(ctx, cckem_encapsulated_key_nbytes_info(info), ek, cckem_shared_key_nbytes_info(info), sk_dec), CCERR_OK, "cckem_decapsulate: Decapsulation error");

        byteBuffer sk_dec_buf = bytesToBytes(sk_dec, cckem_shared_key_nbytes_info(info));
        ok(bytesAreEqual(kat_sk_buf, sk_dec_buf), "Shared key mismatch during decapsulation");

        cckem_full_ctx_clear(info, ctx);
    }
}

int cckyber_tests(TM_UNUSED int argc, TM_UNUSED char *const *argv)
{
    const struct cckyber_suite kyber_suites[] = {
        { cckem_kyber768(), CC_ARRAY_LEN(kyber768_kat_nist), kyber768_kat_nist },
        { cckem_kyber1024(), CC_ARRAY_LEN(kyber1024_kat_nist), kyber1024_kat_nist },
        { cckem_kyber768(), CC_ARRAY_LEN(kyber768_kat_cctv), kyber768_kat_cctv },
        { cckem_kyber1024(), CC_ARRAY_LEN(kyber1024_kat_cctv), kyber1024_kat_cctv },
        { cckem_kyber768(), CC_ARRAY_LEN(kyber768_kat_bssl), kyber768_kat_bssl },
        { cckem_kyber1024(), CC_ARRAY_LEN(kyber1024_kat_bssl), kyber1024_kat_bssl }
    };

    const struct cckyber_suite kyber_suites_ref[] = {
        { cckem_kyber768(), CC_ARRAY_LEN(kyber768_kat_ref), kyber768_kat_ref },
        { cckem_kyber1024(), CC_ARRAY_LEN(kyber1024_kat_ref), kyber1024_kat_ref }
    };

    int ntests = 0;
    for (size_t i = 0; i < CC_ARRAY_LEN(kyber_suites); i++) {
        ntests += 3 * kyber_suites[i].count;
    }
    for (size_t i = 0; i < CC_ARRAY_LEN(kyber_suites_ref); i++) {
        ntests += 14 * kyber_suites_ref[i].count;
    }
    plan_tests(ntests);

    for (size_t i = 0; i < CC_ARRAY_LEN(kyber_suites); i++) {
        cckyber_kat(&kyber_suites[i]);
    }

    for (size_t i = 0; i < CC_ARRAY_LEN(kyber_suites_ref); i++) {
        cckyber_kat_ref(&kyber_suites_ref[i]);
    }

    return 0;
}

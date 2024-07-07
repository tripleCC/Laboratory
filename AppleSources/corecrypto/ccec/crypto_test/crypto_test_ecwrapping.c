/* Copyright (c) (2015,2016,2019,2021,2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/ccec.h>
#include <corecrypto/ccec_priv.h>
#include <corecrypto/ccrng_test.h>
#include <corecrypto/ccsha1.h>
#include <corecrypto/ccsha2.h>
#include <corecrypto/ccrng_pbkdf2_prng.h>
#include <corecrypto/ccrng_sequence.h>
#include "crypto_test_ec.h"

#include "testmore.h"
#include "testbyteBuffer.h"
#include "testccnBuffer.h"

#include <corecrypto/ccec_priv.h>

// PGP Key wrapping
static bool
ECPGPWrapUnwrapTest(struct ccrng_state * rng,
                    unsigned long flags,
                    size_t keysize,
                    ccec_const_cp_t cp,
                    const struct ccec_rfc6637_curve *curve,
                    const struct ccec_rfc6637_wrap *wrap,
                    const struct ccec_rfc6637_unwrap *unwrap)
{
    ccec_full_ctx_decl_cp(cp, peer);

    ok(ccec_generate_key(cp, rng, peer) == 0, "Generated Key");

    uint8_t key[keysize];

    memset(key, 0x23, sizeof(key));

    // ------------------------------
    // Wrap
    // ------------------------------
    size_t wrapped_size = ccec_rfc6637_wrap_key_size(ccec_ctx_pub(peer), flags, keysize);

    uint8_t wrapped_key[wrapped_size];
    uint8_t fingerprint[20];

    ok_status_or_goto(ccec_rfc6637_wrap_key(ccec_ctx_pub(peer), wrapped_key, flags, 0,
                                            keysize, key, curve, wrap,
                                            fingerprint, rng), "pgp wrap",errOut);

    // ------------------------------
    // UnWrap
    // ------------------------------
    uint8_t alg;
    uint8_t unwrapped_key[100];
    size_t unwrapped_key_size = sizeof(unwrapped_key);

    ok_status_or_goto(ccec_rfc6637_unwrap_key(peer,
                                              &unwrapped_key_size, unwrapped_key,
                                              flags, &alg, curve, unwrap,
                                              fingerprint,
                                              wrapped_size, wrapped_key), "pgp unwrap",errOut);

    is(unwrapped_key_size,keysize, "check keysize");
    ok_memcmp(key, unwrapped_key, keysize, "check key");

    // ------------------------------
    // Negative testing
    // ------------------------------

    // check that unwrap refused to support compact keys if flag isn't passed in
    if (flags & CCEC_RFC6637_COMPACT_KEYS) {
        unsigned long nflags = flags & ~(unsigned long)CCEC_RFC6637_COMPACT_KEYS;
        ok_or_fail(ccec_rfc6637_unwrap_key(peer,
                                           &unwrapped_key_size, unwrapped_key,
                                           nflags, &alg, curve, unwrap, fingerprint,
                                           wrapped_size, wrapped_key) != 0, "pgp unwrap compact keys");
    }

    // permutate each byte
    for (size_t i = 0; i < wrapped_size; i++) {
        uint8_t wrapped_key_copy[wrapped_size];
        memcpy(wrapped_key_copy,wrapped_key,wrapped_size);
        wrapped_key_copy[i] ^= (cc_rand(254) + 1);
        while
            (
             // i==2 Special case, x9.63 public key allows for 4,6,7.
             ((i==2)
                && !(flags & CCEC_RFC6637_COMPACT_KEYS)
                && ((wrapped_key_copy[2]==4) || (wrapped_key_copy[2]==6) || (wrapped_key_copy[2]==7)))
             // i==1 Because we align to multiple of 8bit so that mutation of
             // least significant bits are not detected as errors.
            || ((i==1)
                && (CC_BITLEN_TO_BYTELEN(wrapped_key_copy[1])==CC_BITLEN_TO_BYTELEN(wrapped_key[1])))
             )
        {
            wrapped_key_copy[i] ^= (cc_rand(254) + 1);
        }
        unwrapped_key_size=sizeof(unwrapped_key);
        int rc=ccec_rfc6637_unwrap_key(peer, &unwrapped_key_size, unwrapped_key,
                                       flags, &alg, curve, unwrap, fingerprint,
                                       sizeof(wrapped_key_copy), wrapped_key_copy);

        ok(rc != 0, "pgp mutation: byte %d changed from %.2x to %.2x, flags %d",i,wrapped_key[i],wrapped_key_copy[i],flags);
    }

    return true;
errOut:
    return false;
}


// PGP Key wrapping with public key diversification.
// Known Answer Test from 23493000

struct ccecwrapping_vector {
    ccec_const_cp_t (*cp)(void);
    const struct ccec_rfc6637_curve *curve;
    const struct ccec_rfc6637_wrap *wrap;
    const struct ccec_rfc6637_unwrap *unwrap;
    unsigned long flags;
    uint8_t alg;
    const char *str_der_priv_key;
    const char *str_x963_pub_key;
    const char *str_diversify_entropy;
    const char *str_der_diversified_pub_key;
    const char *str_key;
    const char *str_der_ephemeral_priv_key; // Used within wrapping
    const char *str_wrapped_key;
    const char *str_fingerprint;
};

static const struct ccecwrapping_vector ccecwrapping_vectors[] =
{
#include "../test_vectors/ecwrapping.inc"
};

static bool
ECPGP_KAT_vector(struct ccrng_state * rng,
                 const struct ccecwrapping_vector *test_vector)
{
    bool rc=false;
    ccec_const_cp_t cp=test_vector->cp();
    unsigned long flags=test_vector->flags;
    const struct ccec_rfc6637_curve *curve=test_vector->curve;
    const struct ccec_rfc6637_wrap   *wrap=test_vector->wrap;
    const struct ccec_rfc6637_unwrap *unwrap=test_vector->unwrap;

    byteBuffer der_ec_priv_key = hexStringToBytes(test_vector->str_der_priv_key);
    byteBuffer x963_ec_pub_key = hexStringToBytes(test_vector->str_x963_pub_key);
    byteBuffer diversify_entropy = hexStringToBytes(test_vector->str_diversify_entropy);
    byteBuffer diversified_pub_key = hexStringToBytes(test_vector->str_der_diversified_pub_key);
    byteBuffer wrapped_key = hexStringToBytes(test_vector->str_wrapped_key);
    byteBuffer key = hexStringToBytes(test_vector->str_key);
    byteBuffer fingerprint = hexStringToBytes(test_vector->str_fingerprint);
    byteBuffer str_der_ephemeral_priv_key = hexStringToBytes(test_vector->str_der_ephemeral_priv_key);
    ccec_pub_ctx_decl_cp(cp, peer_div_pub);
    ccec_pub_ctx_decl_cp(cp, peer_div_gen);
    ccec_full_ctx_decl_cp(cp, peer);
    size_t  unwrapped_key_size=100;
    uint8_t unwrapped_key[unwrapped_key_size];
    uint8_t peer_public_key[200];
    uint8_t alg;

    ccec_pub_ctx_t pk = ccec_ctx_pub(peer);

    // Import the private key
    ok_status_or_goto(ccec_der_import_priv(cp, der_ec_priv_key->len, der_ec_priv_key->bytes, peer), "import key",errOut);

    // Check the corresponding public key is matching
    cc_assert(ccec_export_pub_size(pk)<sizeof(peer_public_key));
    is(ccec_export_pub(pk, peer_public_key), CCERR_OK, "Export peer public key");
    ok_memcmp_or_fail(peer_public_key,x963_ec_pub_key->bytes,x963_ec_pub_key->len,"Reconstructed key matches the expect value");

    // ------------------------------
    // Diversify key
    // ------------------------------

    if (diversify_entropy->len) {
        // Diversify key from a seed
        ok_status_or_goto(ccec_diversify_pub(cp, pk,
                                     diversify_entropy->len,diversify_entropy->bytes,
                                     rng,
                                     peer_div_gen,
                                     peer_div_pub), "diversify public key",errOut);
        if (diversified_pub_key->len) {
            size_t exported_div_size=ccec_der_export_diversified_pub_size(peer_div_gen,
                                                                           peer_div_pub,flags);
            uint8_t exported_div_pub[exported_div_size];
            ok(NULL!=ccec_der_export_diversified_pub(peer_div_gen,
                                            peer_div_pub,
                                            flags,
                                            sizeof(exported_div_pub),
                                            exported_div_pub), "KAT export diversified public key");
            is(sizeof(exported_div_pub),diversified_pub_key->len, "KAT exported diversified size");
            ok_memcmp_or_fail(exported_div_pub,
                      diversified_pub_key->bytes,
                      diversified_pub_key->len, "KAT exported diversified key");
        }
    }
    else if (diversified_pub_key->len) {
        // Import the diversified key
        ok_status_or_goto(ccec_der_import_diversified_pub(cp,
                diversified_pub_key->len, diversified_pub_key->bytes, NULL, peer_div_gen, peer_div_pub), "import diversified key",errOut);
    }
    
    // ------------------------------
    // Wrap
    // ------------------------------

    if (str_der_ephemeral_priv_key->len) {
        // Force a known key during wrapping
        struct ccrng_ecfips_test_state kat_rng;
        cc_require(ccrng_ecfips_test_init(&kat_rng, str_der_ephemeral_priv_key->len, str_der_ephemeral_priv_key->bytes) == 0,errOut);

        size_t  wrapped_size = ccec_rfc6637_wrap_key_size(pk, flags, key->len);
        uint8_t wrapped_key_buf[wrapped_size];

        if (diversified_pub_key->len) {
            // Diversified wrapping
            ok_status_or_goto(ccec_rfc6637_wrap_key_diversified(peer_div_gen,peer_div_pub,
                                                wrapped_key_buf, flags, test_vector->alg,
                                                key->len, key->bytes,
                                                curve, wrap,
                                                fingerprint->bytes,
                                                (struct ccrng_state *)&kat_rng), "pgp kat wrap",errOut);
        } else {
            // Standard wrapping
            ok_status_or_goto(ccec_rfc6637_wrap_key(pk, wrapped_key_buf, flags, 0,
                                                    key->len, key->bytes,
                                                    curve, wrap,
                                                    fingerprint->bytes,
                                                    (struct ccrng_state *)&kat_rng), "pgp kat wrap",errOut);
        }
        is(wrapped_size,wrapped_key->len, "check wrapped keysize");
        ok_memcmp_or_fail(wrapped_key_buf,wrapped_key->bytes, wrapped_key->len, "check wrapped key");
    }

    // ------------------------------
    // UnWrap
    // ------------------------------

    ok_status_or_goto(ccec_rfc6637_unwrap_key(peer,
                               &unwrapped_key_size, unwrapped_key,
                               flags, &alg, curve, unwrap, fingerprint->bytes,
                               wrapped_key->len, wrapped_key->bytes), "pgp kat unwrap",errOut);

    is(unwrapped_key_size,key->len, "check unwrapped keysize");
    ok_memcmp_or_fail(key->bytes, unwrapped_key, key->len, "check unwrapped key");
    is(alg,test_vector->alg, "symalg");

    rc=true;
errOut:
    free(der_ec_priv_key);
    free(x963_ec_pub_key);
    free(diversified_pub_key);
    free(wrapped_key);
    free(key);
    free(fingerprint);
    free(diversify_entropy);
    free(str_der_ephemeral_priv_key);
    return rc;
}

static void
ECPGP_KAT_Test(struct ccrng_state * rng) {
    for (size_t i=0;i<CC_ARRAY_LEN(ccecwrapping_vectors);i++) {
        ok(ECPGP_KAT_vector(rng,&ccecwrapping_vectors[i]), "EC wrapping KAT, test #%d",i);
    }
}


// PGP Key wrapping with public key diversification.
static bool
ECPGPDiversifiedWrapUnwrapTest(struct ccrng_state * rng,
                               unsigned long flags,
                               size_t keysize,
                               ccec_const_cp_t cp,
                               const struct ccec_rfc6637_curve *curve,
                               const struct ccec_rfc6637_wrap *wrap,
                               const struct ccec_rfc6637_unwrap *unwrap)
{
    ccec_full_ctx_decl_cp(cp, peer);

    // ------------------------------
    // Generate a peer key pair
    // ------------------------------
    ok(ccec_generate_key(cp, rng, peer) == 0, "Generated Key");

    // ------------------------------
    // Anonymizer: Diversify the public key
    // ------------------------------
    ccec_pub_ctx_decl_cp(cp, peer_diversified_generator);
    ccec_pub_ctx_decl_cp(cp, peer_diversified_pub_key);

    ccec_pub_ctx_t pk = ccec_ctx_pub(peer);
    
    // Diversify key
    uint8_t entropy[ccec_diversify_min_entropy_len(cp)];
    ok_status(ccrng_generate(rng,sizeof(entropy),entropy), "entropy generation");
    ok_status(ccec_diversify_pub(cp, pk,
                       sizeof(entropy),entropy,
                       rng,
                       peer_diversified_generator,
                       peer_diversified_pub_key), "diversify public key");

    // Export key
    uint8_t exported_div_pub[ccec_der_export_diversified_pub_size(peer_diversified_generator,
                                                                  peer_diversified_pub_key,flags)];
    ok(NULL!=ccec_der_export_diversified_pub(peer_diversified_generator,
                                    peer_diversified_pub_key,
                                    flags,
                                    sizeof(exported_div_pub),
                                    exported_div_pub), "Export diversified pub key");

    ccec_pub_ctx_decl_cp(cp, peer_imported_diversified_generator);
    ccec_pub_ctx_decl_cp(cp, peer_imported_diversified_pub_key);

    ok_status(ccec_der_import_diversified_pub(cp,
                                    sizeof(exported_div_pub),exported_div_pub,
                                    NULL,
                                    peer_imported_diversified_generator,
                                    peer_imported_diversified_pub_key), "Import diversified pub key");

    // Import key
    ok((ccec_ctx_n(peer_diversified_pub_key)==ccec_ctx_n(peer_imported_diversified_pub_key))
       && ccn_cmp(ccec_ctx_n(peer_diversified_generator),
               ccec_ctx_x(peer_diversified_generator),
               ccec_ctx_x(peer_imported_diversified_generator))==0, "Import diversified generator");

    ok((ccec_ctx_n(peer_diversified_pub_key)==ccec_ctx_n(peer_imported_diversified_pub_key))
       && ccn_cmp(ccec_ctx_n(peer_diversified_pub_key),
               ccec_ctx_x(peer_diversified_pub_key),
               ccec_ctx_x(peer_imported_diversified_pub_key))==0, "Import diversified public key");

    ccec_pub_ctx_clear_cp(cp, peer_diversified_generator);
    ccec_pub_ctx_clear_cp(cp, peer_diversified_pub_key);

    // ------------------------------
    // Wrap / Unwrap
    // ------------------------------

    // Wrap
    uint8_t key[keysize];
    memset(key, 0x23, sizeof(key));

    size_t wrapped_size = ccec_rfc6637_wrap_key_size(pk, flags, keysize);

    uint8_t wrapped_key[wrapped_size];
    uint8_t fingerprint[20]="fingerprint";

    ok_status_or_goto(ccec_rfc6637_wrap_key_diversified(
                             peer_imported_diversified_generator,
                             peer_imported_diversified_pub_key,
                             wrapped_key, flags, 0,
                             keysize, key, curve, wrap, fingerprint, rng), "pgp wrap",errOut);

    uint8_t alg;
    uint8_t unwrapped_key[100];
    size_t  unwrapped_key_size = sizeof(unwrapped_key);

    // UnWrap
    ok_status_or_goto(ccec_rfc6637_unwrap_key(peer,
                                              &unwrapped_key_size, unwrapped_key,
                                              flags, &alg, curve, unwrap,
                                              fingerprint,
                                              wrapped_size, wrapped_key), "pgp unwrap",errOut);

    is(unwrapped_key_size,keysize, "check keysize");
    ok_memcmp(key, unwrapped_key, keysize, "check key");

    return true;
errOut:
    return false;
}

int
ecwrapping_tests(void)
{
    const int verbose=1;
    struct ccrng_state *rng = global_test_rng;

    if(verbose) diag("KAT rfc6637 wrap");
    ECPGP_KAT_Test(rng);

    if(verbose) diag("Standard rfc6637 wrap");
    ok(ECPGPWrapUnwrapTest(rng, 0, 16, ccec_cp_256(), &ccec_rfc6637_dh_curve_p256, &ccec_rfc6637_wrap_sha256_kek_aes128, &ccec_rfc6637_unwrap_sha256_kek_aes128),  "EC PGP wrap 256 bit key 16");
    ok(ECPGPWrapUnwrapTest(rng, 0, 16, ccec_cp_521(), &ccec_rfc6637_dh_curve_p521, &ccec_rfc6637_wrap_sha256_kek_aes128, &ccec_rfc6637_unwrap_sha256_kek_aes128), "EC PGP wrap 521 bit key 16");
    ok(ECPGPWrapUnwrapTest(rng, 0, 32, ccec_cp_256(), &ccec_rfc6637_dh_curve_p256, &ccec_rfc6637_wrap_sha256_kek_aes128, &ccec_rfc6637_unwrap_sha256_kek_aes128),  "EC PGP wrap 256 bit key 32");
    ok(ECPGPWrapUnwrapTest(rng, 0, 32, ccec_cp_521(), &ccec_rfc6637_dh_curve_p521, &ccec_rfc6637_wrap_sha256_kek_aes128, &ccec_rfc6637_unwrap_sha256_kek_aes128), "EC PGP wrap 521 bit key 32");
    ok(ECPGPWrapUnwrapTest(rng, CCEC_RFC6637_COMPACT_KEYS, 16, ccec_cp_256(), &ccec_rfc6637_dh_curve_p256, &ccec_rfc6637_wrap_sha256_kek_aes128, &ccec_rfc6637_unwrap_sha256_kek_aes128),  "EC PGP wrap 256 bit key 16");
    ok(ECPGPWrapUnwrapTest(rng, CCEC_RFC6637_COMPACT_KEYS, 16, ccec_cp_521(), &ccec_rfc6637_dh_curve_p521, &ccec_rfc6637_wrap_sha256_kek_aes128, &ccec_rfc6637_unwrap_sha256_kek_aes128), "EC PGP wrap 521 bit key 16");
    ok(ECPGPWrapUnwrapTest(rng, CCEC_RFC6637_COMPACT_KEYS, 32, ccec_cp_256(), &ccec_rfc6637_dh_curve_p256, &ccec_rfc6637_wrap_sha256_kek_aes128, &ccec_rfc6637_unwrap_sha256_kek_aes128),  "EC PGP wrap 256 bit key 32");
    ok(ECPGPWrapUnwrapTest(rng, CCEC_RFC6637_COMPACT_KEYS, 32, ccec_cp_521(), &ccec_rfc6637_dh_curve_p521, &ccec_rfc6637_wrap_sha256_kek_aes128, &ccec_rfc6637_unwrap_sha256_kek_aes128), "EC PGP wrap 521 bit key 32");

    if(verbose) diag("Diversified compact rfc6637 wrap");
    ok(ECPGPDiversifiedWrapUnwrapTest(rng, CCEC_RFC6637_COMPACT_KEYS | CCEC_EXPORT_COMPACT_DIVERSIFIED_KEYS,
                                      16, ccec_cp_256(), &ccec_rfc6637_dh_curve_p256, &ccec_rfc6637_wrap_sha256_kek_aes128, &ccec_rfc6637_unwrap_sha256_kek_aes128),  "EC PGP wrap 256 bit key 16, with public key diversification");
    ok(ECPGPDiversifiedWrapUnwrapTest(rng, CCEC_RFC6637_COMPACT_KEYS | CCEC_EXPORT_COMPACT_DIVERSIFIED_KEYS,
                                      16, ccec_cp_521(), &ccec_rfc6637_dh_curve_p521, &ccec_rfc6637_wrap_sha256_kek_aes128, &ccec_rfc6637_unwrap_sha256_kek_aes128), "EC PGP wrap 521 bit key 16, with public key diversification");
    ok(ECPGPDiversifiedWrapUnwrapTest(rng, CCEC_RFC6637_COMPACT_KEYS | CCEC_EXPORT_COMPACT_DIVERSIFIED_KEYS,
                                      32, ccec_cp_256(), &ccec_rfc6637_dh_curve_p256, &ccec_rfc6637_wrap_sha256_kek_aes128, &ccec_rfc6637_unwrap_sha256_kek_aes128),  "EC PGP wrap 256 bit key 32, with public key diversification");
    ok(ECPGPDiversifiedWrapUnwrapTest(rng, CCEC_RFC6637_COMPACT_KEYS | CCEC_EXPORT_COMPACT_DIVERSIFIED_KEYS,
                                      32, ccec_cp_521(), &ccec_rfc6637_dh_curve_p521, &ccec_rfc6637_wrap_sha256_kek_aes128, &ccec_rfc6637_unwrap_sha256_kek_aes128), "EC PGP wrap 521 bit key 32, with public key diversification");
    
    if(verbose) diag("Diversified rfc6637 wrap");
    ok(ECPGPDiversifiedWrapUnwrapTest(rng, 0, 16, ccec_cp_256(), &ccec_rfc6637_dh_curve_p256, &ccec_rfc6637_wrap_sha256_kek_aes128, &ccec_rfc6637_unwrap_sha256_kek_aes128),  "EC PGP wrap 256 bit key 16, with public key diversification");
    ok(ECPGPDiversifiedWrapUnwrapTest(rng, 0, 16, ccec_cp_521(), &ccec_rfc6637_dh_curve_p521, &ccec_rfc6637_wrap_sha256_kek_aes128, &ccec_rfc6637_unwrap_sha256_kek_aes128), "EC PGP wrap 521 bit key 16, with public key diversification");
    ok(ECPGPDiversifiedWrapUnwrapTest(rng, 0, 32, ccec_cp_256(), &ccec_rfc6637_dh_curve_p256, &ccec_rfc6637_wrap_sha256_kek_aes128, &ccec_rfc6637_unwrap_sha256_kek_aes128),  "EC PGP wrap 256 bit key 32, with public key diversification");
    ok(ECPGPDiversifiedWrapUnwrapTest(rng, 0, 32, ccec_cp_521(), &ccec_rfc6637_dh_curve_p521, &ccec_rfc6637_wrap_sha256_kek_aes128, &ccec_rfc6637_unwrap_sha256_kek_aes128), "EC PGP wrap 521 bit key 32, with public key diversification");

    return 1;
}

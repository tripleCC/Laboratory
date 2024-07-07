/* Copyright (c) (2014-2016,2018,2019,2021-2023) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "testmore.h"
#include "testbyteBuffer.h"
#include "testccnBuffer.h"
#include "cc_priv.h"

#if (CCEC25519 == 0)
entryPoint(ccec25519_tests, "ccec25519 test")
#else

#include <corecrypto/ccsha2.h>
#include <corecrypto/ccec25519.h>
#include <corecrypto/ccec25519_priv.h>
#include <corecrypto/ccrng_sequence.h>
#include "ccec25519_internal.h"
#include "cced25519_internal.h"

static int verbose = 0;

typedef struct {
    const char *e;
    const char *k;
    const char *ek;
    int rv;
} x25519_test_vector;

static const x25519_test_vector x25519_test_vectors[] = {
#include "crypto_test_x25519.inc"
};

typedef struct {
    uint8_t sk[32];
    uint8_t pk[32];
    uint8_t sig[64];
    size_t len;
    const void *msg;

} ed25519_test_vector;

static const ed25519_test_vector ed25519_test_vectors[] = {
#include "crypto_test_ed25519.inc"
};

static void test_x25519_kat(ccec_const_cp_t cp)
{
    int good;
    size_t i, n;
    uint8_t ek2[32], ek3[32], ek4[32];
    struct ccrng_state *rng = global_test_rng;

    n = CC_ARRAY_LEN(x25519_test_vectors);
    for (i = 0; i < n; ++i) {
        const x25519_test_vector *const tv = &x25519_test_vectors[i];
        byteBuffer e = hexStringToBytes(tv->e);
        byteBuffer k = hexStringToBytes(tv->k);
        byteBuffer ek = hexStringToBytes(tv->ek);

        good = (e->len == 32);
        good &= (k->len == 32);
        good &= (ek->len == 32);
        if (good) {
            cc_clear(sizeof(ek2), ek2);
            int rv = cccurve25519_internal(cp, ek2, e->bytes, k->bytes, rng);
            is(rv, tv->rv, "cccurve25519_internal() != rv");
            good = (memcmp(ek->bytes, ek2, 32) == 0);
        }

        free(e);
        free(k);
        free(ek);

        ok(good, "Check test vector %zu", i + 1);
    }

    // Non-canonical tests (not used in normal Curve25519, but detects issues when used with Ed25519).

    // This is a non canonical test.
    // Public key is 2^255.
    //  If MSbit is NOT masked, equivalent (2^256 - 1) mod (2^255 - 19) = 0x25
    //  If MSbit IS masked, equivalent to  (2^255 - 1) mod (2^255 - 19) = 0x12
    int rv = cccurve25519_internal(cp, ek2,
        (const uint8_t *)"\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        (const uint8_t *)"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"
                         "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF", rng); // Public key set to 2^256-1
    is(rv, CCERR_OK, "cccurve25519_internal() failed");

    rv = cccurve25519_internal(cp, ek3,
                 (const uint8_t *)"\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                                  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                 (const uint8_t *)"\x25\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                                  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", rng); // Public key set to 0x25
    is(rv, CCERR_OK, "cccurve25519_internal() failed");

    rv = cccurve25519_internal(cp, ek4,
                 (const uint8_t *)"\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                                  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                 (const uint8_t *)"\x12\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                                  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", rng); // Public key set to 0x12
    is(rv, CCERR_OK, "cccurve25519_internal() failed");

    // If truncation, ek2 == ek4. If no truncation ek2 == ek3. If bug, ek2 neither == ek3 nor ek4.
    good = ((memcmp(ek2, ek3, 32) != 0) && (memcmp(ek2, ek4, 32) == 0));
    ok(good, "Non-canonical tests: most significant bit masking failure");
}

static void test_x25519_roundtrip(void)
{
    ccec25519pubkey pk1, pk2;
    ccec25519secretkey sk1, sk2;
    ccec25519key sess1, sess2;
    struct ccrng_state *rng = global_test_rng;

    int rv = cccurve25519_make_key_pair(rng, pk1, sk1);
    is(rv, CCERR_OK, "cccurve25519_make_key_pair() failed");

    rv = cccurve25519_make_key_pair(rng, pk2, sk2);
    is(rv, CCERR_OK, "cccurve25519_make_key_pair() failed");

    rv = cccurve25519_with_rng(global_test_rng, sess1, sk1, pk2);
    is(rv, CCERR_OK, "cccurve25519_with_rng() failed");

    rv = cccurve25519_with_rng(global_test_rng, sess2, sk2, pk1);
    is(rv, CCERR_OK, "cccurve25519_with_rng() failed");

    ok_memcmp(sess1, sess2, 32, "Computed Session Keys are equal");
}

static void test_ed25519_rng(void)
{
    const struct ccdigest_info *di = ccsha512_di();

    const uint8_t zeros = 0x00;
    const uint8_t ones = 0xff;

    const uint8_t msg[] = {
        0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
        0x10, 0x10, 0x10, 0x10, 0x10, 0x10
    };

    uint8_t prime[32] = {
        0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f
    };

    struct ccrng_sequence_state seq_rng;
    struct ccrng_state *rng = (struct ccrng_state *)&seq_rng;

    int rv;
    ccec25519signature sig;
    ccec25519pubkey pk;
    ccec25519secretkey sk;
    rv = cced25519_make_key_pair(di, global_test_rng, pk, sk);
    is(rv, CCERR_OK, "cced25519_make_key_pair() failed");

    ccrng_sequence_init(&seq_rng, 1, &zeros);
    rv = cced25519_sign_deterministic(di, rng, sig, sizeof(msg), msg, pk, sk);
    isnt(rv, CCERR_OK, "RNG returning only zeros should fail");

    ccrng_sequence_init(&seq_rng, 1, &ones);
    rv = cced25519_sign_deterministic(di, rng, sig, sizeof(msg), msg, pk, sk);
    isnt(rv, CCERR_OK, "RNG returning only ones should fail");

    ccrng_sequence_init(&seq_rng, sizeof(prime), prime);
    rv = cced25519_sign_deterministic(di, rng, sig, sizeof(msg), msg, pk, sk);
    isnt(rv, CCERR_OK, "RNG returning only p should fail");

    prime[0] -= 1;
    ccrng_sequence_init(&seq_rng, sizeof(prime), prime);
    rv = cced25519_sign_deterministic(di, rng, sig, sizeof(msg), msg, pk, sk);
    is(rv, CCERR_OK, "RNG returning p-1 should work");
}

static void test_ed25519_roundtrip(void)
{
    struct ccrng_state *rng = global_test_rng;
    const struct ccdigest_info *di = ccsha512_di();
    char label[64];
    int err;

    const uint8_t msg[] = {
        0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
        0x10, 0x10, 0x10, 0x10, 0x10, 0x10
    };

    for (size_t i = 0; i < 10; ++i) {
        ccec25519secretkey sk;
        ccec25519pubkey pk;
        int rv = cced25519_make_key_pair(di, rng, pk, sk);
        is(rv, CCERR_OK, "cced25519_make_key_pair() failed");
        snprintf(label, sizeof(label), "Generated Pair Test %zu", i + 1);

        ccec25519signature sig;
        err = cced25519_sign_with_rng(di, rng, sig, sizeof(msg), msg, pk, sk);
        is(err, CCERR_OK, "pk != sk * G");
        err = cced25519_verify(di, sizeof(msg), msg, sig, pk);
        is(err, CCERR_OK, "Verify %s", label);
    }
}

static void test_ed25519_kat(ccec_const_cp_t cp)
{
    struct ccrng_state *rng = global_test_rng;
    const struct ccdigest_info *di = ccsha512_di();
    char label[64];
    int err;

    for (size_t i = 0; i < CC_ARRAY_LEN(ed25519_test_vectors); ++i) {
        const ed25519_test_vector *const tv = &ed25519_test_vectors[i];
        snprintf(label, sizeof(label), "test vector %zu", i + 1);

        ccec25519signature sig;
        err = cced25519_sign_deterministic(di, rng, sig, tv->len, tv->msg, tv->pk, tv->sk);
        is(err, CCERR_OK, "Sign %s", label);
        ok_memcmp(sig, tv->sig, sizeof(sig), "Signature %s", label);

        err = cced25519_verify_internal(cp, di, tv->len, tv->msg, sig, tv->pk);
        is(err, CCERR_OK, "Verify %s", label);
    }
}

static void test_ed25519_mismatched_pk(void)
{
    struct ccrng_state *rng = global_test_rng;
    const struct ccdigest_info *di = ccsha512_di();

    const uint8_t msg[4] = { 0 };
    ccec25519signature sig;

    ccec25519secretkey sk;
    ccec25519pubkey pk;
    int rv = cced25519_make_key_pair(di, rng, pk, sk);
    is(rv, CCERR_OK, "cced25519_make_key_pair() failed");

    // Make sure it works
    rv = cced25519_sign_with_rng(di, rng, sig, sizeof(msg), msg, pk, sk);
    is(rv, CCERR_OK, "Signing should work");

    // Flip a bit in the pubkey
    pk[0] ^= 1;
    rv = cced25519_sign_with_rng(di, rng, sig, sizeof(msg), msg, pk, sk);
    is(rv, CCERR_PARAMETER, "Signing should fail when the pk is not correct");
}

static void test_ed25519_bogus_pk(void)
{
    struct ccrng_state *rng = global_test_rng;
    const struct ccdigest_info *di = ccsha512_di();
    const uint8_t msg[4] = { 0 };

    // Public key (y) must be a quadratic residue. This one (p-2) is not.
    const uint8_t bogus_pub[32] = {
          0xeb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
          0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
          0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f
    };

    ccec25519signature sig;
    ccec25519secretkey sk;
    ccec25519pubkey pk, pk2;

    cced25519_make_key_pair(di, rng, pk, sk);
    cced25519_make_pub(di, pk2, sk);
    ok_memcmp(pk, pk2, 32, "pk ≠ pk2");

    int rv = cced25519_sign(di, sig, sizeof(msg), msg, pk, sk);
    is(rv, CCERR_OK, "Signing should work");

    rv = cced25519_verify(di, sizeof(msg), msg, sig, bogus_pub);
    isnt(rv, CCERR_OK, "Verifying must fail with an invalid public key");
}

int ccec25519_tests(TM_UNUSED int argc, TM_UNUSED char *const *argv)
{
    plan_tests(12910);

    if (verbose) {
        diag("Starting Curve25519 tests");
    }

    test_x25519_roundtrip();

    for (unsigned i = 0; i < CC_ARRAY_LEN(ccec_cp_x25519_impls); i++) {
        ccec_const_cp_t cp = ccec_cp_x25519_impls[i]();

        test_x25519_kat(cp);
    }

    test_ed25519_rng();
    test_ed25519_roundtrip();
    test_ed25519_mismatched_pk();
    test_ed25519_bogus_pk();

    for (unsigned i = 0; i < CC_ARRAY_LEN(ccec_cp_ed25519_impls); i++) {
        ccec_const_cp_t cp = ccec_cp_ed25519_impls[i]();

        test_ed25519_kat(cp);
    }

    return 0;
}

#endif // CCEC25519

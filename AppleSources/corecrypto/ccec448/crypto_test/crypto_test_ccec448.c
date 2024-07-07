/* Copyright (c) (2022,2023) Apple Inc. All rights reserved.
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

#if (CCEC448 == 0)
entryPoint(ccec448_tests, "ccec448 test")
#else
#include <corecrypto/ccec448.h>
#include "ccec448_internal.h"

static int verbose = 0;

typedef struct {
    const char *d;
    const char *u;
    const char *x;
} x448_test_vector;

// https://www.rfc-editor.org/rfc/rfc7748#section-5.2
static const x448_test_vector x448_test_vectors[] = {
    {
        "3d262fddf9ec8e88495266fea19a34d28882acef045104d0d1aae121700a779c984c24f8cdd78fbff44943eba368f54b29259a4f1c600ad3",
        "06fce640fa3487bfda5f6cf2d5263f8aad88334cbd07437f020f08f9814dc031ddbdc38c19c6da2583fa5429db94ada18aa7a7fb4ef8a086",
        "ce3e4ff95a60dc6697da1db1d85e6afbdf79b50a2412d7546d5f239fe14fbaadeb445fc66a01b0779d98223961111e21766282f73dd96b6f"
    },
    {
        "203d494428b8399352665ddca42f9de8fef600908e0d461cb021f8c538345dd77c3e4806e25f46d3315c44e0a5b4371282dd2c8d5be3095f",
        "0fbcc2f993cd56d3305b0b7d9e55d4c1a8fb5dbb52f8e9a1e9b6201b165d015894e56c4d3570bee52fe205e28a78b91cdfbde71ce8d157db",
        "884a02576239ff7a2f2f63b2db6a9ff37047ac13568e1e30fe63c4a7ad1b3ee3a5700df34321d62077e63633c575c1c954514e99da7c179d"
    }
};

typedef struct {
    const char *sk;
    const char *pk;
    const char *msg;
    const char *sig;
} ed448_test_vector;

// https://www.rfc-editor.org/rfc/rfc8032#section-7.4
static const ed448_test_vector ed448_test_vectors[] = {
#include "crypto_test_ed448.inc"
};

static void test_x448_kat(ccec_const_cp_t cp)
{
    struct ccrng_state *rng = global_test_rng;
    size_t num_vectors = CC_ARRAY_LEN(x448_test_vectors);

    for (size_t i = 0; i < num_vectors; i++) {
        const x448_test_vector *tv = &x448_test_vectors[i];

        byteBuffer d = hexStringToBytes(tv->d);
        byteBuffer u = hexStringToBytes(tv->u);
        byteBuffer x = hexStringToBytes(tv->x);

        cc_assert(d->len == 56 && u->len == 56 && x->len == 56);

        ccec448key out;
        int rv = cccurve448_internal(cp, out, d->bytes, u->bytes, rng);
        is(rv, CCERR_OK, "cccurve448() failed");
        ok_memcmp(out, x->bytes, sizeof(out), "X448 test vector failed");

        free(d);
        free(u);
        free(x);
    }
}

static void test_x448_roundtrip(void)
{
    struct ccrng_state *rng = global_test_rng;

    ccec448pubkey pk1;
    ccec448secretkey sk1;

    ccec448pubkey pk2;
    ccec448secretkey sk2;

    ccec448key out1;
    ccec448key out2;

    int rv = cccurve448_make_priv(rng, sk1);
    is(rv, CCERR_OK, "cccurve448_make_priv() failed");

    rv = cccurve448_make_pub(rng, pk1, sk1);
    is(rv, CCERR_OK, "cccurve448_make_pub() failed");

    rv = cccurve448_make_key_pair(rng, pk2, sk2);
    is(rv, CCERR_OK, "cccurve448_make_key_pair() failed");

    rv = cccurve448(rng, out1, sk1, pk2);
    is(rv, CCERR_OK, "cccurve448() failed");

    rv = cccurve448(rng, out2, sk2, pk1);
    is(rv, CCERR_OK, "cccurve448() failed");

    ok_memcmp(out1, out2, sizeof(out1), "out1 ≠ out2");
}

static void test_ed448_kat(ccec_const_cp_t cp)
{
    struct ccrng_state *rng = global_test_rng;
    size_t num_vectors = CC_ARRAY_LEN(ed448_test_vectors);

    for (size_t i = 0; i < num_vectors; i++) {
        const ed448_test_vector *tv = &ed448_test_vectors[i];

        byteBuffer sk = hexStringToBytes(tv->sk);
        byteBuffer pk = hexStringToBytes(tv->pk);
        byteBuffer msg = hexStringToBytes(tv->msg);
        byteBuffer sig = hexStringToBytes(tv->sig);

        cc_assert(sk->len == 57 && pk->len == 57 && sig->len == 114);

        // Generate a non-deterministic signature.
        cced448signature signature;
        int rv = cced448_sign_internal(cp, signature, msg->len, msg->bytes, pk->bytes, sk->bytes, rng);
        is(rv, CCERR_OK, "cced448_sign() failed");

        isnt(0, memcmp(signature, sig->bytes, sizeof(signature)), "signature must be ≠ sig");

        // And verify it.
        rv = cced448_verify_internal(cp, msg->len, msg->bytes, signature, pk->bytes);
        is(rv, CCERR_OK, "cced448_verify(signature) failed");

        // Verify the test vector's signature.
        rv = cced448_verify_internal(cp, msg->len, msg->bytes, sig->bytes, pk->bytes);
        is(rv, CCERR_OK, "cced448_verify(sig) failed");

        // Re-create the deterministic signature.
        rv = cced448_sign_deterministic(cp, signature, msg->len, msg->bytes, pk->bytes, sk->bytes, rng);
        is(rv, CCERR_OK, "cced448_sign_deterministic() failed");

        ok_memcmp(signature, sig->bytes, sizeof(signature), "Ed448 test vector failed");

        // Verification must fail if signature is corrupted.
        signature[0] ^= 0x5a;
        rv = cced448_verify_internal(cp, msg->len, msg->bytes, signature, pk->bytes);
        isnt(rv, CCERR_OK, "cced448_verify() should fail");

        free(sk);
        free(pk);
        free(msg);
        free(sig);
    }
}

static void test_ed448_errors(void)
{
    struct ccrng_state *rng = global_test_rng;

    cced448pubkey pk;
    cced448secretkey sk;

    const uint8_t msg[32] = { 0 };

    int rv = cced448_make_key_pair(rng, pk, sk);
    is(rv, CCERR_OK, "cced448_make_key_pair() failed");

    cced448signature sig;
    rv = cced448_sign(rng, sig, sizeof(msg), msg, pk, sk);
    is(rv, CCERR_OK, "cced448_sign() failed");

    rv = cced448_verify(sizeof(msg), msg, sig, pk);
    is(rv, CCERR_OK, "cced448_verify() failed");

    // Signing must fail if sk * B ≠ pk.
    cced448pubkey pub1;
    cc_memcpy(pub1, pk, sizeof(pk));
    pub1[0] ^= 0x5a;

    rv = cced448_sign(rng, sig, sizeof(msg), msg, pub1, sk);
    isnt(rv, CCERR_OK, "cced448_sign() should fail");

    // Last bit of the public key signals the sign of x.
    cced448pubkey pub2;
    cc_memcpy(pub2, pk, sizeof(pk));
    pub2[56] = 0x01;

    rv = cced448_verify(sizeof(msg), msg, sig, pub2);
    isnt(rv, CCERR_OK, "cced448_verify() should fail");

    // Last byte of the signature must be zero.
    cced448signature sig1;
    cc_memcpy(sig1, sig, sizeof(sig));
    sig1[113] = 0x01;

    rv = cced448_verify(sizeof(msg), msg, sig1, pk);
    isnt(rv, CCERR_OK, "cced448_verify() should fail");

    // Public key (y) must be smaller than p. This one is equal to p.
    const uint8_t pub3[57] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00
    };

    rv = cced448_verify(sizeof(msg), msg, sig, pub3);
    isnt(rv, CCERR_OK, "cced448_verify() should fail");

    // Public key (y) must be a quadratic residue. This one (p-2) is not.
    const uint8_t pub4[57] = {
        0xfd, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00
    };

    rv = cced448_verify(sizeof(msg), msg, sig, pub4);
    isnt(rv, CCERR_OK, "cced448_verify() should fail");

    // If the recovered x is zero, the sign bit can't be '1'.
    const uint8_t pub5[57] = {
        0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x80
    };

    rv = cced448_verify(sizeof(msg), msg, sig, pub5);
    isnt(rv, CCERR_OK, "cced448_verify() should fail");

    // The S part of the signature is a scalar and must be < q.
    const uint8_t q[56] = {
        0xf3, 0x44, 0x58, 0xab, 0x92, 0xc2, 0x78, 0x23, 0x55, 0x8f, 0xc5, 0x8d, 0x72, 0xc2, 0x6c, 0x21,
        0x90, 0x36, 0xd6, 0xae, 0x49, 0xdb, 0x4e, 0xc4, 0xe9, 0x23, 0xca, 0x7c, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3f
    };

    cc_memcpy(&sig[57], q, sizeof(q));

    rv = cced448_verify(sizeof(msg), msg, sig, pk);
    isnt(rv, CCERR_OK, "cced448_verify() should fail");
}

int ccec448_tests(TM_UNUSED int argc, TM_UNUSED char *const *argv)
{
    plan_tests(256);

    if (verbose) {
        diag("Starting Curve448 tests");
    }

    test_x448_roundtrip();

    for (unsigned i = 0; i < CC_ARRAY_LEN(ccec_cp_x448_impls); i++) {
        ccec_const_cp_t cp = ccec_cp_x448_impls[i]();

        test_x448_kat(cp);
    }

    test_ed448_errors();

    for (unsigned i = 0; i < CC_ARRAY_LEN(ccec_cp_ed448_impls); i++) {
        ccec_const_cp_t cp = ccec_cp_ed448_impls[i]();

        test_ed448_kat(cp);
    }

    return 0;
}

#endif // CCEC448

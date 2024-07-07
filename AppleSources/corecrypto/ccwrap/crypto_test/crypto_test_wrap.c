/* Copyright (c) (2012,2015-2019,2021) Apple Inc. All rights reserved.
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
#include "cc_priv.h"

static int verbose = 0;

#if (CCWRAP == 0)
entryPoint(ccwrap_tests, "ccwrap test")
#else
#include <corecrypto/ccmode.h>
#include <corecrypto/ccaes.h>
#include <corecrypto/ccwrap_priv.h>

#define KEY128 "000102030405060708090a0b0c0d0e0f"
#define KEY192 "000102030405060708090a0b0c0d0e0f0001020304050607"
#define KEY256 "000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f"
#define KEY512                                                                                     \
    "000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d" \
    "0e0f000102030405060708090a0b0c0d0e0f"

struct ccwrap_vector {
    size_t count;
    const char *kek;  // Key to encrypt the input
    const char *key;  // Input
    const char *wrap; // Wrapped input
    int error;
};

const struct ccwrap_vector ccwrap_aes_vectors[] = {
    // Toy sample
    {
        .count = 0,
        .kek = "f59782f1dceb0544a8da06b34969b9212b55ce6dcbdd0975a33f4b3f88b538da",
        .key = "73d33060b5f9f2eb5785c0703ddfa704",
        .wrap = "2e63946ea3c090902fa1558375fdb2907742ac74e39403fc",
        .error = CCERR_OK,
    },
// Test vectors
#include "../test_vectors/KW_AD_128.inc"
#include "../test_vectors/KW_AD_192.inc"
#include "../test_vectors/KW_AD_256.inc"
#include "../test_vectors/KW_AE_128.inc"
#include "../test_vectors/KW_AE_192.inc"
#include "../test_vectors/KW_AE_256.inc"
};

static int test_wrap(const struct ccmode_ecb *enc_ecb,
                     const struct ccmode_ecb *dec_ecb,
                     const char *keydata,
                     const char *kekdata)
{
    ccecb_ctx_decl(enc_ecb->size, enc_ctx);
    ccecb_ctx_decl(dec_ecb->size, dec_ctx);
    byteBuffer kek = hexStringToBytes(kekdata);

    ccecb_init(enc_ecb, enc_ctx, kek->len, kek->bytes);
    ccecb_init(dec_ecb, dec_ctx, kek->len, kek->bytes);

    byteBuffer key = hexStringToBytes(keydata);
    size_t wrapped_size = ccwrap_wrapped_size(key->len);
    byteBuffer wrapped_key = mallocByteBuffer(wrapped_size);

    uint8_t iv[CCWRAP_SEMIBLOCK] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };

    is(ccwrap_auth_encrypt(
           enc_ecb, enc_ctx, key->len, key->bytes, &wrapped_size, wrapped_key->bytes),
       CCERR_OK,
       "Wrapped Key");

    size_t unwrapped_size = ccwrap_unwrapped_size(wrapped_size);
    byteBuffer unwrapped_key = mallocByteBuffer(unwrapped_size);

    is(ccwrap_auth_decrypt(dec_ecb,
                           dec_ctx,
                           wrapped_key->len,
                           wrapped_key->bytes,
                           &unwrapped_size,
                           unwrapped_key->bytes),
       CCERR_OK,
       "Unwrapped Key");
    ok(bytesAreEqual(key, unwrapped_key), "Round Trip Success");

    wrapped_key->bytes[0] ^= 1;
    is(ccwrap_auth_decrypt(dec_ecb,
                           dec_ctx,
                           wrapped_key->len,
                           wrapped_key->bytes,
                           &unwrapped_size,
                           unwrapped_key->bytes),
       CCERR_INTEGRITY,
       "Integrity Check");

    free(unwrapped_key);

    is(ccwrap_auth_encrypt_withiv(enc_ecb,
                                  enc_ctx,
                                  key->len,
                                  key->bytes,
                                  &wrapped_size,
                                  wrapped_key->bytes,
                                  &iv),
       CCERR_OK,
       "Wrapped Key (with iv)");

    unwrapped_size = ccwrap_unwrapped_size(wrapped_size);
    unwrapped_key = mallocByteBuffer(unwrapped_size);

    is(ccwrap_auth_decrypt_withiv(dec_ecb,
                                  dec_ctx,
                                  wrapped_key->len,
                                  wrapped_key->bytes,
                                  &unwrapped_size,
                                  unwrapped_key->bytes,
                                  &iv),
       CCERR_OK,
       "Unwrapped Key (with iv)");
    ok(bytesAreEqual(key, unwrapped_key), "Round Trip Success (with iv)");

    wrapped_key->bytes[0] ^= 1;
    is(ccwrap_auth_decrypt_withiv(dec_ecb,
                                  dec_ctx,
                                  wrapped_key->len,
                                  wrapped_key->bytes,
                                  &unwrapped_size,
                                  unwrapped_key->bytes,
                                  &iv),
       CCERR_INTEGRITY,
       "Integrity Check (with iv)");

    free(kek);
    free(key);
    free(wrapped_key);
    free(unwrapped_key);
    return 1;
}

static int test_kat_wrap(const struct ccmode_ecb *enc_ecb,
                         const struct ccmode_ecb *dec_ecb,
                         const struct ccwrap_vector *tv)
{
    ccecb_ctx_decl(enc_ecb->size, enc_ctx);
    ccecb_ctx_decl(dec_ecb->size, dec_ctx);
    byteBuffer kek = hexStringToBytes(tv->kek);
    byteBuffer key = hexStringToBytes(tv->key);
    int rc = 1;

    rc &= is(ccecb_init(enc_ecb, enc_ctx, kek->len, kek->bytes), CCERR_OK, "Enc init");
    rc &= is(ccecb_init(dec_ecb, dec_ctx, kek->len, kek->bytes), CCERR_OK, "Dec init");

    if (tv->error == CCERR_OK) {
        size_t wrapped_size = ccwrap_wrapped_size(key->len);
        size_t unwrapped_size = ccwrap_unwrapped_size(wrapped_size);
        byteBuffer computed_wrapped_key = mallocByteBuffer(wrapped_size);
        byteBuffer expected_wrapped_key = hexStringToBytes(tv->wrap);
        byteBuffer unwrapped_key = mallocByteBuffer(unwrapped_size);

        rc &= is(
            ccwrap_auth_encrypt(
                enc_ecb, enc_ctx, key->len, key->bytes, &wrapped_size, computed_wrapped_key->bytes),
            CCERR_OK,
            "Wrapped Key");
        rc &= ok(bytesAreEqual(computed_wrapped_key, expected_wrapped_key), "Wrap Success");

        rc &= is(ccwrap_auth_decrypt(dec_ecb,
                                     dec_ctx,
                                     wrapped_size,
                                     computed_wrapped_key->bytes,
                                     &unwrapped_size,
                                     unwrapped_key->bytes),
                 CCERR_OK,
                 "Unwrapping");
        rc &= ok(bytesAreEqual(key, unwrapped_key), "Round Trip Success");

        free(computed_wrapped_key);
        free(expected_wrapped_key);
        free(unwrapped_key);
    } else if (tv->error == CCERR_INTEGRITY) {
        byteBuffer wrapped_key = hexStringToBytes(tv->wrap);
        size_t unwrapped_size = ccwrap_unwrapped_size(wrapped_key->len);
        byteBuffer unwrapped_key = mallocByteBuffer(unwrapped_size);

        rc &= is(ccwrap_auth_decrypt(dec_ecb,
                                     dec_ctx,
                                     wrapped_key->len,
                                     wrapped_key->bytes,
                                     &unwrapped_size,
                                     unwrapped_key->bytes),
                 CCERR_INTEGRITY,
                 "Integrity");

        free(wrapped_key);
        free(unwrapped_key);
    } else {
        fail("test_kat_wrap unknown error");
    }

    free(kek);
    free(key);
    return rc;
}

static int test_ccwrap_wrapped_size(void)
{
    size_t i;
    size_t vectors[][2] = {
        { CCWRAP_SEMIBLOCK * 2, CCWRAP_SEMIBLOCK * 3 },
        { 0, CCWRAP_SEMIBLOCK },
    };
    size_t nvectors = CC_ARRAY_LEN(vectors);
    int rc = 0;

    for (i = 0; i < nvectors; i += 1) {
        rc |= is(ccwrap_wrapped_size(vectors[i][0]), vectors[i][1], "Unwrapped size");
    }

    return rc;
}

static int test_ccwrap_unwrapped_size(void)
{
    size_t i;
    size_t vectors[][2] = {
        { CCWRAP_SEMIBLOCK * 3, CCWRAP_SEMIBLOCK * 2 },
        { CCWRAP_SEMIBLOCK, 0 },
        { CCWRAP_SEMIBLOCK - 1, 0 },
        { 0, 0 },
    };
    size_t nvectors = CC_ARRAY_LEN(vectors);
    int rc = 0;

    for (i = 0; i < nvectors; i += 1) {
        rc |= is(ccwrap_unwrapped_size(vectors[i][0]), vectors[i][1], "Unwrapped size");
    }

    return rc;
}

static int test_ccwrap_auth_encrypt_bad_nbytes(void)
{
    int rc = 0;
    const struct ccmode_ecb *enc_ecb = ccaes_ecb_encrypt_mode();
    ccecb_ctx_decl(enc_ecb->size, enc_ctx);
    byteBuffer kek = hexStringToBytes(KEY128);

    ccecb_init(enc_ecb, enc_ctx, kek->len, kek->bytes);

    size_t i;
    size_t vectors[] = {
        CCWRAP_SEMIBLOCK,
        CCWRAP_SEMIBLOCK * 2 + 1,

        // this amount is only valid in the unwrap direction
        CCWRAP_SEMIBLOCK * CCWRAP_MAXSEMIBLOCKS,
    };
    size_t nvectors = CC_ARRAY_LEN(vectors);

    for (i = 0; i < nvectors; i += 1) {
        size_t nbytes = vectors[i];
        size_t obytes = ccwrap_wrapped_size(nbytes);
        uint8_t key[nbytes];
        uint8_t wrapped[obytes];

        rc |= is(ccwrap_auth_encrypt(enc_ecb, enc_ctx, nbytes, key, &obytes, wrapped),
                 CCERR_PARAMETER,
                 "encrypt bad nbytes");
    }

    free(kek);
    return rc;
}

static int test_ccwrap_auth_decrypt_bad_nbytes(void)
{
    int rc = 0;
    const struct ccmode_ecb *dec_ecb = ccaes_ecb_decrypt_mode();
    ccecb_ctx_decl(dec_ecb->size, dec_ctx);
    byteBuffer kek = hexStringToBytes(KEY128);

    ccecb_init(dec_ecb, dec_ctx, kek->len, kek->bytes);

    size_t i;
    size_t vectors[] = {
        CCWRAP_SEMIBLOCK * 2,
        CCWRAP_SEMIBLOCK * 3 + 1,
        CCWRAP_SEMIBLOCK * (CCWRAP_MAXSEMIBLOCKS + 1),
    };
    size_t nvectors = CC_ARRAY_LEN(vectors);

    for (i = 0; i < nvectors; i += 1) {
        size_t nbytes = vectors[i];
        size_t obytes = ccwrap_unwrapped_size(nbytes);
        uint8_t wrapped[nbytes];
        uint8_t key[obytes];

        rc |= is(ccwrap_auth_decrypt(dec_ecb, dec_ctx, nbytes, wrapped, &obytes, key),
                 CCERR_PARAMETER,
                 "decrypt bad nbytes");
    }

    free(kek);
    return rc;
}

int ccwrap_tests(TM_UNUSED int argc, TM_UNUSED char *const *argv)
{
    plan_tests(20204);
    if (verbose)
        diag("Starting ccwrap tests\n");
    const struct ccmode_ecb *enc_ecb = ccaes_ecb_encrypt_mode();
    const struct ccmode_ecb *dec_ecb = ccaes_ecb_decrypt_mode();

    for (size_t i = 0; i < CC_ARRAY_LEN(ccwrap_aes_vectors); i++) {
        ok(test_kat_wrap(enc_ecb, dec_ecb, &ccwrap_aes_vectors[i]),
           "AES key size %u, plaintext size %u, count %d",
           ccwrap_aes_vectors[i].kek == NULL ? 0 : strlen(ccwrap_aes_vectors[i].kek) / 2,
           ccwrap_aes_vectors[i].key == NULL ? 0 : strlen(ccwrap_aes_vectors[i].key) / 2,
           ccwrap_aes_vectors[i].count);
    }

    ok(test_wrap(enc_ecb, dec_ecb, KEY128, KEY128), "ccwrap of 128 bit key with 128 bit kek");
    ok(test_wrap(enc_ecb, dec_ecb, KEY256, KEY128), "ccwrap of 256 bit key with 128 bit kek");
    ok(test_wrap(enc_ecb, dec_ecb, KEY512, KEY128), "ccwrap of 512 bit key with 128 bit kek");
    ok(test_wrap(enc_ecb, dec_ecb, KEY128, KEY192), "ccwrap of 128 bit key with 192 bit kek");
    ok(test_wrap(enc_ecb, dec_ecb, KEY256, KEY192), "ccwrap of 256 bit key with 192 bit kek");
    ok(test_wrap(enc_ecb, dec_ecb, KEY512, KEY192), "ccwrap of 512 bit key with 192 bit kek");
    ok(test_wrap(enc_ecb, dec_ecb, KEY128, KEY256), "ccwrap of 128 bit key with 256 bit kek");
    ok(test_wrap(enc_ecb, dec_ecb, KEY256, KEY256), "ccwrap of 256 bit key with 256 bit kek");
    ok(test_wrap(enc_ecb, dec_ecb, KEY512, KEY256), "ccwrap of 512 bit key with 256 bit kek");

    ok(test_ccwrap_wrapped_size(), "wrapped size");
    ok(test_ccwrap_unwrapped_size(), "unwrapped size");
    ok(test_ccwrap_auth_encrypt_bad_nbytes(), "encrypt bad nbytes");
    ok(test_ccwrap_auth_decrypt_bad_nbytes(), "decrypt bad nbytes");

    return 0;
}
#endif

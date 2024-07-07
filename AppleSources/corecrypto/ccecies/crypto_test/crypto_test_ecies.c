/* Copyright (c) (2014-2022) Apple Inc. All rights reserved.
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
#include "cc_macros.h"

#if (CCECIES == 0)
entryPoint(ccies, "ccies")
#else

#include "crypto_test_ecies.h"
#include "crypto_test_ec.h"
#include <corecrypto/ccec.h>
#include <corecrypto/ccec_priv.h>
#include "ccec_internal.h"
#include <corecrypto/ccecies.h>
#include <corecrypto/ccecies_priv.h>
#include "ccecies_internal.h"
#include <corecrypto/ccaes.h>
#include <corecrypto/ccrng_test.h>
#include <corecrypto/ccrng_ecfips_test.h>
#include <corecrypto/ccsha1.h>
#include <corecrypto/ccsha2.h>

static const int verbose = 1;

static const uint8_t shared_info1[] = "test1";
static const uint8_t shared_info2[] = "test2";
static const uint8_t shared_info3[] = "test3";

#define di_SHA1 &ccsha1_eay_di
#define di_SHA224 &ccsha224_ltc_di
#define di_SHA256 &ccsha256_ltc_di
#define di_SHA384 &ccsha384_ltc_di
#define di_SHA512 &ccsha512_ltc_di

const struct ccecies_vector ccecies_aes_gcm_vectors[] = {
#include "../test_vectors/ecies_aes_gcm.inc"
#include "../test_vectors/ecies_aes_gcm_legacy.inc"
    // End
    {
        .di = NULL,
    }
};

static int is_zero(size_t nbytes, uint8_t *p)
{
    int rc = 0;
    for (size_t i = 0; i < nbytes; i++) {
        rc |= p[i];
    }
    return (rc == 0);
}

// Superset of the inputs necessary for ccecies_encrypt_gcm and ccecies_encrypt_gcm_from_shared_secret
// Execute both and verify they behave the same (error or valid cases)
static int test_ccecies_encrypt_gcm(ccec_pub_ctx_t public_key,
                                    const ccecies_gcm_t ecies,
                                    ccec_pub_ctx_t ephemeral_public_key,
                                    size_t shared_secret_nbytes,
                                    const uint8_t *shared_secret,
                                    size_t plaintext_nbytes,
                                    const uint8_t *plaintext,
                                    size_t sharedinfo1_nbytes,
                                    const void *sharedinfo1,
                                    size_t sharedinfo2_nbytes,
                                    const void *sharedinfo2,
                                    size_t *encrypted_blob_nbytes,
                                    uint8_t *encrypted_blob)
{
    int status1;
    int status2;
    // shadow output parameter
    byteBuffer encrypted_blob1 = mallocByteBuffer(*encrypted_blob_nbytes);
    byteBuffer encrypted_blob2 = mallocByteBuffer(*encrypted_blob_nbytes);
    size_t encrypted_blob_nbytes1 = *encrypted_blob_nbytes;
    size_t encrypted_blob_nbytes2 = *encrypted_blob_nbytes;

    status1 = ccecies_encrypt_gcm(public_key,
                                  ecies,
                                  plaintext_nbytes,
                                  plaintext,
                                  sharedinfo1_nbytes,
                                  sharedinfo1,
                                  sharedinfo2_nbytes,
                                  sharedinfo2,
                                  &encrypted_blob_nbytes1,
                                  encrypted_blob1->bytes);

    status2 = ccecies_encrypt_gcm_from_shared_secret(public_key,
                                                     ecies,
                                                     ephemeral_public_key,
                                                     shared_secret_nbytes,
                                                     shared_secret,
                                                     plaintext_nbytes,
                                                     plaintext,
                                                     sharedinfo1_nbytes,
                                                     sharedinfo1,
                                                     sharedinfo2_nbytes,
                                                     sharedinfo2,
                                                     &encrypted_blob_nbytes2,
                                                     encrypted_blob2->bytes);

    if (ecies->options & (ECIES_EPH_PUBKEY_IN_SHAREDINFO1 | ECIES_EPH_PUBKEY_AND_SHAREDINFO1)) {
        is(status1, status2, "Encrypt same error code");
        is(encrypted_blob_nbytes1, encrypted_blob_nbytes2, "Encrypt same output size");
        ok_memcmp(encrypted_blob1->bytes, encrypted_blob2->bytes, encrypted_blob2->len, "Encrypt same output value");
    }
    memcpy(encrypted_blob, encrypted_blob1->bytes, encrypted_blob1->len);
    *encrypted_blob_nbytes = encrypted_blob_nbytes1;

    free(encrypted_blob1);
    free(encrypted_blob2);

    return status1;
}

// Superset of the inputs necessary for ccecies_decrypt_gcm and ccecies_decrypt_gcm_from_shared_secret
// Execute both and verify they behave the same (error or valid cases)
static int test_ccecies_decrypt_gcm(ccec_full_ctx_t full_key,
                                    const ccecies_gcm_t ecies,
                                    size_t shared_secret_nbytes,
                                    const uint8_t *shared_secret,
                                    size_t encrypted_blob_nbytes,
                                    const uint8_t *encrypted_blob,
                                    size_t sharedinfo1_nbytes,
                                    const void *sharedinfo1,
                                    size_t sharedinfo2_nbytes,
                                    const void *sharedinfo2,
                                    size_t *plaintext_nbytes,
                                    uint8_t *plaintext)
{
    int status1;
    int status2;
    // shadow output parameter
    byteBuffer plaintext1 = mallocByteBuffer(*plaintext_nbytes);
    byteBuffer plaintext2 = mallocByteBuffer(*plaintext_nbytes);
    size_t plaintext_nbytes1 = *plaintext_nbytes;
    size_t plaintext_nbytes2 = *plaintext_nbytes;

    status1 = ccecies_decrypt_gcm(full_key,
                                  ecies,
                                  encrypted_blob_nbytes,
                                  encrypted_blob,
                                  sharedinfo1_nbytes,
                                  sharedinfo1,
                                  sharedinfo2_nbytes,
                                  sharedinfo2,
                                  &plaintext_nbytes1,
                                  plaintext1->bytes);

    status2 = ccecies_decrypt_gcm_from_shared_secret(ccec_ctx_cp(full_key),
                                                     ecies,
                                                     shared_secret_nbytes,
                                                     shared_secret,
                                                     encrypted_blob_nbytes,
                                                     encrypted_blob,
                                                     sharedinfo1_nbytes,
                                                     sharedinfo1,
                                                     sharedinfo2_nbytes,
                                                     sharedinfo2,
                                                     &plaintext_nbytes2,
                                                     plaintext2->bytes);

    if (ecies->options & (ECIES_EPH_PUBKEY_IN_SHAREDINFO1 | ECIES_EPH_PUBKEY_AND_SHAREDINFO1)) {
        is(!!status1, !!status2, "Same error code"); // slight variation of error code since elliptic curve operations are not
                                                     // performed in the case of ccecies_decrypt_gcm_from_shared_secret
        is(plaintext_nbytes1, plaintext_nbytes2, "Decrypt Same output size");
        ok_memcmp(plaintext1->bytes, plaintext2->bytes, plaintext2->len, "Decrypt Same output value");
    }
    memcpy(plaintext, plaintext1->bytes, plaintext1->len);
    *plaintext_nbytes = plaintext_nbytes1;

    free(plaintext1);
    free(plaintext2);

    return status1;
}

// Negative testing based on KATs
static int ccecies_gcm_kat_negative_test(const struct ccecies_vector *test, int test_counter)
{
    int status = 0; // fail
    int status_decrypt_gcm;
    byteBuffer plaintext = hexStringToBytes(test->message);
    byteBuffer expectedCiphertext = hexStringToBytes(
        ((test->options & ECIES_EXPORT_PUB_STANDARD) == ECIES_EXPORT_PUB_STANDARD) ? test->cipher : test->compact_cipher);
    size_t sharedInfo1_size = strlen(test->sharedInfo1);
    size_t sharedInfo2_size = strlen(test->sharedInfo2);
    byteBuffer eph_priv_key = hexStringToBytes(test->eph_priv_key);
    byteBuffer dec_priv_key = hexStringToBytes(test->dec_priv_key);
    byteBuffer shared_secret = hexStringToBytes(test->Z);
    struct ccrng_ecfips_test_state rng;
    struct ccecies_gcm ecies_enc;
    struct ccecies_gcm ecies_dec;
    ccec_const_cp_t cp = test->curve();
    size_t fake_size;
    size_t output_size;
    ccec_full_ctx_decl_cp(cp, remote_key);
    ccec_full_ctx_decl_cp(cp, ephemeral_key);
    // Buffer for outputs
    byteBuffer ciphertext = NULL;
    byteBuffer plaintext_bis = NULL;

    // Generate "remote" public key from private key
    is_or_goto(
        ccec_recover_full_key(cp, dec_priv_key->len, dec_priv_key->bytes, remote_key), CCERR_OK, "Generated private Key", errout);
    is_or_goto(ccec_recover_full_key(cp, eph_priv_key->len, eph_priv_key->bytes, ephemeral_key),
               CCERR_OK,
               "Generated ephemeral Key",
               errout);

    // Set RNG to control ephemeral key
    ccrng_ecfips_test_init(&rng, eph_priv_key->len, eph_priv_key->bytes);

    // Invalid setup
    is(ccecies_encrypt_gcm_setup(
           &ecies_enc, test->di, (struct ccrng_state *)&rng, ccaes_gcm_encrypt_mode(), 12, test->mac_nbytes, test->options),
       CCERR_CRYPTO_CONFIG,
       "Negative test encrypt setup");
    is(ccecies_decrypt_gcm_setup(&ecies_dec, test->di, ccaes_gcm_decrypt_mode(), 13, test->mac_nbytes, test->options),
       CCERR_CRYPTO_CONFIG,
       "Negative test decrypt setup");
    is(ccecies_encrypt_gcm_setup(
           &ecies_enc, test->di, (struct ccrng_state *)&rng, ccaes_gcm_encrypt_mode(), test->key_nbytes, 3, test->options),
       CCERR_CRYPTO_CONFIG,
       "Negative test encrypt setup");
    is(ccecies_decrypt_gcm_setup(&ecies_dec, test->di, ccaes_gcm_decrypt_mode(), test->key_nbytes, 7, test->options),
       CCERR_CRYPTO_CONFIG,
       "Negative test decrypt setup");

    // Actual setup
    is_or_goto(ccecies_encrypt_gcm_setup(&ecies_enc,
                                         test->di,
                                         (struct ccrng_state *)&rng,
                                         ccaes_gcm_encrypt_mode(),
                                         test->key_nbytes,
                                         test->mac_nbytes,
                                         test->options),
               CCERR_OK,
               "Negative test encrypt setup",
               errout);
    is_or_goto(ccecies_decrypt_gcm_setup(
                   &ecies_dec, test->di, ccaes_gcm_decrypt_mode(), test->key_nbytes, test->mac_nbytes, test->options),
               CCERR_OK,
               "Negative test decrypt setup",
               errout);

    ccec_pub_ctx_t pub_remote_key = ccec_ctx_pub(remote_key);
    ciphertext = mallocByteBuffer(ccecies_encrypt_gcm_ciphertext_size(pub_remote_key, &ecies_enc, plaintext->len));
    plaintext_bis = mallocByteBuffer(ccecies_decrypt_gcm_plaintext_size_cp(cp, &ecies_dec, ciphertext->len));

    // Valid encrypted value
    is_or_goto(test_ccecies_encrypt_gcm(pub_remote_key,
                                        &ecies_enc,
                                        ccec_ctx_pub(ephemeral_key),
                                        shared_secret->len,
                                        shared_secret->bytes,
                                        plaintext->len,
                                        plaintext->bytes,
                                        sharedInfo1_size,
                                        test->sharedInfo1,
                                        sharedInfo2_size,
                                        test->sharedInfo2,
                                        &ciphertext->len,
                                        ciphertext->bytes),
               CCERR_OK,
               "Encrypt",
               errout);

    // ------------------------------
    // Negative testing of decrypt
    // ------------------------------

    // Wrong size
    is(ccecies_decrypt_gcm_plaintext_size(remote_key, &ecies_dec, 0), (size_t)0, "Error case");

    // Corrupted public key
    ciphertext->bytes[2] ^= 1;
    memset(plaintext_bis->bytes, 0xAA, plaintext_bis->len);
    output_size = plaintext_bis->len;
    status_decrypt_gcm = test_ccecies_decrypt_gcm(remote_key,
                                                  &ecies_dec,
                                                  shared_secret->len,
                                                  shared_secret->bytes,
                                                  ciphertext->len,
                                                  ciphertext->bytes,
                                                  sharedInfo1_size,
                                                  test->sharedInfo1,
                                                  sharedInfo2_size,
                                                  test->sharedInfo2,
                                                  &output_size,
                                                  plaintext_bis->bytes);
    // Corrupted public key may become invalid (not on curve, incorrect encoding)
    // or remains valid and should make decrypt function return CCMODE_INTEGRITY_FAILURE.
    isnt(status_decrypt_gcm, CCERR_OK, "Corrupted public key");
    ok(is_zero(plaintext_bis->len, plaintext_bis->bytes), "Delete on error");
    ciphertext->bytes[2] ^= 1;

    // Corrupted encrypted data (first byte)
    size_t b = ((test->options & ECIES_EXPORT_PUB_STANDARD) == ECIES_EXPORT_PUB_STANDARD)
                   ? ccec_x963_export_size(0, pub_remote_key)
                   : ccec_compact_export_size(0, pub_remote_key);
    ciphertext->bytes[b] ^= 1;
    memset(plaintext_bis->bytes, 0xAA, plaintext_bis->len);
    output_size = plaintext_bis->len;
    is_or_goto(test_ccecies_decrypt_gcm(remote_key,
                                        &ecies_dec,
                                        shared_secret->len,
                                        shared_secret->bytes,
                                        ciphertext->len,
                                        ciphertext->bytes,
                                        sharedInfo1_size,
                                        test->sharedInfo1,
                                        sharedInfo2_size,
                                        test->sharedInfo2,
                                        &output_size,
                                        plaintext_bis->bytes),
               CCMODE_INTEGRITY_FAILURE,
               "Corrupted encrypted data, first byte",
               errout);
    ok(is_zero(plaintext_bis->len, plaintext_bis->bytes), "Delete on error");
    ciphertext->bytes[b] ^= 1;

    // Corrupted encrypted data (last byte)
    ciphertext->bytes[ciphertext->len - test->mac_nbytes - 1] ^= 1;
    memset(plaintext_bis->bytes, 0xAA, plaintext_bis->len);
    output_size = plaintext_bis->len;
    is_or_goto(test_ccecies_decrypt_gcm(remote_key,
                                        &ecies_dec,
                                        shared_secret->len,
                                        shared_secret->bytes,
                                        ciphertext->len,
                                        ciphertext->bytes,
                                        sharedInfo1_size,
                                        test->sharedInfo1,
                                        sharedInfo2_size,
                                        test->sharedInfo2,
                                        &output_size,
                                        plaintext_bis->bytes),
               CCMODE_INTEGRITY_FAILURE,
               "Corrupted encrypted data, last byte",
               errout);
    ok(is_zero(plaintext_bis->len, plaintext_bis->bytes), "Delete on error");
    ciphertext->bytes[ciphertext->len - test->mac_nbytes - 1] ^= 1;

    // Corrupted mac
    ciphertext->bytes[ciphertext->len - test->mac_nbytes] ^= 1;
    memset(plaintext_bis->bytes, 0xAA, plaintext_bis->len);
    output_size = plaintext_bis->len;
    is_or_goto(test_ccecies_decrypt_gcm(remote_key,
                                        &ecies_dec,
                                        shared_secret->len,
                                        shared_secret->bytes,
                                        ciphertext->len,
                                        ciphertext->bytes,
                                        sharedInfo1_size,
                                        test->sharedInfo1,
                                        sharedInfo2_size,
                                        test->sharedInfo2,
                                        &output_size,
                                        plaintext_bis->bytes),
               CCMODE_INTEGRITY_FAILURE,
               "Corrupted mac",
               errout);
    ok(is_zero(plaintext_bis->len, plaintext_bis->bytes), "Delete on error");
    ciphertext->bytes[ciphertext->len - test->mac_nbytes] ^= 1;

    // Output buffer too small
    fake_size = plaintext_bis->len - 1;
    memset(plaintext_bis->bytes, 0xAA, plaintext_bis->len);
    output_size = fake_size;
    is_or_goto(test_ccecies_decrypt_gcm(remote_key,
                                        &ecies_dec,
                                        shared_secret->len,
                                        shared_secret->bytes,
                                        ciphertext->len,
                                        ciphertext->bytes,
                                        sharedInfo1_size,
                                        test->sharedInfo1,
                                        sharedInfo2_size,
                                        test->sharedInfo2,
                                        &output_size,
                                        plaintext_bis->bytes),
               CCERR_PARAMETER,
               "Decrypt: output too small",
               errout);
    ok(is_zero(fake_size, plaintext_bis->bytes), "Delete on error");

    memset(plaintext_bis->bytes, 0xAA, plaintext_bis->len);
    output_size = plaintext_bis->len;
    if (test->options & ECIES_EPH_PUBKEY_IN_SHAREDINFO1) {
        // SharedInfo1 must not be passed
        is_or_goto(test_ccecies_decrypt_gcm(remote_key,
                                            &ecies_dec,
                                            shared_secret->len,
                                            shared_secret->bytes,
                                            ciphertext->len,
                                            ciphertext->bytes,
                                            sizeof(shared_info3),
                                            shared_info3,
                                            sharedInfo2_size,
                                            test->sharedInfo2,
                                            &output_size,
                                            plaintext_bis->bytes),
                   CCERR_PARAMETER,
                   "SharedInfo1 must not be passed",
                   errout);
        ok(is_zero(plaintext_bis->len, plaintext_bis->bytes), "Delete on error");
    } else if (test->options & ECIES_EPH_PUBKEY_AND_SHAREDINFO1) {
        // SharedInfo1 must be passed
        is_or_goto(test_ccecies_decrypt_gcm(remote_key,
                                            &ecies_dec,
                                            shared_secret->len,
                                            shared_secret->bytes,
                                            ciphertext->len,
                                            ciphertext->bytes,
                                            0,
                                            NULL,
                                            sharedInfo2_size,
                                            test->sharedInfo2,
                                            &output_size,
                                            plaintext_bis->bytes),
                   CCERR_PARAMETER,
                   "SharedInfo1 must be passed",
                   errout);
        ok(is_zero(plaintext_bis->len, plaintext_bis->bytes), "Delete on error");
    }

    if ((test->options & ECIES_EPH_PUBKEY_IN_SHAREDINFO1) == 0) {
        // SharedInfo1 mismatch
        is_or_goto(test_ccecies_decrypt_gcm(remote_key,
                                            &ecies_dec,
                                            shared_secret->len,
                                            shared_secret->bytes,
                                            ciphertext->len,
                                            ciphertext->bytes,
                                            sizeof(shared_info3),
                                            shared_info3,
                                            sharedInfo2_size,
                                            test->sharedInfo2,
                                            &output_size,
                                            plaintext_bis->bytes),
                   CCMODE_INTEGRITY_FAILURE,
                   "SharedInfo1 mismatch",
                   errout);
        ok(is_zero(plaintext_bis->len, plaintext_bis->bytes), "Delete on error");
    }

    // SharedInfo2 mismatch
    memset(plaintext_bis->bytes, 0xAA, plaintext_bis->len);
    output_size = plaintext_bis->len;
    is_or_goto(test_ccecies_decrypt_gcm(remote_key,
                                        &ecies_dec,
                                        shared_secret->len,
                                        shared_secret->bytes,
                                        ciphertext->len,
                                        ciphertext->bytes,
                                        sharedInfo1_size,
                                        test->sharedInfo1,
                                        sizeof(shared_info3),
                                        shared_info3,
                                        &output_size,
                                        plaintext_bis->bytes),
               CCMODE_INTEGRITY_FAILURE,
               "SharedInfo2 mismatch",
               errout);
    ok(is_zero(plaintext_bis->len, plaintext_bis->bytes), "Delete on error");

    // ------------------------------
    // Negative testing of encrypt
    // ------------------------------

    // Wrong size
    struct ccecies_gcm ecies_enc_bogus;
    ecies_enc_bogus = ecies_enc;
    ecies_enc_bogus.options = 0;

    is(ccecies_encrypt_gcm_ciphertext_size(pub_remote_key, &ecies_enc_bogus, plaintext->len), (size_t)0, "Error case");

    // Bad random, does not apply to "from shared secret version" since
    // it does not generate ephemeral key
    ccrng_ecfips_test_init(&rng, 0, NULL);
    output_size = ciphertext->len;
    is(ccecies_encrypt_gcm(pub_remote_key,
                           &ecies_enc,
                           plaintext->len,
                           plaintext->bytes,
                           sharedInfo1_size,
                           test->sharedInfo1,
                           sharedInfo2_size,
                           test->sharedInfo2,
                           &output_size,
                           ciphertext->bytes),
       CCERR_CRYPTO_CONFIG,
       "Bad random");

    // Output size too small
    fake_size = ccecies_encrypt_gcm_ciphertext_size(pub_remote_key, &ecies_enc, plaintext->len) - 1;
    is(test_ccecies_encrypt_gcm(pub_remote_key,
                                &ecies_enc,
                                ccec_ctx_pub(ephemeral_key),
                                shared_secret->len,
                                shared_secret->bytes,
                                plaintext->len,
                                plaintext->bytes,
                                sharedInfo1_size,
                                test->sharedInfo1,
                                sharedInfo2_size,
                                test->sharedInfo2,
                                &fake_size,
                                ciphertext->bytes),
       CCERR_PARAMETER,
       "Encrypt: output too small");

    status = 1; // pass
errout:
    ok(status == 1, "Error in test %i", test_counter);
    free(expectedCiphertext);
    free(eph_priv_key);
    free(dec_priv_key);
    free(plaintext);
    free(plaintext_bis);
    free(ciphertext);
    free(shared_secret);
    ccec_full_ctx_clear_cp(cp, remote_key);
    ccec_full_ctx_clear_cp(cp, ephemeral_key);
    return status;
}

// Process one vector
static int ccecies_gcm_kat_test(const struct ccecies_vector *test, int test_counter)
{
    int status = 0; // fail
    byteBuffer plaintext = hexStringToBytes(test->message);
    byteBuffer expectedCiphertext = hexStringToBytes(
        ((test->options & ECIES_EXPORT_PUB_STANDARD) == ECIES_EXPORT_PUB_STANDARD) ? test->cipher : test->compact_cipher);
    size_t sharedInfo1_size = strlen(test->sharedInfo1);
    size_t sharedInfo2_size = strlen(test->sharedInfo2);
    byteBuffer eph_priv_key = hexStringToBytes(test->eph_priv_key);
    byteBuffer dec_priv_key = hexStringToBytes(test->dec_priv_key);
    byteBuffer shared_secret = hexStringToBytes(test->Z);
    struct ccrng_ecfips_test_state rng;
    struct ccecies_gcm ecies_enc;
    struct ccecies_gcm ecies_dec;
    ccec_const_cp_t cp = test->curve();

    ccec_full_ctx_decl_cp(cp, remote_key);
    ccec_full_ctx_decl_cp(cp, ephemeral_key);

    // Buffer for outputs
    byteBuffer ciphertext = NULL;
    byteBuffer plaintext_bis = NULL;

    // Generate "remote" public key from private key
    is_or_goto(ccec_recover_full_key(cp, dec_priv_key->len, dec_priv_key->bytes, remote_key), CCERR_OK, "Generated Key", errout);
    is_or_goto(
        ccec_recover_full_key(cp, eph_priv_key->len, eph_priv_key->bytes, ephemeral_key), CCERR_OK, "Generated Key", errout);

    // Set RNG to control ephemeral key
    ccrng_ecfips_test_init(&rng, eph_priv_key->len, eph_priv_key->bytes);
    is_or_goto(ccecies_encrypt_gcm_setup(&ecies_enc,
                                         test->di,
                                         (struct ccrng_state *)&rng,
                                         ccaes_gcm_encrypt_mode(),
                                         test->key_nbytes,
                                         test->mac_nbytes,
                                         test->options),
               CCERR_OK,
               "KAT Encrypt setup",
               errout);
    is_or_goto(ccecies_decrypt_gcm_setup(
                   &ecies_dec, test->di, ccaes_gcm_decrypt_mode(), test->key_nbytes, test->mac_nbytes, test->options),
               CCERR_OK,
               "KAT Decrypt setup",
               errout);

    ccec_pub_ctx_t pub_remote_key = ccec_ctx_pub(remote_key);
    ciphertext = mallocByteBuffer(ccecies_encrypt_gcm_ciphertext_size(pub_remote_key, &ecies_enc, plaintext->len));
    plaintext_bis = mallocByteBuffer(ccecies_decrypt_gcm_plaintext_size_cp(cp, &ecies_dec, ciphertext->len));

    is_or_goto(test_ccecies_encrypt_gcm(pub_remote_key,
                                        &ecies_enc,
                                        ccec_ctx_pub(ephemeral_key),
                                        shared_secret->len,
                                        shared_secret->bytes,
                                        plaintext->len,
                                        plaintext->bytes,
                                        sharedInfo1_size,
                                        test->sharedInfo1,
                                        sharedInfo2_size,
                                        test->sharedInfo2,
                                        &ciphertext->len,
                                        ciphertext->bytes),
               CCERR_OK,
               "Encrypt",
               errout);
    is_or_goto(test_ccecies_decrypt_gcm(remote_key,
                                        &ecies_dec,
                                        shared_secret->len,
                                        shared_secret->bytes,
                                        ciphertext->len,
                                        ciphertext->bytes,
                                        sharedInfo1_size,
                                        test->sharedInfo1,
                                        sharedInfo2_size,
                                        test->sharedInfo2,
                                        &plaintext_bis->len,
                                        plaintext_bis->bytes),
               CCERR_OK,
               "Decrypt",
               errout);

    // Checks
    is(ciphertext->len, expectedCiphertext->len, "Ciphertext size correct");

    // Manually checks internal fields for debugging
    // Point
    size_t point_nbytes = expectedCiphertext->len - test->mac_nbytes - plaintext->len;
    ok_memcmp(ciphertext->bytes, expectedCiphertext->bytes, point_nbytes, "Point as expected");

    // Encrypted
    size_t ciphertext_offset = (expectedCiphertext->len - test->mac_nbytes - plaintext->len);
    ok_memcmp(ciphertext->bytes + ciphertext_offset,
              expectedCiphertext->bytes + ciphertext_offset,
              plaintext->len,
              "Encrypted data as expected");

    // Tag
    size_t tag_offset = (expectedCiphertext->len - test->mac_nbytes);
    ok_memcmp(ciphertext->bytes + tag_offset, expectedCiphertext->bytes + tag_offset, test->mac_nbytes, "Tag as expected");

    is(plaintext->len, plaintext_bis->len, "Decrypted plaintext size correct");
    ok_memcmp(plaintext->bytes, plaintext_bis->bytes, plaintext->len, "Recovered plaintext correct");

    status = 1;
errout:
    ok(status == 1, "Error in test %i", test_counter);
    free(expectedCiphertext);
    free(eph_priv_key);
    free(dec_priv_key);
    free(plaintext);
    free(plaintext_bis);
    free(ciphertext);
    free(shared_secret);
    ccec_full_ctx_clear_cp(cp, remote_key);
    ccec_full_ctx_clear_cp(cp, ephemeral_key);
    return status;
}

static int ecies_aes_gcm_crypt_decrypt(ccec_full_ctx_t key,
                                       size_t msg_size,
                                       const struct ccdigest_info *di,
                                       struct ccrng_state *rng,
                                       uint32_t options)
{
    int status = 0; // fail
    byteBuffer plaintext = mallocByteBuffer(msg_size);

    // Buffer for outputs
    byteBuffer ciphertext = NULL;
    byteBuffer plaintext_bis = NULL;

    struct ccecies_gcm ecies_enc;
    struct ccecies_gcm ecies_dec;

    ccrng_generate(rng, msg_size, plaintext->bytes);

    is_or_goto(ccecies_encrypt_gcm_setup(&ecies_enc, di, rng, ccaes_gcm_encrypt_mode(), 16, 16, options),
               CCERR_OK,
               "Roundtrip encrypt setup",
               errout);
    is_or_goto(ccecies_decrypt_gcm_setup(&ecies_dec, di, ccaes_gcm_decrypt_mode(), 16, 16, options),
               CCERR_OK,
               "Roundtrip decrypt setup",
               errout);

    ccec_pub_ctx_t pub_key = ccec_ctx_pub(key);

    ciphertext = mallocByteBuffer(ccecies_encrypt_gcm_ciphertext_size(pub_key, &ecies_enc, msg_size));

    plaintext_bis = mallocByteBuffer(ccecies_decrypt_gcm_plaintext_size(key, &ecies_dec, ciphertext->len));

    // With shared info
    if ((options & ECIES_EPH_PUBKEY_IN_SHAREDINFO1) == 0) {
        is_or_goto(ccecies_encrypt_gcm(pub_key,
                                       &ecies_enc,
                                       plaintext->len,
                                       plaintext->bytes,
                                       sizeof(shared_info1),
                                       shared_info1,
                                       sizeof(shared_info2),
                                       shared_info2,
                                       &ciphertext->len,
                                       ciphertext->bytes),
                   CCERR_OK,
                   "Encrypt",
                   errout);

        is_or_goto(ccecies_decrypt_gcm(key,
                                       &ecies_dec,
                                       ciphertext->len,
                                       ciphertext->bytes,
                                       sizeof(shared_info1),
                                       shared_info1,
                                       sizeof(shared_info2),
                                       shared_info2,
                                       &plaintext_bis->len,
                                       plaintext_bis->bytes),
                   CCERR_OK,
                   "Decrypt",
                   errout);

        ok(plaintext->len == plaintext_bis->len, "Encrypt/Decrypt correct keysize");
        ok(memcmp(plaintext->bytes, plaintext_bis->bytes, plaintext->len) == 0, "Shared secrets match");
    }

    // Without shared info
    if ((options & ECIES_EPH_PUBKEY_AND_SHAREDINFO1) == 0) {
        is_or_goto(
            ccecies_encrypt_gcm(
                pub_key, &ecies_enc, plaintext->len, plaintext->bytes, 0, NULL, 0, NULL, &ciphertext->len, ciphertext->bytes),
            CCERR_OK,
            "Encrypt",
            errout);

        is_or_goto(
            ccecies_decrypt_gcm(
                key, &ecies_dec, ciphertext->len, ciphertext->bytes, 0, NULL, 0, NULL, &plaintext_bis->len, plaintext_bis->bytes),
            CCERR_OK,
            "Decrypt",
            errout);

        ok(plaintext->len == plaintext_bis->len, "Encrypt/Decrypt correct keysize");
        ok(memcmp(plaintext->bytes, plaintext_bis->bytes, plaintext->len) == 0, "Shared secrets match");
    }

    status = 1; // Success

errout:
    free(plaintext);
    free(plaintext_bis);
    free(ciphertext);
    return status;
}

static int ecies_test(struct ccrng_state *rng, size_t expected_keysize, ccec_const_cp_t cp, uint32_t options)
{
    int status = 0;
    ccec_full_ctx_decl_cp(cp, full_key);

    ok_or_goto(ccec_generate_key_fips(cp, rng, full_key) == 0, "Generated Key", errout);

    if (verbose)
        diag("Test with keysize %u", expected_keysize);
    ok_or_goto(ccec_ctx_bitlen(full_key) == expected_keysize, "Generated correct keysize", errout);

    // SHA-1
    ok_or_goto(ecies_aes_gcm_crypt_decrypt(full_key, 16, ccsha1_di(), rng, options), "ECIES AES GCM SHA1, Msg length 16", errout);
    ok_or_goto(ecies_aes_gcm_crypt_decrypt(full_key, 1, ccsha1_di(), rng, options), "ECIES AES GCM SHA1, Msg length 1", errout);
    ok_or_goto(
        ecies_aes_gcm_crypt_decrypt(full_key, 4096, ccsha1_di(), rng, options), "ECIES AES GCM SHA1, Msg length 4096", errout);
    ok_or_goto(
        ecies_aes_gcm_crypt_decrypt(full_key, 4097, ccsha1_di(), rng, options), "ECIES AES GCM SHA1, Msg length 4097", errout);

    // SHA-256
    ok_or_goto(
        ecies_aes_gcm_crypt_decrypt(full_key, 16, ccsha256_di(), rng, options), "ECIES AES GCM SHA256, Msg length 16", errout);
    ok_or_goto(
        ecies_aes_gcm_crypt_decrypt(full_key, 1, ccsha256_di(), rng, options), "ECIES AES GCM SHA256, Msg length 1", errout);
    ok_or_goto(ecies_aes_gcm_crypt_decrypt(full_key, 4096, ccsha256_di(), rng, options),
               "ECIES AES GCM SHA256, Msg length 4096",
               errout);
    ok_or_goto(ecies_aes_gcm_crypt_decrypt(full_key, 4097, ccsha256_di(), rng, options),
               "ECIES AES GCM SHA256, Msg length 4097",
               errout);
    status = 1;
errout:
    ccec_full_ctx_clear_cp(cp, full_key);
    return status;
}

typedef int (*test_func_t)(const struct ccecies_vector *test, int test_counter);
static int ecies_gcm_vector_tests(test_func_t func, const struct ccecies_vector *test)
{
    int test_counter = 0;
    int test_status = 1;
    const struct ccecies_vector *current_test = &test[test_counter++];
    while (current_test->di != NULL && test_status) {
        struct ccecies_vector ct = *current_test;
        test_status = func(&ct, test_counter);
        ct.options &= ~(unsigned int)ECIES_EXPORT_PUB_STANDARD; // kill this option
        ct.options |= ECIES_EXPORT_PUB_COMPACT;                 // add this option instead
        test_status &= func(&ct, test_counter);                 // and redo the test
        current_test = &test[test_counter++];
    }
    return test_status;
}

static char *option_name(uint32_t option)
{
    if (ECIES_EXPORT_PUB_STANDARD == (option & ECIES_EXPORT_PUB_STANDARD)) {
        return "ECIES_EXPORT_PUB_STANDARD";
    } else if (ECIES_EXPORT_PUB_COMPACT == (option & ECIES_EXPORT_PUB_COMPACT)) {
        return "ECIES_EXPORT_PUB_COMPACT";
    } else
        return NULL;
}

static int options_test(struct ccrng_state *rng, uint32_t options)
{
    if (verbose)
        diag(option_name(options));

    ok(ecies_test(rng, 192, ccec_cp_192(), options), "ECIES with 192 bit EC Key");
    ok(ecies_test(rng, 224, ccec_cp_224(), options), "ECIES with 224 bit EC Key");
    ok(ecies_test(rng, 256, ccec_cp_256(), options), "ECIES with 256 bit EC Key");
    ok(ecies_test(rng, 384, ccec_cp_384(), options), "ECIES with 384 bit EC Key");
    ok(ecies_test(rng, 521, ccec_cp_521(), options), "ECIES with 521 bit EC Key");
    if (verbose)
        diag_linereturn();

    char buf[134 + 1];
    snprintf(buf, 133, "%s | ECIES_EPH_PUBKEY_IN_SHAREDINFO1", option_name(options));
    buf[133] = 0;
    if (verbose) {
        diag(buf);
    }
    ok(ecies_test(rng, 192, ccec_cp_192(), options | ECIES_EPH_PUBKEY_IN_SHAREDINFO1),
       "ECIES with 192 bit EC Key, public key in sharedInfo1");
    ok(ecies_test(rng, 224, ccec_cp_224(), options | ECIES_EPH_PUBKEY_IN_SHAREDINFO1),
       "ECIES with 224 bit EC Key, public key in sharedInfo1");
    ok(ecies_test(rng, 256, ccec_cp_256(), options | ECIES_EPH_PUBKEY_IN_SHAREDINFO1),
       "ECIES with 256 bit EC Key, public key in sharedInfo1");
    ok(ecies_test(rng, 384, ccec_cp_384(), options | ECIES_EPH_PUBKEY_IN_SHAREDINFO1),
       "ECIES with 384 bit EC Key, public key in sharedInfo1");
    ok(ecies_test(rng, 521, ccec_cp_521(), options | ECIES_EPH_PUBKEY_IN_SHAREDINFO1),
       "ECIES with 521 bit EC Key, public key in sharedInfo1");
    if (verbose) {
        diag_linereturn();
    }

    snprintf(buf, 134, "%s | ECIES_EPH_PUBKEY_AND_SHAREDINFO1", option_name(options));
    buf[134] = 0;
    if (verbose) {
        diag(buf);
    }
    ok(ecies_test(rng, 192, ccec_cp_192(), options | ECIES_EPH_PUBKEY_AND_SHAREDINFO1),
       "ECIES with 192 bit EC Key, public key in sharedInfo1");
    ok(ecies_test(rng, 224, ccec_cp_224(), options | ECIES_EPH_PUBKEY_AND_SHAREDINFO1),
       "ECIES with 224 bit EC Key, public key in sharedInfo1");
    ok(ecies_test(rng, 256, ccec_cp_256(), options | ECIES_EPH_PUBKEY_AND_SHAREDINFO1),
       "ECIES with 256 bit EC Key, public key in sharedInfo1");
    ok(ecies_test(rng, 384, ccec_cp_384(), options | ECIES_EPH_PUBKEY_AND_SHAREDINFO1),
       "ECIES with 384 bit EC Key, public key in sharedInfo1");
    ok(ecies_test(rng, 521, ccec_cp_521(), options | ECIES_EPH_PUBKEY_AND_SHAREDINFO1),
       "ECIES with 521 bit EC Key, public key in sharedInfo1");
    if (verbose) {
        diag_linereturn();
    }

    return 0;
}

static int options_conflict_test(struct ccrng_state *rng)
{
    const struct ccdigest_info *di = ccsha256_di();
    ccec_const_cp_t cp = ccec_cp_256();
    ccec_full_ctx_decl_cp(cp, key);

    uint32_t options = ECIES_EPH_PUBKEY_IN_SHAREDINFO1 | ECIES_EPH_PUBKEY_AND_SHAREDINFO1;

    size_t plaintext_len = 32;
    uint8_t plaintext[plaintext_len];
    ccrng_generate(rng, 32, plaintext);

    struct ccecies_gcm ecies_enc;
    struct ccecies_gcm ecies_dec;
    ok_or_fail(ccecies_encrypt_gcm_setup(&ecies_enc, di, rng, ccaes_gcm_encrypt_mode(), 16, 16, options) == CCERR_OK,
               "Conflict encrypt setup");
    ok_or_fail(ccecies_decrypt_gcm_setup(&ecies_dec, di, ccaes_gcm_decrypt_mode(), 16, 16, options) == CCERR_OK,
               "Conflict decrypt setup");

    ok_or_fail(ccec_generate_key_fips(cp, rng, key) == 0, "Generated Key");
    ccec_pub_ctx_t pub_key = ccec_ctx_pub(key);

    size_t ciphertext_len = ccecies_encrypt_gcm_ciphertext_size(pub_key, &ecies_enc, 32);
    uint8_t ciphertext[ciphertext_len];

    is(ccecies_encrypt_gcm(pub_key,
                           &ecies_enc,
                           plaintext_len,
                           plaintext,
                           sizeof(shared_info1),
                           shared_info1,
                           sizeof(shared_info2),
                           shared_info2,
                           &ciphertext_len,
                           ciphertext),
       CCERR_PARAMETER,
       "Setting both ECIES_EPH_PUBKEY_IN_SHAREDINFO1 and "
       "ECIES_EPH_PUBKEY_AND_SHAREDINFO1 should fail");

    is(ccecies_decrypt_gcm(key,
                           &ecies_dec,
                           ciphertext_len,
                           ciphertext,
                           sizeof(shared_info1),
                           NULL,
                           sizeof(shared_info2),
                           NULL,
                           &plaintext_len,
                           plaintext),
       CCERR_PARAMETER,
       "Setting both ECIES_EPH_PUBKEY_IN_SHAREDINFO1 and "
       "ECIES_EPH_PUBKEY_AND_SHAREDINFO1 should fail");

    ccec_full_ctx_clear_cp(cp, key);
    return 0;
}

static int modes_consistency_test(struct ccrng_state *rng)
{
    const struct ccdigest_info *di = ccsha256_di();
    ccec_const_cp_t cp = ccec_cp_256();
    ccec_full_ctx_decl_cp(cp, key);

    uint32_t options = ECIES_EXPORT_PUB_STANDARD;

    size_t plaintext_len = 32;
    uint8_t plaintext[plaintext_len];
    ccrng_generate(rng, plaintext_len, plaintext);

    struct ccecies_gcm ecies_enc;
    struct ccecies_gcm ecies_dec;

    ok_or_fail(ccecies_encrypt_gcm_setup(&ecies_enc, di, rng, ccaes_gcm_decrypt_mode(), 16, 16, options) == CCERR_CRYPTO_CONFIG,
               "Decrypt mode in encrypt setup");
    ok_or_fail(ccecies_decrypt_gcm_setup(&ecies_dec, di, ccaes_gcm_encrypt_mode(), 16, 16, options) == CCERR_CRYPTO_CONFIG,
               "Encrypt mode in decrypt setup");

    // Actual initialization
    ok_or_fail(ccecies_encrypt_gcm_setup(&ecies_enc, di, rng, ccaes_gcm_encrypt_mode(), 16, 16, options) == CCERR_OK,
               "Consistent modes encrypt setup");
    ok_or_fail(ccecies_decrypt_gcm_setup(&ecies_dec, di, ccaes_gcm_decrypt_mode(), 16, 16, options) == CCERR_OK,
               "Consistent modes decrypt setup");

    ok_or_fail(ccec_generate_key_fips(cp, rng, key) == 0, "Generated Key");
    ccec_pub_ctx_t pub_key = ccec_ctx_pub(key);

    size_t ciphertext_len = ccecies_encrypt_gcm_ciphertext_size(pub_key, &ecies_enc, 32);
    uint8_t ciphertext[ciphertext_len];

    is(ccecies_encrypt_gcm(pub_key,
                           &ecies_dec,
                           plaintext_len,
                           plaintext,
                           sizeof(shared_info1),
                           shared_info1,
                           sizeof(shared_info2),
                           shared_info2,
                           &ciphertext_len,
                           ciphertext),
       CCERR_CRYPTO_CONFIG,
       "Using ECIES decryptor during encryption should fail");

    // Create a valid ciphertext to make sure the decryption function
    is_or_goto(ccecies_encrypt_gcm(pub_key,
                                   &ecies_enc,
                                   plaintext_len,
                                   plaintext,
                                   sizeof(shared_info1),
                                   shared_info1,
                                   sizeof(shared_info2),
                                   shared_info2,
                                   &ciphertext_len,
                                   ciphertext),
               CCERR_OK,
               "Encrypt",
               errout);

    is(ccecies_decrypt_gcm(key,
                           &ecies_enc,
                           ciphertext_len,
                           ciphertext,
                           0,
                           NULL,
                           0,
                           NULL,
                           &plaintext_len,
                           plaintext),
       CCERR_CRYPTO_CONFIG,
       "Using ECIES encryptor during decryption should fail");

errout:
    ccec_full_ctx_clear_cp(cp, key);
    return 0;
}

int ccecies_tests(TM_UNUSED int argc, TM_UNUSED char *const *argv)
{
    struct ccrng_state *rng = global_test_rng;

    plan_tests(6969);

    if (verbose)
        diag("KATs");
    ok(ecies_gcm_vector_tests(ccecies_gcm_kat_test, ccecies_aes_gcm_vectors), "AES GCM KAT");

    if (verbose)
        diag("Negative tests");
    ok(ecies_gcm_vector_tests(ccecies_gcm_kat_negative_test, ccecies_aes_gcm_vectors), "AES GCM Negative tests");

    options_test(rng, ECIES_EXPORT_PUB_STANDARD);
    options_test(rng, ECIES_EXPORT_PUB_COMPACT);

    options_conflict_test(rng);

    modes_consistency_test(rng);

    return 0;
}

#endif

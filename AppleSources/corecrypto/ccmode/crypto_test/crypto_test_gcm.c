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

#include <corecrypto/ccaes.h>
#include <corecrypto/ccmode.h>
#include <corecrypto/ccrng.h>
#include <corecrypto/ccn.h>
#include "cc_runtime_config.h"
#include "ccaes_vng_gcm.h"

#include "ccmode_internal.h"
#include "crypto_test_modes.h"
#include "testbyteBuffer.h"
#include "testmore.h"

static int verbose = 0;

typedef struct ccgcm_test_t {
    char *keyStr;     //key
    char *aDataStr;     //additional data
    char *init_ivStr;      //initialization vector
    char *ptStr;      //plain text
    char *ctStr;      //cipher text
    char *tagStr;     //tag
} ccgcm_test_vector;

// Redundant tests, there are already run as part of crypto_test_modes.c
// however, this file does testing that crypto_test_modes does not support
// This file looks generic but gcm_vectors only contains test for AES
// and there is no way to specify another block cipher.
// crypto_test_modes is really generic.

ccgcm_test_vector gcm_vectors[] = {
#include "../test_vectors/aes_gcm_test_vectors_ossl.inc"
#include "../test_vectors/aes_gcm_test_vectors.inc"
};

size_t nvectors = CC_ARRAY_LEN(gcm_vectors);

static int ccgcm_discrete(const struct ccmode_gcm *mode,
                          size_t key_len, const void *key,
                          size_t iv_len, const void *iv,
                          size_t adata_len, const void *adata,
                          size_t nbytes, const void *in, void *out,
                          size_t tag_len, void *tag)
{
    size_t max_block_len = cc_rand(19); if(max_block_len==0) max_block_len=1;
    if(verbose) printf("\n------max_block_len=%zu\n", max_block_len);
    int rc = 0;

    ccgcm_ctx_decl(mode->size, ctx);
    mode->init(mode, ctx, key_len, key);

    if(iv_len > 0 && iv != NULL) {
        rc |= mode->set_iv(ctx, iv_len, iv);
    }

    if(adata_len > 0 && adata != NULL) {
        if (adata_len>max_block_len) {
            size_t d1 = adata_len-max_block_len;
            rc |= mode->gmac(ctx, max_block_len, adata);
            rc |= mode->gmac(ctx, d1, (const uint8_t *)adata + max_block_len);
        } else {
            rc |= mode->gmac(ctx, adata_len, adata);
        }
    } else {
        if(verbose) printf("Skipping added AAD\n");
    }

    if(nbytes > 0) {
        rc |= mode->gcm(ctx, nbytes, in, out);
    } else {
        if(verbose) printf("Skipping data\n");
    }

    rc |= mode->finalize(ctx, tag_len, tag);
    ccgcm_ctx_clear(mode->size, ctx);

    return rc;
}

typedef int (*ccgcm_test_func_t)(const struct ccmode_gcm *mode,
size_t key_len, const void *key,
size_t iv_len, const void *iv,
size_t adata_len, const void *adata,
size_t nbytes, const void *in, void *out,
size_t tag_len, void *tag);



static int gcm_test_a_function(const struct ccmode_gcm *em, const struct ccmode_gcm *dm,
                               size_t key_len, const void *key,
                               size_t iv_len, const void *iv,
                               size_t adata_len, const void *adata,
                               size_t nbytes, const void *plaintext, void *ciphertext,
                               size_t tag_len, void *tag,
                               ccgcm_test_func_t func)
{

    uint8_t cipher_result[nbytes], plain_result[nbytes];
    uint8_t cipher_tag[tag_len], plain_tag[tag_len];
    int rc;

    rc = func(em, key_len, key, iv_len, iv, adata_len, adata, nbytes, plaintext,     cipher_result, tag_len, cipher_tag);
    ok_or_fail(rc==0, "gcm encryption failed");
    memcpy(plain_tag, tag, tag_len); //set the expected tag for decryption
    rc = func(dm, key_len, key, iv_len, iv, adata_len, adata, nbytes, cipher_result, plain_result,  tag_len, plain_tag );
    ok_or_fail(rc==0, "gcm decryption failed");

    ok_memcmp_or_fail(plaintext, plain_result, nbytes,"Round Trip Encrypt/Decrypt works");
    ok_memcmp_or_fail(tag, cipher_tag, tag_len, "tags match on encrypt");
    ok_memcmp_or_fail(tag, plain_tag, tag_len, "tags match on decrypt");
    ok_memcmp_or_fail(ciphertext, cipher_result, nbytes, "Ciphertext matches known answer");

    plain_tag[0] ^= 1;
    rc = func(dm, key_len, key, iv_len, iv, adata_len, adata, nbytes, cipher_result, plain_result,  tag_len, plain_tag );
    ok_or_fail(rc != 0, "gcm authentication failed");

    return 1;
}

static int gcm_testcase(const struct ccmode_gcm *encrypt_ciphermode, const struct ccmode_gcm *decrypt_ciphermode, size_t casenum)
{
    size_t i=casenum;
    byteBuffer key = hexStringToBytes(gcm_vectors[i].keyStr);
    byteBuffer iv = hexStringToBytes(gcm_vectors[i].init_ivStr);
    byteBuffer adata = hexStringToBytes(gcm_vectors[i].aDataStr);
    byteBuffer plaintext = hexStringToBytes(gcm_vectors[i].ptStr);
    byteBuffer ciphertext = hexStringToBytes(gcm_vectors[i].ctStr);
    byteBuffer tag = hexStringToBytes(gcm_vectors[i].tagStr);

    if(verbose) printf("GCM Case %zu\n", casenum);

    gcm_test_a_function(encrypt_ciphermode, decrypt_ciphermode,
                        key->len, key->bytes,
                        iv->len, iv->bytes,
                        adata->len, adata->bytes,
                        plaintext->len,
                        plaintext->bytes, ciphertext->bytes,
                        tag->len, tag->bytes,
                        ccgcm_discrete);

    gcm_test_a_function(encrypt_ciphermode, decrypt_ciphermode,
                        key->len, key->bytes,
                        iv->len, iv->bytes,
                        adata->len, adata->bytes,
                        plaintext->len,
                        plaintext->bytes, ciphertext->bytes,
                        tag->len, tag->bytes,
                        ccgcm_one_shot);

    gcm_test_a_function(encrypt_ciphermode, decrypt_ciphermode,
                        key->len, key->bytes,
                        iv->len, iv->bytes,
                        adata->len, adata->bytes,
                        plaintext->len,
                        plaintext->bytes, ciphertext->bytes,
                        tag->len, tag->bytes,
                        ccgcm_one_shot_legacy);

    free(key);
    free(iv);
    free(adata);
    free(plaintext);
    free(ciphertext);
    free(tag);
    return 1;

}

static int gcm_test_zerolen_iv(const struct ccmode_gcm *encrypt_ciphermode, const struct ccmode_gcm *decrypt_ciphermode)
{
    int rc;

    byteBuffer key = hexStringToBytes("59454c4c4f57205355424d4152494e45");
    byteBuffer ad = hexStringToBytes("0000005a");
    byteBuffer ptext = hexStringToBytes("506f69736f6e6f7573207061726167726170687320736d61736820796f75722070686f6e6f677261706820696e2068616c660a49742062652074686520496e73706563746168204465636b206f6e207468652077617270617468");
    byteBuffer ctext = hexStringToBytes("3a8fbd9d5e5d53663664c8a67ca82c22d09b932a18fb18a37814330955bf55b73aef15a678182f42b9b0f7d8137b7c30dc09123ab9b150b8e04d65532e223e6a4eacc98275f75e113e9daf8598b7445fe04ec754bfe914bd65e8");
    byteBuffer tag = hexStringToBytes("226a3338b54f22819e933c242746f303");

    uint8_t textout[ptext->len];
    uint8_t tagout[tag->len];

    rc = ccgcm_one_shot(encrypt_ciphermode, key->len, key->bytes, 0, NULL, ad->len, ad->bytes, ptext->len, ptext->bytes, textout, sizeof (tagout), tagout);
    ok_or_fail(rc != 0, "gcm one-shot encryption accepted zero-length iv");

    rc = ccgcm_discrete(encrypt_ciphermode, key->len, key->bytes, 0, NULL, ad->len, ad->bytes, ptext->len, ptext->bytes, textout, sizeof (tagout), tagout);
    ok_or_fail(rc != 0, "gcm discrete encryption accepted zero-length iv");

    rc = ccgcm_one_shot_legacy(encrypt_ciphermode, key->len, key->bytes, 0, NULL, ad->len, ad->bytes, ptext->len, ptext->bytes, textout, sizeof (tagout), tagout);
    ok_or_fail(rc == 0, "gcm one-shot legacy encryption failed");
    ok_memcmp_or_fail(ctext->bytes, textout, ctext->len, "gcm one-shot legacy encryption text mismatch");
    ok_memcmp_or_fail(tag->bytes, tagout, tag->len, "gcm one-shot legacy encryption tag mismatch");

    rc = ccgcm_one_shot(decrypt_ciphermode, key->len, key->bytes, 0, NULL, ad->len, ad->bytes, ctext->len, ctext->bytes, textout, sizeof (tagout), tagout);
    ok_or_fail(rc != 0, "gcm one-shot decryption accepted zero-length iv");

    rc = ccgcm_discrete(decrypt_ciphermode, key->len, key->bytes, 0, NULL, ad->len, ad->bytes, ctext->len, ctext->bytes, textout, sizeof (tagout), tagout);
    ok_or_fail(rc != 0, "gcm discrete decryption accepted zero-length iv");

    rc = ccgcm_one_shot_legacy(decrypt_ciphermode, key->len, key->bytes, 0, NULL, ad->len, ad->bytes, ctext->len, ctext->bytes, textout, sizeof (tagout), tagout);
    ok_or_fail(rc == 0, "gcm legacy decryption failed");
    ok_memcmp_or_fail(ptext->bytes, textout, ptext->len, "gcm one-shot legacy decryption text mismatch");
    ok_memcmp_or_fail(tag->bytes, tagout, tag->len, "gcm one-shot legacy decryption tag mismatch");

    free(key);
    free(tag);
    free(ad);
    free(ptext);
    free(ctext);
    return 1;
}

static int gcm_test_init_with_iv(const struct ccmode_gcm *encrypt_ciphermode, const struct ccmode_gcm *decrypt_ciphermode)
{
    // int rc;

    byteBuffer key = hexStringToBytes("e792232af1917965d75fc9b65a87f656");
    byteBuffer iv1 = hexStringToBytes("c7ccdafe0000000000000000");
    byteBuffer iv2 = hexStringToBytes("c7ccdafe0000000000000001");
    byteBuffer ad = hexStringToBytes("04d7e6bd00cca0947da2");
    byteBuffer ptext = hexStringToBytes("576f772c20746865205368616f6c696e207374796c6520697320616c6c20696e206d650a4368696c642c207468652077686f6c652064616d6e2069736c652069732063616c6c696e206d650a");
    byteBuffer ctext1 = hexStringToBytes("f90a4f9c1250849af5289066aad8c10f67ffc2ca5799e58d8b49cc6f22c495f56f46adb18c3b21b4710306dffc88ce9a7252ba92b74b35db08221d8dca7aed27105b0d1a812bd10e49af2345");
    byteBuffer tag1 = hexStringToBytes("73d833e2d55d741743b09e0e07c6d610");
    byteBuffer ctext2 = hexStringToBytes("d075317f57fc20ff37832f507e90c84fd311a0a160b59084217b642829028dcef56ffa73db659bf250ab97eda2df50635d1fc29f6e2dbbc651acd4e747ed7577805a61708bec9ad8e272cce4");
    byteBuffer tag2 = hexStringToBytes("298184a805bede8490c0da2cf19e7b0e");

    uint8_t ivout[iv1->len];
    uint8_t textout[ptext->len];
    uint8_t tagout[tag1->len];

    ccgcm_ctx_decl(ccgcm_context_size(encrypt_ciphermode), encrypt_ctx);
    ccgcm_ctx_decl(ccgcm_context_size(decrypt_ciphermode), decrypt_ctx);

    ok_or_fail(ccgcm_init_with_iv(encrypt_ciphermode, encrypt_ctx, key->len, key->bytes, iv1->bytes) == 0, "ccgcm_init_with_iv encrypt1");
    ok_or_fail(ccgcm_aad(encrypt_ciphermode, encrypt_ctx, ad->len, ad->bytes) == 0, "ccgcm_aad encrypt1");
    ok_or_fail(ccgcm_update(encrypt_ciphermode, encrypt_ctx, ptext->len, ptext->bytes, textout) == 0, "ccgcm_update encrypt1");
    ok_or_fail(ccgcm_finalize(encrypt_ciphermode, encrypt_ctx, tag1->len, tagout) == 0, "ccgcm_finalize encrypt1");
    ok_memcmp(ctext1->bytes, textout, ctext1->len, "ctext1 encrypt1");
    ok_memcmp(tag1->bytes, tagout, tag1->len, "tag1 encrypt1");

    ok_or_fail(ccgcm_init_with_iv(decrypt_ciphermode, decrypt_ctx, key->len, key->bytes, iv1->bytes) == 0, "ccgcm_init_with_iv decrypt1");
    ok_or_fail(ccgcm_aad(decrypt_ciphermode, decrypt_ctx, ad->len, ad->bytes) == 0, "ccgcm_aad decrypt1");
    ok_or_fail(ccgcm_update(decrypt_ciphermode, decrypt_ctx, ctext1->len, ctext1->bytes, textout) == 0, "ccgcm_update decrypt1");
    ok_or_fail(ccgcm_finalize(decrypt_ciphermode, decrypt_ctx, tag1->len, tagout) == 0, "ccgcm_finalize decrypt1");
    ok_memcmp(ptext->bytes, textout, ptext->len, "ptext decrypt1");
    ok_memcmp(tag1->bytes, tagout, tag1->len, "tag1 decrypt1");

    ok_or_fail(ccgcm_reset(encrypt_ciphermode, encrypt_ctx) == 0, "ccgcm_reset encrypt2");
    ok_or_fail(ccgcm_inc_iv(encrypt_ciphermode, encrypt_ctx, ivout) == 0, "ccgcm_inc_iv encrypt2");
    ok_or_fail(ccgcm_aad(encrypt_ciphermode, encrypt_ctx, ad->len, ad->bytes) == 0, "ccgcm_aad encrypt2");
    ok_or_fail(ccgcm_update(encrypt_ciphermode, encrypt_ctx, ptext->len, ptext->bytes, textout) == 0, "ccgcm_update encrypt2");
    ok_or_fail(ccgcm_finalize(encrypt_ciphermode, encrypt_ctx, tag2->len, tagout) == 0, "ccgcm_finalize encrypt2");
    ok_memcmp(iv2->bytes, ivout, iv2->len, "iv2 encrypt2");
    ok_memcmp(ctext2->bytes, textout, ctext2->len, "ctext2 encrypt2");
    ok_memcmp(tag2->bytes, tagout, tag2->len, "tag2 encrypt2");

    ok_or_fail(ccgcm_reset(decrypt_ciphermode, decrypt_ctx) == 0, "ccgcm_reset decrypt2");
    ok_or_fail(ccgcm_inc_iv(decrypt_ciphermode, decrypt_ctx, ivout) == 0, "ccgcm_inc_iv decrypt2");
    ok_or_fail(ccgcm_aad(decrypt_ciphermode, decrypt_ctx, ad->len, ad->bytes) == 0, "ccgcm_aad decrypt2");
    ok_or_fail(ccgcm_update(decrypt_ciphermode, decrypt_ctx, ctext2->len, ctext2->bytes, textout) == 0, "ccgcm_update decrypt2");
    ok_or_fail(ccgcm_finalize(decrypt_ciphermode, decrypt_ctx, tag2->len, tagout) == 0, "ccgcm_finalize decrypt2");
    ok_memcmp(iv2->bytes, ivout, iv2->len, "iv2 decrypt2");
    ok_memcmp(ptext->bytes, textout, ptext->len, "ptext decrypt2");
    ok_memcmp(tag2->bytes, tagout, tag2->len, "tag2 decrypt2");

    ok_or_fail(ccgcm_init_with_iv(encrypt_ciphermode, encrypt_ctx, key->len, key->bytes, iv1->bytes) == 0, "ccgcm_init_with_iv encrypt no-set-iv");
    ok_or_fail(ccgcm_reset(encrypt_ciphermode, encrypt_ctx) == 0, "ccgcm_reset encrypt no-set-iv");
    ok_or_fail(ccgcm_set_iv(encrypt_ciphermode, encrypt_ctx, iv2->len, iv2->bytes) != 0, "ccgcm_set_iv encrypt no-set-iv");

    ok_or_fail(ccgcm_init_with_iv(decrypt_ciphermode, decrypt_ctx, key->len, key->bytes, iv1->bytes) == 0, "ccgcm_init_with_iv decrypt no-set-iv");
    ok_or_fail(ccgcm_reset(decrypt_ciphermode, decrypt_ctx) == 0, "ccgcm_reset decrypt no-set-iv");
    ok_or_fail(ccgcm_set_iv(decrypt_ciphermode, decrypt_ctx, iv2->len, iv2->bytes) != 0, "ccgcm_set_iv decrypt no-set-iv");

    ok_or_fail(ccgcm_init(encrypt_ciphermode, encrypt_ctx, key->len, key->bytes) == 0, "ccgcm_init_with_iv encrypt no-inc-iv");
    ok_or_fail(ccgcm_set_iv(encrypt_ciphermode, encrypt_ctx, iv1->len, iv1->bytes) == 0, "ccgcm_set_iv encrypt no-inc-iv");
    ok_or_fail(ccgcm_reset(encrypt_ciphermode, encrypt_ctx) == 0, "ccgcm_reset encrypt no-inc-iv");
    ok_or_fail(ccgcm_inc_iv(encrypt_ciphermode, encrypt_ctx, ivout) != 0, "ccgcm_set_iv encrypt no-inc-iv");

    ok_or_fail(ccgcm_init(decrypt_ciphermode, decrypt_ctx, key->len, key->bytes) == 0, "ccgcm_init_with_iv decrypt no-inc-iv");
    ok_or_fail(ccgcm_set_iv(decrypt_ciphermode, decrypt_ctx, iv1->len, iv1->bytes) == 0, "ccgcm_set_iv decrypt no-inc-iv");
    ok_or_fail(ccgcm_reset(decrypt_ciphermode, decrypt_ctx) == 0, "ccgcm_reset decrypt no-inc-iv");
    ok_or_fail(ccgcm_inc_iv(decrypt_ciphermode, decrypt_ctx, ivout) != 0, "ccgcm_set_iv decrypt no-inc-iv");


    free(key);
    free(iv1);
    free(iv2);
    free(ad);
    free(ptext);
    free(ctext1);
    free(tag1);
    free(ctext2);
    free(tag2);



    return 1;
}

/* In this test we reach into the internal state to trigger the validation error on long messages. */
static int gcm_test_counter_wrap(const struct ccmode_gcm *encrypt_ciphermode, const struct ccmode_gcm *decrypt_ciphermode)
{
    uint8_t buf[CCGCM_BLOCK_NBYTES] = { 0 };

    ccgcm_ctx_decl(ccgcm_context_size(encrypt_ciphermode), encrypt_ctx);
    ccgcm_ctx_decl(ccgcm_context_size(decrypt_ciphermode), decrypt_ctx);

    ok_or_fail(ccgcm_init(encrypt_ciphermode, encrypt_ctx, CCAES_KEY_SIZE_128, buf) == 0, "ccgcm_init encrypt counter wrap");
    ok_or_fail(ccgcm_set_iv(encrypt_ciphermode, encrypt_ctx, CCGCM_IV_NBYTES, buf) == 0, "ccgcm_set encrypt counter wrap");
    ok_or_fail(ccgcm_update(encrypt_ciphermode, encrypt_ctx, sizeof (buf), buf, buf) == 0, "ccgcm_update (begin) encrypt counter wrap");
    ((struct _ccmode_gcm_key *)encrypt_ctx)->text_nbytes = CCGCM_TEXT_MAX_NBYTES - CCGCM_BLOCK_NBYTES;
    ok_or_fail(ccgcm_update(encrypt_ciphermode, encrypt_ctx, sizeof (buf), buf, buf) == 0, "ccgcm_update (end) encrypt counter wrap");
    ok_or_fail(ccgcm_update(encrypt_ciphermode, encrypt_ctx, 1, buf, buf) == CCMODE_INVALID_INPUT, "ccgcm_update (overflow) encrypt counter wrap");

    ok_or_fail(ccgcm_init(decrypt_ciphermode, decrypt_ctx, CCAES_KEY_SIZE_128, buf) == 0, "ccgcm_init decrypt counter wrap");
    ok_or_fail(ccgcm_set_iv(decrypt_ciphermode, decrypt_ctx, CCGCM_IV_NBYTES, buf) == 0, "ccgcm_set decrypt counter wrap");
    ok_or_fail(ccgcm_update(decrypt_ciphermode, decrypt_ctx, sizeof (buf), buf, buf) == 0, "ccgcm_update (begin) decrypt counter wrap");
    ((struct _ccmode_gcm_key *)decrypt_ctx)->text_nbytes = CCGCM_TEXT_MAX_NBYTES - CCGCM_BLOCK_NBYTES;
    ok_or_fail(ccgcm_update(decrypt_ciphermode, decrypt_ctx, sizeof (buf), buf, buf) == 0, "ccgcm_update (end) decrypt counter wrap");
    ok_or_fail(ccgcm_update(decrypt_ciphermode, decrypt_ctx, 1, buf, buf) == CCMODE_INVALID_INPUT, "ccgcm_update (overflow) decrypt counter wrap");

    return 1;
}

static void gcm_test_gf_mult(const struct ccmode_gcm *ciphermode)
{
    uint8_t key[CCAES_KEY_SIZE_128];
    int rv = ccrng_generate(global_test_rng, sizeof(key), key);
    is(rv, CCERR_OK, "ccrng_generate failed");

    ccgcm_ctx_decl(ccgcm_context_size(ciphermode), ctx);

    rv = ccgcm_init(ciphermode, ctx, CCAES_KEY_SIZE_128, key);
    is(rv, CCERR_OK, "ccgcm_init failed");

    uint8_t I[16], I0[16], I1[16], I2[16], I3[16];
    rv = ccrng_generate(global_test_rng, sizeof(I), I);
    is(rv, CCERR_OK, "ccrng_generate failed");

    ccmode_gcm_gf_mult(CCMODE_GCM_KEY_H(ctx), I, I0);

    ccmode_gcm_gf_mult_32(CCMODE_GCM_KEY_H(ctx), I, I1);
    ok_memcmp(I0, I1, sizeof(I1), "ccmode_gcm_gf_mult ≠ ccmode_gcm_gf_mult_32");

    // On machines with uint128_t, test ccmode_gcm_gf_mult_64().
#if (CCN_UNIT_SIZE == 8) && CC_DUNIT_SUPPORTED
    ccmode_gcm_gf_mult_64(CCMODE_GCM_KEY_H(ctx), I, I2);
    ok_memcmp(I0, I2, sizeof(I2), "ccmode_gcm_gf_mult ≠ ccmode_gcm_gf_mult_64");
#else
    (void)I2;
#endif

    // If the VNG version of gf_mult() is available,
    // compare it against the default C implementation.
#if CCMODE_GCM_VNG_SPEEDUP
#ifdef  __x86_64__
    if (CC_HAS_AESNI() && CC_HAS_SupplementalSSE3())
#endif
    {
        gcm_gmult(I, CCMODE_GCM_VNG_KEY_Htable(ctx), I3);
        ok_memcmp(I0, I3, sizeof(I3), "ccmode_gcm_gf_mult ≠ gcm_gmult");
    }
#endif
}

static void gcm_test_gf_mult_edge_case(void)
{
    // Counterexample for bmul64:
    //   %x: 15554860936645695441
    //   %y: 17798150062858027007

    const uint8_t a[16] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xd7, 0xdd, 0xf7, 0x9b, 0xd3, 0x5d, 0xd7, 0xd1
    };

    const uint8_t b[16] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xf6, 0xff, 0xbb, 0x2e, 0xfb, 0xbf, 0xbf, 0xff
    };

    const uint8_t c[16] = {
        0x35, 0xa3, 0x58, 0x0e, 0xed, 0x93, 0xf5, 0x4b,
        0x75, 0xc4, 0x80, 0x75, 0x8e, 0x13, 0x6d, 0x43
    };

    uint8_t r[16];

    ccmode_gcm_gf_mult(a, b, r);
    ok_memcmp(r, c, sizeof(c), "ccmode_gcm_gf_mult KAT failed");

    ccmode_gcm_gf_mult_32(a, b, r);
    ok_memcmp(r, c, sizeof(c), "ccmode_gcm_gf_mult_32 KAT failed");

#if (CCN_UNIT_SIZE == 8) && CC_DUNIT_SUPPORTED
    ccmode_gcm_gf_mult_64(a, b, r);
    ok_memcmp(r, c, sizeof(c), "ccmode_gcm_gf_mult_64 KAT failed");
#endif
}

int test_gcm(const struct ccmode_gcm *encrypt_ciphermode, const struct ccmode_gcm *decrypt_ciphermode)
{
    for (size_t i = 0; i < nvectors; i++) {
        gcm_testcase(encrypt_ciphermode, decrypt_ciphermode, i);
    }

    gcm_test_zerolen_iv(encrypt_ciphermode, decrypt_ciphermode);
    gcm_test_init_with_iv(encrypt_ciphermode, decrypt_ciphermode);
    gcm_test_counter_wrap(encrypt_ciphermode, decrypt_ciphermode);
    gcm_test_gf_mult(encrypt_ciphermode);
    gcm_test_gf_mult_edge_case();

    return 1;
}

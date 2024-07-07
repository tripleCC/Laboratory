/* Copyright (c) (2020,2021,2023) Apple Inc. All rights reserved.
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

#include <corecrypto/ccrsa.h>
#include <corecrypto/ccsha2.h>
#include <corecrypto/cc_priv.h>
#include <corecrypto/ccrsabssa.h>
#include "testbyteBuffer.h"
#include "ccrsabssa_test_vectors.h"
#include "ccrsabssa_internal.h"

void test_blind_unblind(const struct ccrsabssa_ciphersuite * ciphersuite);
void test_rsabssa_test_vectors(void);

// Exercise ccn_write_uint_padded_ct() edge cases.
const struct ccrsabssa_ciphersuite ccrsabssa_ciphersuite_rsa2041_sha256 = {
    .rsa_modulus_nbits = 2041,
    .di = ccsha256_di,
    .salt_size_nbytes = 48,
};

int ccrsabssa_tests(CC_UNUSED int argc, CC_UNUSED char *const *argv)
{
    plan_tests(732);
    diag("Starting RSABSSA tests");
    
    const struct ccrsabssa_ciphersuite *ciphersuites [] = {
        &ccrsabssa_ciphersuite_rsa2041_sha256,
        &ccrsabssa_ciphersuite_rsa2048_sha384,
        &ccrsabssa_ciphersuite_rsa3072_sha384,
        &ccrsabssa_ciphersuite_rsa4096_sha384};
    
    for (size_t i = 0; i < CC_ARRAY_LEN(ciphersuites); i++) {
        test_blind_unblind(ciphersuites[i]);
    }
    
    test_rsabssa_test_vectors();
    
    return 0;
}

void test_rsabssa_test_vectors(void) {
    // We start by reconstructing the key from the test vectors.
    size_t modulus_nbytes = sizeof(n);
    size_t e_nbytes = sizeof(e);
    ccrsa_full_ctx_decl(ccn_sizeof(modulus_nbytes * 8), full_key);
    ccrsa_ctx_n(full_key) = ccn_nof_size(modulus_nbytes);
    
    int ret = ccrsa_make_priv(full_key,
                              sizeof(e), e,
                              sizeof(p), p,
                              sizeof(q), q);
    
    ok(CCERR_OK == ret, "ccrsabssa: Failed to initialize test key.");
    
    uint8_t public_key_bytes[modulus_nbytes];
    uint8_t exported_e[e_nbytes];
    
    ok(CCERR_OK == ccrsa_get_pubkey_components(ccrsa_ctx_public(full_key),
                                               public_key_bytes, &modulus_nbytes,
                                               exported_e, &e_nbytes),
       "ccrsabssa: Failed to export public key components of the test key.");
    
    ok(CCERR_OK == cc_cmp_safe(modulus_nbytes, public_key_bytes, n),
       "ccrsabssa: Exported public key doesn't match the one from test vector.");
    
    uint8_t recovered_d[modulus_nbytes];
    ccn_write_uint(ccn_nof_size(modulus_nbytes), ccrsa_ctx_d(full_key), modulus_nbytes, recovered_d);
    ok(CCERR_OK == cc_cmp_safe(modulus_nbytes, recovered_d, d_vector),
       "ccrsabssa: Recomputed d does not match the one from the test vector.");
    
    // Now that the key is verified, we perform the unblinding of the signature with the blinding inverse and verify the resulting signature.
    byteBuffer computed_signature  = mallocByteBuffer(modulus_nbytes);
    ok(CCERR_OK == ccrsabssa_unblind_signature(&ccrsabssa_ciphersuite_rsa4096_sha384,
                                               ccrsa_ctx_public(full_key),
                                               evaluated_message, sizeof(evaluated_message),
                                               blind_inv, sizeof(blind_inv),
                                               msg, sizeof(msg),
                                               computed_signature->bytes, computed_signature->len),
       "ccrsabssa: Unblinding failed or resulting signature is not valid.");
    ok_memcmp(computed_signature->bytes, sig, sizeof(sig),
              "ccrsabssa: Unblinded signature does not match the one from test vector.");
    free(computed_signature);
}

/// This test simply blinds and unblinds a message and verifies the resulting signature.
void test_blind_unblind(const struct ccrsabssa_ciphersuite * ciphersuite) {
    size_t modulus_nbits = ciphersuite->rsa_modulus_nbits;
    int err = 0;
    
    const uint8_t e[] = { 0x1, 0x00, 0x01 };
    ccrsa_full_ctx_decl_nbits(modulus_nbits, rsaPrivateKey);
    err = ccrsa_generate_key(modulus_nbits, rsaPrivateKey, sizeof(e), e, global_test_rng);
    ok(err == CCERR_OK, "ccrsabssa: Failed to generate private key");
    
    ccrsa_pub_ctx_t rsaPublicKey = ccrsa_ctx_public(rsaPrivateKey);
    size_t modulus_nbytes = (size_t) cc_ceiling(ccrsa_pubkeylength(rsaPublicKey), 8);
        
    for (int i = 0; i < 30; i++) {
        // We generate a random 32-byte nonce.
        size_t msg_nbytes = 32;
        uint8_t msg[32] = {0};
        ok(CCERR_OK == ccrng_generate(global_test_rng, msg_nbytes, msg), "Failed to generate random message");
        
        byteBuffer blinding_inverse = mallocByteBuffer(modulus_nbytes);
        byteBuffer blinded_message  = mallocByteBuffer(modulus_nbytes);
        byteBuffer signature  = mallocByteBuffer(modulus_nbytes);
        
        // We blind the message
        int rv = ccrsabssa_blind_message(ciphersuite, rsaPublicKey, msg, msg_nbytes,
                                         blinding_inverse->bytes, blinding_inverse->len,
                                         blinded_message->bytes, blinded_message->len,
                                         global_test_rng);
        ok(CCERR_OK == rv, "ccrsabssa: Failed to blind the message.");
        
        // We sign the blinded message
        ok(CCERR_OK == ccrsabssa_sign_blinded_message(ciphersuite, rsaPrivateKey,
                                                      blinded_message->bytes, blinded_message->len,
                                                      signature->bytes, signature->len,
                                                      global_test_rng), "ccrsabssa: Failed performing blinded signature.");
        
        // We remove the blinding and the function verifies the resulting signature.
        byteBuffer unblinded_signature  = mallocByteBuffer(modulus_nbytes);
        ok(CCERR_OK == ccrsabssa_unblind_signature(ciphersuite, rsaPublicKey,
                                                   signature->bytes, signature->len,
                                                   blinding_inverse->bytes, blinding_inverse->len,
                                                   msg, sizeof(msg),
                                                   unblinded_signature->bytes, unblinded_signature->len), "ccrsabssa: Failed to perform unblinding.");
        
        free(unblinded_signature);
        free(blinding_inverse);
        free(blinded_message);
        free(signature);
    }
    
    ccrsa_full_ctx_clear_nbits(modulus_nbits, rsaPrivateKey);
}

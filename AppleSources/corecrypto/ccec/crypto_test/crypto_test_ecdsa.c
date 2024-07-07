/* Copyright (c) (2014,2015,2016,2017,2018,2019) Apple Inc. All rights reserved.
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

#include "crypto_test_ec.h"
#include <corecrypto/ccsha1.h>
#include <corecrypto/ccsha2.h>
#include <corecrypto/ccrng_ecfips_test.h>

#include <corecrypto/ccec_priv.h>
#include "ccec_internal.h"

const struct ccecdsa_vector ccecdsa_vectors[]=
{
#include "../test_vectors/ecdsa.inc"
#include "../test_vectors/p256-sha256.inc"
    {
        .di=NULL,
    },
};

// Process one vector
static int ccecdsa_kat_vector(const struct ccecdsa_vector *test)
{
    int status = 0; // fail
    byteBuffer expected_r = hexStringToBytes(test->r);
    byteBuffer expected_s = hexStringToBytes(test->s);
    byteBuffer priv_key = hexStringToBytes(test->priv_key);
    byteBuffer k = hexStringToBytes(test->k);
    byteBuffer x = hexStringToBytes(test->qx);
    byteBuffer y = hexStringToBytes(test->qy);
    struct ccrng_ecfips_test_state rng;
    ccec_const_cp_t cp=test->curve();
    const struct ccdigest_info *di=test->di;
    ccec_full_ctx_decl_cp(cp, key);
    ccec_ctx_init(cp, key);
    bool valid;
    ccec_pub_ctx_t pkey= ccec_ctx_pub(key);

    if (priv_key->len) {
        // Generate "remote" public key from private key
        ok_or_fail((ccec_recover_full_key(cp,priv_key->len, priv_key->bytes, key) == 0), "Generated Full Key");
    } else {
        ok_or_fail((ccec_make_pub(ccec_cp_prime_bitlen(cp), x->len, x->bytes,
                      y->len, y->bytes, pkey)==0), "Generated Pub Key");
    }

    // Buffer for outputs
    byteBuffer computed_r = mallocByteBuffer(ccec_signature_r_s_size(pkey));
    byteBuffer computed_s = mallocByteBuffer(ccec_signature_r_s_size(pkey));
    byteBuffer hash = mallocByteBuffer(di->output_size);

    if(test->hex_msg == 1){
        byteBuffer m = hexStringToBytes(test->msg);
        ccdigest(di, m->len, m->bytes, hash->bytes);
        free(m);
    }else{
        ccdigest(di, strlen(test->msg), test->msg, hash->bytes);
    }

    // ccec_print_full_key("Imported key", key);
    ok_or_goto((ccec_verify_composite(pkey, di->output_size, hash->bytes,
                                      expected_r->bytes, expected_s->bytes, &valid)==0), "Verify", errout);

    ok_or_goto(valid==true, "Stock signature verification", errout);

    if (k->len && priv_key->len) {
        // Set RNG to control k
        ccrng_ecfips_test_init(&rng, k->len, k->bytes);
        ok_or_goto((ccec_sign_composite(key, di->output_size, hash->bytes,
                                       computed_r->bytes, computed_s->bytes, (struct ccrng_state *)&rng)==0), "Sign", errout);

        ok_or_goto((ccec_verify_composite(pkey, di->output_size, hash->bytes,
                                          computed_r->bytes, computed_s->bytes, &valid)==0), "Verify", errout);

        ok_or_goto(valid==true, "Generated signature verification", errout);

        // Checks
        //cc_print("r: ",expected_r->len, computed_r->bytes);
        //cc_print("s: ",expected_s->len, computed_s->bytes);
        ok_or_goto(memcmp(computed_r->bytes,expected_r->bytes,expected_r->len)==0, "signature r", errout);
        ok_or_goto(memcmp(computed_s->bytes,expected_s->bytes,expected_s->len)==0, "signature s", errout);
    }
    status = 1; // success
errout:
    free(computed_r);
    free(computed_s);
    free(hash);
    free(expected_r);
    free(expected_s);
    free(priv_key);
    free(k);
    free(x);
    free(y);
    return status;
}

// Process one vector
static int ccecdsa_negative_vector(const struct ccecdsa_vector *test)
{
    int status = 0; // fail
    byteBuffer expected_r = hexStringToBytes(test->r);
    byteBuffer expected_s = hexStringToBytes(test->s);
    byteBuffer x = hexStringToBytes(test->qx);
    byteBuffer y = hexStringToBytes(test->qy);
    byteBuffer priv_key = hexStringToBytes(test->priv_key);
    byteBuffer k = hexStringToBytes(test->k);
    struct ccrng_ecfips_test_state rng;
    ccec_const_cp_t cp=test->curve();
    const struct ccdigest_info *di=test->di;
    ccec_full_ctx_decl_cp(cp, key);  
    bool valid;
    ccec_pub_ctx_t pkey= ccec_ctx_pub(key);

    if (priv_key->len) {
        // Generate "remote" public key from private key
        ok_or_fail((ccec_recover_full_key(cp,priv_key->len, priv_key->bytes, key) == 0), "Generated Full Key");
    } else {
        ok_or_fail((ccec_make_pub(ccec_cp_prime_bitlen(cp), x->len, x->bytes,
                                  y->len, y->bytes, pkey)==0), "Generated Pub Key");
    }

    // Buffer for outputs
    byteBuffer computed_r = mallocByteBuffer(ccec_signature_r_s_size(pkey));
    byteBuffer computed_s = mallocByteBuffer(ccec_signature_r_s_size(pkey));
    byteBuffer hash = mallocByteBuffer(di->output_size);

    if(test->hex_msg == 1){
        byteBuffer m = hexStringToBytes(test->msg);
        ccdigest(di, m->len, m->bytes, hash->bytes);
        free(m);
    }else{
        ccdigest(di, strlen(test->msg), test->msg, hash->bytes);
    }

    //==============================================
    // Negative testing of verify
    //==============================================

    // Good verify
    ok_or_goto((ccec_verify_composite(pkey, di->output_size, hash->bytes,
                                      expected_r->bytes, expected_s->bytes, &valid)==0), "Verify", errout);
    ok_or_goto(valid==true, "Good signature", errout);

    // r is corrupted
    expected_r->bytes[0]^=1;
    ok_or_goto((ccec_verify_composite(pkey, di->output_size, hash->bytes,
                                      expected_r->bytes, expected_s->bytes, &valid)==0), "Verify: r corrupted", errout);
    ok_or_goto(valid==false, "r corrupted", errout);
    expected_r->bytes[0]^=1;

    // s is corrupted
    expected_s->bytes[0]^=1;
    ok_or_goto((ccec_verify_composite(pkey, di->output_size, hash->bytes,
                                      expected_r->bytes, expected_s->bytes, &valid)==0), "Verify: s corrupted", errout);
    ok_or_goto(valid==false, "s corrupted", errout);
    expected_s->bytes[0]^=1;

    if (k->len && priv_key->len) {
        //==============================================
        // Negative testing of signature
        //==============================================
        // Set RNG to control k
        ccrng_ecfips_test_init(&rng, k->len, k->bytes);
        ok_or_goto((ccec_sign_composite(key, di->output_size, hash->bytes,
                                        computed_r->bytes, computed_s->bytes, (struct ccrng_state *)&rng)==0), "Sign", errout);

        // Checks
        ok_or_goto(memcmp(computed_r->bytes,expected_r->bytes,expected_r->len)==0, "signature r", errout);
        ok_or_goto(memcmp(computed_s->bytes,expected_s->bytes,expected_s->len)==0, "signature s", errout);

        // RNG error
        ccrng_ecfips_test_init(&rng, 0, k->bytes);
        ok_or_goto((ccec_sign_composite(key, di->output_size, hash->bytes,
                                        computed_r->bytes, computed_s->bytes, (struct ccrng_state *)&rng)!=0), "Sign: rng", errout);

        // Private scalar is zero
        ccrng_ecfips_test_init(&rng, k->len, k->bytes);
        ccn_zero(ccec_cp_n(cp),ccec_ctx_k(key));
        ok_or_goto((ccec_sign_composite(key, di->output_size, hash->bytes,
                                        computed_r->bytes, computed_s->bytes, (struct ccrng_state *)&rng)!=0), "Private scalar is zero", errout);

        // Private scalar is the order
        ccrng_ecfips_test_init(&rng, k->len, k->bytes);
        ccn_set(ccec_cp_n(cp),ccec_ctx_k(key),cczp_prime(ccec_cp_zq(cp)));
        ok_or_goto((ccec_sign_composite(key, di->output_size, hash->bytes,
                                        computed_r->bytes, computed_s->bytes, (struct ccrng_state *)&rng)!=0), "Private scalar is too big", errout);
    }


    status = 1; // success
errout:
    free(computed_r);
    free(computed_s);
    free(hash);
    free(expected_r);
    free(expected_s);
    free(priv_key);
    free(k);
    free(x);
    free(y);
    return status;
}


int
ecdsa_known_answer_tests(void)
{
    size_t test_counter=0;
    int test_status=1;
    const struct ccecdsa_vector * current_test=&ccecdsa_vectors[test_counter++];
    while (current_test->di!=NULL)
    {
        test_status=ccecdsa_kat_vector(current_test);
        current_test=&ccecdsa_vectors[test_counter++];
    }
    return test_status;
}

int
ecdsa_negative_tests(void)
{
    size_t test_counter=0;
    int test_status=1;
    const struct ccecdsa_vector * current_test=&ccecdsa_vectors[test_counter++];
    while (current_test->di!=NULL)
    {
        test_status=ccecdsa_negative_vector(current_test);
        current_test=&ccecdsa_vectors[test_counter++];
    }
    return test_status;
}


/* Copyright (c) (2016-2019,2021) Apple Inc. All rights reserved.
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

#include <corecrypto/ccec.h>
#include <corecrypto/ccec_priv.h>
#include "ccec_internal.h"
#include <corecrypto/ccrng_test.h>
#include "crypto_test_ec.h"


static int verbose = 0;

const struct ccecdh_vector ccecdh_vectors[]=
{
#include "../test_vectors/ecdh.inc"
};

static int
ECDH_KATTesting(const struct ccecdh_vector *testvec) {
    int status;
    int rc=1;

    ccec_const_cp_t cp = testvec->curve();
    size_t keySize=ccec_cp_prime_bitlen(cp);
    ccec_full_ctx_decl_cp(cp, full_ec_key);
    ccec_pub_ctx_decl_cp(cp, pub_ec_key);

    byteBuffer QCAVSx = hexStringToBytes(testvec->QCAVSx);
    byteBuffer QCAVSy = hexStringToBytes(testvec->QCAVSy);
    byteBuffer dIUT   = hexStringToBytes(testvec->dIUT);
    byteBuffer QIUTx  = hexStringToBytes(testvec->QIUTx);
    byteBuffer QIUTy  = hexStringToBytes(testvec->QIUTy);
    byteBuffer ZIUT   = hexStringToBytes(testvec->ZIUT);
    int expected_status=testvec->status;

    uint8_t Z[ZIUT->len];
    size_t Z_len=sizeof(Z);
    memset(Z,0,sizeof(Z));

    is(ccec_make_priv(keySize,
                      QIUTx->len, QIUTx->bytes,
                      QIUTy->len, QIUTy->bytes,
                      dIUT->len,  dIUT->bytes,
                      full_ec_key),0,"Make priv");
    is(ccec_make_pub(keySize,
                     QCAVSx->len, QCAVSx->bytes,
                     QCAVSy->len, QCAVSy->bytes,
                     pub_ec_key),0,"Make pub");

    status=ccecdh_compute_shared_secret(full_ec_key, pub_ec_key, &Z_len, Z, global_test_rng);
    rc&=is(status,expected_status, "Return value as expected");
    if (expected_status==0) {
        rc&=is(Z_len,ZIUT->len,"Z length");
        rc&=ok_memcmp(Z, ZIUT->bytes, ZIUT->len, "Known answer test failure");
    } else {
        pass("ECDH"); // for the test counter
        pass("ECDH"); // for the test counter
    }
    free(QCAVSx);
    free(QCAVSy);
    free(dIUT);
    free(QIUTx);
    free(QIUTy);
    free(ZIUT);
    return rc;
}


static int
ECDH_negativeTesting(ccec_const_cp_t cp)
{
    size_t n=ccec_cp_n(cp);
    ccec_full_ctx_decl_cp(cp, full_key); ccec_ctx_init(cp, full_key);
    uint8_t out[ccec_ccn_size(cp)];
    size_t  out_len=sizeof(out);
    uint32_t status=0;
    uint32_t nb_test=0;
    int result=0;
    
    // Set a dummy private key
    ccn_seti(n, ccec_ctx_k(full_key), 2);

    /* 0) Sanity: valid arguments */
    ccn_set(n,ccec_ctx_x(full_key),ccec_const_point_x(ccec_cp_g(cp),cp));
    ccn_set(n,ccec_ctx_y(full_key),ccec_const_point_y(ccec_cp_g(cp),cp));
    ccn_seti(n, ccec_ctx_z(full_key), 1);
    ccec_pub_ctx_t pub_key = ccec_ctx_pub(full_key);

    if (ccec_validate_pub(pub_key) &&
        (ccecdh_compute_shared_secret(full_key,pub_key,&out_len, out,global_test_rng)==0))
    {
        isnt(out_len, 0, "computed_shared_secret_len not be zero");
        status|=1<<nb_test;
    }
    nb_test++;
    
    /* 1) Set x to p */
    ccn_set(n,ccec_ctx_x(full_key),ccec_ctx_prime(full_key));
    ccn_set(n,ccec_ctx_y(full_key),ccec_const_point_y(ccec_cp_g(cp),cp));
    ccn_seti(n, ccec_ctx_z(full_key), 1);
    if (!ccec_validate_pub(pub_key) &&
        (ccecdh_compute_shared_secret(full_key, pub_key,&out_len, out,global_test_rng)!=0))
    {
        is(out_len, 0, "computed_shared_secret_len should've been set to zero");
        status|=1<<nb_test;
    }
    nb_test++;
    
    /* 2) Set y to p */
    out_len = sizeof(out);
    ccn_set(n,ccec_ctx_x(full_key),ccec_const_point_x(ccec_cp_g(cp),cp));
    ccn_set(n,ccec_ctx_y(full_key),ccec_ctx_prime(full_key));
    ccn_seti(n, ccec_ctx_z(full_key), 1);
    if (!ccec_validate_pub(pub_key) &&
         (ccecdh_compute_shared_secret(full_key, pub_key,&out_len, out,global_test_rng)!=0))
    {
        is(out_len, 0, "computed_shared_secret_len should've been set to zero");
        status|=1<<nb_test;
    }
    nb_test++;

    if (ccn_is_zero(n,ccec_cp_b(cp)))
    {   // The point (1,1) can't be on the curve with equation y^2=x^3-3x+0.
        ccn_seti(n,ccec_ctx_x(full_key),1);
        ccn_seti(n,ccec_ctx_y(full_key),1);
    }
    else
    {   // The point (0,0) can't be on the curve with equation y^2=x^3-3x+b with b!=0
        ccn_zero(n,ccec_ctx_x(full_key));
        ccn_zero(n,ccec_ctx_y(full_key));
    }

    out_len = sizeof(out);
    if (!ccec_validate_pub(pub_key) &&
        (ccecdh_compute_shared_secret(full_key, pub_key,&out_len, out,global_test_rng)!=0))
    {
        is(out_len, 0, "computed_shared_secret_len should've been set to zero");
        status|=1<<nb_test;
    }
    nb_test++;

    /* 4) Output is infinite point  */
    out_len = sizeof(out);
    ccn_set(n,ccec_ctx_x(full_key),ccec_const_point_x(ccec_cp_g(cp),cp));
    ccn_set(n,ccec_ctx_y(full_key),ccec_const_point_y(ccec_cp_g(cp),cp));
    ccn_set(n,ccec_ctx_k(full_key),cczp_prime(ccec_cp_zq(cp)));

    if (ccecdh_compute_shared_secret(full_key, pub_key,&out_len, out,global_test_rng)!=0)
    {
        is(out_len, 0, "computed_shared_secret_len should've been set to zero");
        status|=1<<nb_test;
    }
    nb_test++;

    /* 5) Sanity: valid arguments */
    out_len = sizeof(out);
    ccn_seti(n, ccec_ctx_k(full_key), 2);
    ccn_set(n,ccec_ctx_x(full_key),ccec_const_point_x(ccec_cp_g(cp),cp));
    ccn_set(n,ccec_ctx_y(full_key),ccec_const_point_y(ccec_cp_g(cp),cp));
    ccn_seti(n, ccec_ctx_z(full_key), 1);
    if (ccecdh_compute_shared_secret(full_key,pub_key,&out_len, out,global_test_rng)==0)
    {
        isnt(out_len, 0, "computed_shared_secret_len not be zero");
        status|=1<<nb_test;
    }
    nb_test++;

    // 6) Pass a zero-length `out` buffer
    out_len = 0;
    if (ccecdh_compute_shared_secret(full_key, pub_key, &out_len, out, global_test_rng) != 0) {
        is(out_len, 0, "computed_shared_secret_len should remain zero");
        status |= 1 << nb_test;
    }
    nb_test++;

    // 7) Pass a tiny `out` buffer
    out_len = 1;
    if (ccecdh_compute_shared_secret(full_key, pub_key, &out_len, out, global_test_rng) != 0) {
        is(out_len, 0, "computed_shared_secret_len should've been set to zero");
        status |= 1 << nb_test;
    }
    nb_test++;

    // 8) Set a zero scalar key
    out_len = sizeof(out);
    ccn_zero(n, ccec_ctx_k(full_key));
    if (ccecdh_compute_shared_secret(full_key,pub_key,&out_len, out,global_test_rng)!=0)
    {
        is(out_len, 0, "computed_shared_secret_len should've been set to zero");
        status|=1<<nb_test;
    }
    nb_test++;

    // 9) Set a big scalar key
    out_len = sizeof(out);
    ccn_set(ccec_cp_n(cp),ccec_ctx_k(full_key),cczp_prime(ccec_cp_zq(cp)));
    if (ccecdh_compute_shared_secret(full_key,pub_key,&out_len, out,global_test_rng)!=0)
    {
        is(out_len, 0, "computed_shared_secret_len should've been set to zero");
        status|=1<<nb_test;
    }
    nb_test++;

    /* Test aftermath */
    if ((nb_test==0) || (status!=((1<<nb_test)-1)))
    {
        result=0;
    }
    else
    {
        result=1; // Test is successful, Yeah!
    }

    return result;
}

int
ecdh_known_answer_tests(void) {
    int status=1;


    if(verbose) diag("ECDH Known Answer Tests");
    size_t i=0;
    while(ccecdh_vectors[i].curve!=NULL) {
        status&=ok(ECDH_KATTesting(&ccecdh_vectors[i]), "ECDH KAT Test failed: %d",i);
        i++;
    }

    return status;
}

int
ecdh_negative_tests(void) {
    int status=1;

    if(verbose) diag("ECDH Negative Tests");
    status&=ok(ECDH_negativeTesting(ccec_cp_192()), "ECDH Negative testing on 192 bit curve");
    status&=ok(ECDH_negativeTesting(ccec_cp_224()), "ECDH Negative testing on 224 bit curve");
    status&=ok(ECDH_negativeTesting(ccec_cp_256()), "ECDH Negative testing on 256 bit curve");
    status&=ok(ECDH_negativeTesting(ccec_cp_384()), "ECDH Negative testing on 384 bit curve");
    status&=ok(ECDH_negativeTesting(ccec_cp_521()), "ECDH Negative testing on 521 bit curve");

    return status;
}



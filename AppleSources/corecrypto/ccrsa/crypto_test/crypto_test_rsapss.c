/* Copyright (c) (2015-2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "ccrsa_internal.h"
#include "cczp_internal.h"
#include <corecrypto/ccdigest.h>
#include <corecrypto/ccsha1.h>
#include <corecrypto/ccrng_sequence.h>
#include <corecrypto/ccsha2.h>
#include "crypto_test_rsapss.h"
#include "testmore.h"

/*
 http://www.emc.com/emc-plus/rsa-labs/standards-initiatives/pkcs-rsa-cryptography-standard.htm#
 ftp://ftp.rsasecurity.com/pub/pkcs/pkcs-1/pkcs-1v2-1-vec.zip
 the test vectors are from RSA lab (above links)
 A python scrips tranforms  pss-vect.txt to SigPSS.inc
 These test vectors donot check the salt generation function.

 The CAVP test vectors are not particularly useful, because they just check the RSA signing operation and not the PSS padding.
 http://csrc.nist.gov/groups/STM/cavp/documents/components/RSA2SP1VS.pdf

 */

#define TEST_VECT_HASH_LEN 20
#define N_RSA_PARAMS 10
#define N_EXAMPLES 6
struct rsapss_sig_test_t {
    char * modulus; size_t modulus_len;
    char *e; size_t e_len;
    char *d; size_t d_len;
    char *p; size_t p_len;
    char *q; size_t q_len;
    char *dp; size_t dp_len;
    char *dq; size_t dq_len;
    char *qinv; size_t qinv_len;

    struct {
        char * msg; size_t msg_len;
        char *salt; size_t salt_len;
        char *sig; size_t sig_len;
    } example[N_EXAMPLES];

} rsapss_sig_test_vect [N_RSA_PARAMS]= {
    //The initializer file must have exactly 10 set of RSA parameters and 6 example per each RSA parameters.
#include "../test_vectors/pss-vect.inc"
};

//this is for debugging. It is not meant for testing the library
struct rsapss_sig_test_t rsapss_sig_test2 =
{
#include "../test_vectors/pss-int-vect.inc"
};

//this is for debugging. It is not meant for testing the library
struct rsapss_sig_intermediate_t {
    char *mHash; size_t mHash_len;
    char *salt; size_t salt_len;
    char *Mp; size_t Mp_len;
    char *H; size_t H_len;
    char *DB; size_t DB_len;
    char *dbMask; size_t dbMask_len;
    char *maskedDB; size_t maskedDB_len;
    char *EM; size_t EM_len;
} rsapss_sig_int = {
#include "../test_vectors/pss-int.inc"
};

static int read_fullkey(ccrsa_full_ctx_t fk, const struct rsapss_sig_test_t *v)
{
    size_t n = ccrsa_ctx_n(fk);

    ccrsa_pub_ctx_t pubk = ccrsa_ctx_public(fk);
    CCZP_N(ccrsa_ctx_zm(pubk)) = n;

    ccrsa_make_pub(pubk,
                   v->e_len, (const unsigned char *)v->e,
                   v->modulus_len, (const unsigned char *)v->modulus);

    //set the private key
    size_t np, nq;

    CCZP_N(ccrsa_ctx_private_zp(fk)) = np=ccn_nof(v->p_len*8);
    CCZP_N(ccrsa_ctx_private_zq(fk)) = nq=ccn_nof(v->q_len*8);
    ccn_read_uint(np, CCZP_PRIME(ccrsa_ctx_private_zp(fk)), v->p_len, (const unsigned char *)v->p);
    ccn_read_uint(nq, CCZP_PRIME(ccrsa_ctx_private_zq(fk)), v->q_len, (const unsigned char *)v->q);
    ccn_read_uint(np, ccrsa_ctx_private_dp(fk), v->dp_len, (const unsigned char *)v->dp);
    ccn_read_uint(nq, ccrsa_ctx_private_dq(fk), v->dq_len, (const unsigned char *)v->dq);
    ccn_read_uint(np, ccrsa_ctx_private_qinv(fk), v->qinv_len, (const unsigned char *)v->qinv);

    //need to initialize reciprocals of zp and zq
    is(cczp_init(ccrsa_ctx_private_zp(fk)), CCERR_OK, "cczp_init() failed");
    is(cczp_init(ccrsa_ctx_private_zq(fk)), CCERR_OK, "cczp_init() failed");

    return 0;
}

static int test_rsapss_sig(const struct rsapss_sig_test_t *v, size_t nex)
{
    const cc_size n = ccn_nof((cc_size)v->modulus_len*8);
    ccrsa_full_ctx_decl_n(n, fk);
    ccrsa_ctx_n(fk) = n;
    read_fullkey(fk, v);

    const struct ccdigest_info *di = ccsha1_di();
    ok_or_goto(TEST_VECT_HASH_LEN == di->output_size, "RSA-PSS: test vector hash len mismatch\n", fail);

    int rc=0;
    size_t i;
    for(i=0; i<nex; i++){ //round trip signature check
        size_t siglen = v->example[i].sig_len;
        uint8_t sig[siglen];
        unsigned char mHash[di->output_size];
        uint8_t canary_out[sizeof(CCRSA_PSS_FAULT_CANARY)];

        //compute the message hash
        ccdigest(di, v->example[i].msg_len, v->example[i].msg, mHash);

        //set a dummy rng, and pass to signature function for salt generation
        struct ccrng_sequence_state seq_rng;
        ccrng_sequence_init(&seq_rng, v->example[i].salt_len, (uint8_t*)v->example[i].salt);
        struct ccrng_state *rng = (struct ccrng_state *)&seq_rng;
        
        // Sign the digest
        rc = ccrsa_sign_pss(fk, di, di, v->example[i].salt_len, rng, TEST_VECT_HASH_LEN, mHash, &siglen, sig);
        ok(rc==0,  "signing error i=%d", i);
        ok_memcmp(sig, v->example[i].sig, siglen, "wrong signature generated i=%d", i);

        // Verify the signature
        rc=ccrsa_verify_pss_digest(ccrsa_ctx_public(fk),
                                   di, di,
                                   di->output_size, mHash,
                                   siglen, sig,
                                   v->example[i].salt_len, NULL);
        ok(rc == CCERR_VALID_SIGNATURE, "generated signature doesn't verify");
        
        // Sign the message
        rc = ccrsa_sign_pss_msg(fk, di, di, v->example[i].salt_len, rng, v->example[i].msg_len, (uint8_t *)v->example[i].msg, &siglen, sig);
        ok(rc == 0, "ccrsa_sign_pss_msg error i=%d", i);
        ok_memcmp(sig, v->example[i].sig, siglen, "ccrsa_sign_pss_msg wrong signature generated i=%d", i);
        
        // Verify the signature using the ccrsa_verify_pss_digest method
        rc = ccrsa_verify_pss_digest(ccrsa_ctx_public(fk), di, di, di->output_size, mHash, siglen, sig, v->example[i].salt_len, canary_out);
        ok(rc == CCERR_VALID_SIGNATURE, "ccrsa_verify_pss_digest failed");
        ok_memcmp(CCRSA_PSS_FAULT_CANARY, canary_out, sizeof(CCRSA_PSS_FAULT_CANARY), "ccrsa_verify_pss_digest output canary not equal");
        
        // Verify the signature using the ccrsa_verify_pss_msg method
        rc = ccrsa_verify_pss_msg(ccrsa_ctx_public(fk), di, di, v->example[i].msg_len, (uint8_t *) v->example[i].msg, siglen, sig, v->example[i].salt_len, canary_out);
        ok(rc == CCERR_VALID_SIGNATURE, "ccrsa_verify_pss_msg failed");
        ok_memcmp(CCRSA_PSS_FAULT_CANARY, canary_out, sizeof(CCRSA_PSS_FAULT_CANARY), "ccrsa_verify_pss_msg output canary not equal");
    }
    ccrsa_full_ctx_clear_n(n, fk);
    return 0;
fail:
    ccrsa_full_ctx_clear_n(n, fk);
    return -1;

}


static int pss_round_trip(const ccrsa_full_ctx_t fk,
                          const struct ccdigest_info* hashAlgorithm,
                          const struct ccdigest_info* MgfHashAlgorithm,
                          size_t saltLen,struct ccrng_state *rng,
                          size_t hLen, const uint8_t *mHash,
                          size_t *sigLen, uint8_t *sig)
{
    int rc;

    rc = ccrsa_sign_pss_blinded(rng, fk, hashAlgorithm, MgfHashAlgorithm, saltLen, rng, hLen, mHash, sigLen, sig);

    rc|=ccrsa_verify_pss_digest(ccrsa_ctx_public(fk),
                                hashAlgorithm, MgfHashAlgorithm,
                                hLen, mHash,
                                *sigLen, sig,
                                saltLen, NULL);

    return (rc == CCERR_VALID_SIGNATURE) ? 0 : -1;
}


static void flipbit(unsigned char *s, int k)
{
    int k7 = 1<<(k&7);
    int bit= k7 & s[k/8];

    if(!bit)
        s[k/8] |= k7;
    else
        s[k/8] &= ~k7;
}

#define okrc(cond, s, rc) {(rc)|=(cond)?0:-1; ok((cond),(s));}
static int test_rsapss_misc(const struct rsapss_sig_test_t *v)
{
    int rc=0, rc2=0;
    size_t saltLen, hLen, sigLen;
    const struct ccdigest_info *di;

    const cc_size n = ccn_nof((cc_size)v->modulus_len*8);
    ccrsa_full_ctx_decl_n(n, fk);
    ccrsa_ctx_n(fk) = n;
    read_fullkey(fk, v);

    const struct ccdigest_info *di160 = ccsha1_di();
    const struct ccdigest_info *di512 = ccsha512_di();
    struct ccrng_state *rng=global_test_rng;
    uint8_t mHash[di512->output_size]; //big enough for all hashes
    ccdigest(di512, 30, "The quick brown fox jumps over the lazy dog.", mHash); //don't want to use strlen()

    //TEST: saltLen>hLen
    const size_t modBits = ccn_bitlen(ccrsa_ctx_n(fk) , ccrsa_ctx_m(fk) );
    const size_t modBytes = cc_ceiling(modBits, 8);
    uint8_t sig[n*sizeof(cc_unit)];

    //TEST: saltlen>hlen, fails
    di = di160;
    hLen = di->output_size;
    sigLen=modBytes;
    saltLen = hLen+1;
    rc= ccrsa_sign_pss_blinded(rng, fk, di, di512, saltLen, rng, hLen, mHash, &sigLen, sig);
    okrc(rc!=0, "negative test failed:  saltLen>hLen, msg=sha1, MGF=sha512", rc2);

    //TEST: saltLen=0, passes
    di = di160;
    hLen = di->output_size;
    sigLen=modBytes;
    saltLen = 0;
    rc=pss_round_trip(fk,di, di512, saltLen, rng, hLen, mHash, &sigLen, sig);
    okrc(rc==0, "test failed:  saltLen==0", rc2);

    //TEST: saltLen=0 with different hashes, passes
    di = di512;
    hLen = di->output_size;
    sigLen=modBytes;
    saltLen = 0;
    rc=pss_round_trip(fk,di, di160, saltLen, rng, hLen, mHash, &sigLen, sig);
    okrc(rc==0,"\n test failed:  saltLen==0, msg=sha512, MGF=sha1", rc2);

    //TEST:
    //len=emLen-sLen-hLen-2; len==0
    di = di512;
    hLen = di->output_size;
    sigLen=modBytes;
    saltLen = 62;
    rc=pss_round_trip(fk,di, di512, saltLen, rng, hLen, mHash, &sigLen, sig);
    okrc(rc==0, "\n test failed:  len==0", rc2);

    //TEST: flip a random bit in the signature pass, big message hash, small MGF hash, fails
    di = di512;
    hLen = di->output_size;
    sigLen=modBytes;
    saltLen = hLen-3;
    rc=pss_round_trip(fk,di, di160, saltLen, rng, hLen, mHash, &sigLen, sig);
    okrc(rc==0, "pss_round_trip test failed", rc2);
    uint16_t bit_num;
    rc=ccrng_generate(rng, 2,&bit_num);
    okrc(rc==0, "random generation failed", rc2);
    cc_assert(n*sizeof(cc_unit)*8>0x02FF);
    flipbit(sig, bit_num & 0x02FF);
    uint8_t fault_canary[sizeof(CCRSA_PSS_FAULT_CANARY)];
    rc=ccrsa_verify_pss_digest(ccrsa_ctx_public(fk), di, di160, hLen, mHash, sigLen, sig, saltLen, fault_canary);
    okrc(rc!=0, "ccrsa_verify_pss_digest() flipbit negative test failed", rc2);
    isnt(memcmp(fault_canary, CCRSA_PSS_FAULT_CANARY, sizeof(CCRSA_PSS_FAULT_CANARY)), 0, "ccrsa_verify_pss_digest canary incorrect");

    //TEST: rng returns error
    struct ccrng_sequence_state rng_seq;
    ccrng_sequence_init(&rng_seq, 0, NULL); // length=0 => make it generate error
    di = di160;
    hLen = di->output_size;
    sigLen=modBytes;
    saltLen = hLen;
    rc= ccrsa_sign_pss_blinded(global_test_rng,fk, di, di512, saltLen, (struct ccrng_state *)&rng_seq, hLen, mHash, &sigLen, sig);
    okrc(rc!=0, "rng negative test failed", rc2);
    
    ccrsa_full_ctx_clear_n(n, fk);
    return rc2;
}

extern int
test_verify_pkcs1pss_known_answer_test(void);

int test_rsa_pss_known_answer(void)
{
    int i, rc;

    rc = test_verify_pkcs1pss_known_answer_test();
    rc |= test_rsapss_misc(&rsapss_sig_test_vect[1]);
    for(i=0; i<N_RSA_PARAMS; i++) {
        rc |= test_rsapss_sig(&rsapss_sig_test_vect[i], N_EXAMPLES);
    }
    return rc;
}

/* Copyright (c) (2016,2018-2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/ccrsa_priv.h>
#include <corecrypto/ccrsa.h>
#include <corecrypto/ccdigest.h>
#include <corecrypto/ccsha1.h>
#include <corecrypto/ccrng_sequence.h>
#include <corecrypto/ccsha2.h>

#include "testmore.h"

struct ccrsa_verify_vector {
    const struct ccdigest_info *di;
    unsigned long mod_nbytes;
    const void *mod;
    unsigned long exp_nbytes;
    const void *exp;
    const void *digest;         /* length governed by di */
    unsigned long msg_nbytes;
    const void *msg;
    unsigned long sig_nbytes;
    const void *sig;
    unsigned long salt_nbytes;
    const void *salt;
    bool valid; // expected result
};

static int ccrsa_test_verify_pkcs1pss_vector(const struct ccrsa_verify_vector *v)
{
    int rc=CCERR_INTERNAL;
    const struct ccdigest_info *di = v->di;
    const cc_size n = ccn_nof_size(v->mod_nbytes);
    unsigned char H[di->output_size];
    uint8_t canary_out[sizeof(CCRSA_PSS_FAULT_CANARY)];
    const uint8_t *sig = v->sig;
    unsigned long siglen = v->sig_nbytes;
    size_t salt_nbytes;
    ccrsa_pub_ctx_decl(v->mod_nbytes, key);
    ccrsa_ctx_n(key) = n;
    ccrsa_make_pub(key, v->exp_nbytes, v->exp, v->mod_nbytes, v->mod);
    if (v->digest) {
        memcpy(H, v->digest, sizeof(H));
    } else {
        ccdigest(di, v->msg_nbytes, v->msg, H);
    }

    if (v->salt_nbytes==1 && ((const uint8_t*)(v->salt))[0]==0) {
        salt_nbytes=0;
    } else {
        salt_nbytes=v->salt_nbytes;
    }

    rc = ccrsa_verify_pss_digest(key, di, di, di->output_size, H, siglen, sig, salt_nbytes, canary_out);
    if (v->valid && rc != CCERR_VALID_SIGNATURE) {
        return -1;
    } else if (!v->valid && rc == CCERR_VALID_SIGNATURE) {
        return -1;
    }
    if (v->valid && memcmp(CCRSA_PSS_FAULT_CANARY, canary_out, sizeof(CCRSA_PSS_FAULT_CANARY)) != 0) {
        return -1;
    }
    
    rc = ccrsa_verify_pss_msg(key, di, di, v->msg_nbytes, v->msg, siglen, sig, salt_nbytes, canary_out);
    if (v->valid && rc != CCERR_VALID_SIGNATURE) {
        return -1;
    } else if (!v->valid && rc == CCERR_VALID_SIGNATURE) {
        return -1;
    }
    if (v->valid && memcmp(CCRSA_PSS_FAULT_CANARY, canary_out, sizeof(CCRSA_PSS_FAULT_CANARY)) != 0) {
        return -1;
    }
    ccrsa_pub_ctx_clear(v->mod_nbytes, key);
    return 0;
}


/* Nist CAVP vectors specifies the hash as strings - those are matching hashes implementations */
/* We picked the implementations that are on all platform, it does not matter since we are not testing the hash here */
#define SHA1 &ccsha1_eay_di
#define SHA224 &ccsha224_ltc_di
#define SHA256 &ccsha256_ltc_di
#define SHA384 &ccsha384_ltc_di
#define SHA512 &ccsha512_ltc_di

/* Nist CAVP vectors for verify specify the result as F (failed) or P (passed)
 those translate as true or false */

#define P true
#define F false

const struct ccrsa_verify_vector verify_vectors_pkcs1pss[]=
{
#include "../test_vectors/SigVerPSS_186-3.inc"
};

extern int
test_verify_pkcs1pss_known_answer_test(void);

int
test_verify_pkcs1pss_known_answer_test(void)
{
    size_t i;
    uint32_t nb_test_passed,nb_test;
    nb_test_passed=0;
    nb_test=0;
    // Run only tests for supported hash algorithms
    for(i = 0; i < CC_ARRAY_LEN(verify_vectors_pkcs1pss); i++)
    {
        if (verify_vectors_pkcs1pss[i].di!=NULL)
        {
            // 1 bit is set to one when the test passed
            nb_test++;
            if (ccrsa_test_verify_pkcs1pss_vector(&verify_vectors_pkcs1pss[i]) == 0)
            {
                nb_test_passed+=1;
            }
        }
    }

    if ((nb_test_passed==nb_test) && (nb_test>0))
    {
        return 0;
    }
    return -1;
}

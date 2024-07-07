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
#include "crypto_test_rsapkcs1v15.h"
#include "testmore.h"

struct ccrsa_verify_vector {
    const struct ccdigest_info *di;
    unsigned long modlen; // in bits
    const void *mod;
    cc_unit exp;
    const void *digest;   /* length governed by di */
    unsigned long msglen; // in bytes
    const void *msg;
    unsigned long siglen; // in bytes - should be modlen/8
    const void *sig;
    bool valid; // expected result
};

static int ccrsa_test_verify_pkcs1v15_vector(const struct ccrsa_verify_vector *v)
{
    bool ok;
    int rc;
    const struct ccdigest_info *di = v->di;
    const cc_size n = ccn_nof(v->modlen);
    const size_t s = ccn_sizeof(v->modlen);
    unsigned char H[di->output_size];
    const uint8_t *sig = v->sig;
    unsigned long siglen = v->siglen;
    
    uint8_t canary_out[sizeof(CCRSA_PKCS1_FAULT_CANARY)];

    cc_unit exponent[n];
    cc_unit modulus[n];
    ccrsa_pub_ctx_decl(v->modlen, key);
    ccrsa_ctx_n(key) = n;
    ccn_seti(n, exponent, v->exp);
    ccn_read_uint(n, modulus, s, v->mod);

    ccrsa_init_pub(key, modulus, exponent);
    if (v->digest) {
        memcpy(H, v->digest, sizeof(H));
    } else {
        ccdigest(di, v->msglen, v->msg, H);
    }

    ok = !v->valid;
    rc = ccrsa_verify_pkcs1v15(key, di->oid, di->output_size, H, siglen, sig, &ok);
    if (rc || (ok != v->valid)) {
        return -1;
    }
    
    rc = ccrsa_verify_pkcs1v15_digest(key, di->oid, di->output_size, H, siglen, sig, canary_out);
    if ((v->valid && rc != CCERR_VALID_SIGNATURE) || (!v->valid && rc == CCERR_VALID_SIGNATURE)) {
        return -1;
    }
    if (v->valid && memcmp(canary_out, CCRSA_PKCS1_FAULT_CANARY, sizeof(CCRSA_PKCS1_FAULT_CANARY)) != 0) {
        return -1;
    }
    
    if (!v->digest) {
        rc = ccrsa_verify_pkcs1v15_msg(key, di, v->msglen, v->msg, siglen, sig, canary_out);
        if ((v->valid && rc != CCERR_VALID_SIGNATURE) || (!v->valid && rc == CCERR_VALID_SIGNATURE)) {
            return -1;
        }
        if (v->valid && memcmp(canary_out, CCRSA_PKCS1_FAULT_CANARY, sizeof(CCRSA_PKCS1_FAULT_CANARY)) != 0) {
            return -1;
        }
    }

    while (siglen > 0 && sig[0] == 0) {
        sig += 1;
        siglen -= 1;

        ok = true;
        rc = ccrsa_verify_pkcs1v15(key, di->oid, di->output_size, H, siglen, sig, &ok);
        if (!rc || ok) {
            return -1;
        }

        ok = !v->valid;
        rc = ccrsa_verify_pkcs1v15_allowshortsigs(key, di->oid, di->output_size, H, siglen, sig, &ok);
        if (rc || (ok != v->valid)) {
            return -1;
        }
    }
    ccrsa_pub_ctx_clear(v->modlen, key);
    return 0;
}

/* Nist CAVP vectors specifies the hash as strings - those are matching hashes implementations */
/* We picked the implementations that are on all platform, it does not matter since we are not testing the hash here */
#define di_SHA1 &ccsha1_eay_di
#define di_SHA224 &ccsha224_ltc_di
#define di_SHA256 &ccsha256_ltc_di
#define di_SHA384 &ccsha384_ltc_di
#define di_SHA512 &ccsha512_ltc_di

/* Nist CAVP vectors for verify specify the result as F (failed) or P (passed)
 those translate as true or false */

#define P true
#define F false

const struct ccrsa_verify_vector verify_vectors_pkcs1v15[] = {
#include "../test_vectors/SigVer15.inc"
};

int test_verify_pkcs1v15_known_answer_test(void)
{
    uint32_t i;
    uint32_t nb_test_passed, nb_test;
    nb_test_passed = 0;
    nb_test = 0;
    // Run only tests for supported hash algorithms
    for (i = 0; i < CC_ARRAY_LEN(verify_vectors_pkcs1v15); i++) {
        if (verify_vectors_pkcs1v15[i].di != NULL) {
            // 1 bit is set to one when the test passed
            nb_test++;
            if (ccrsa_test_verify_pkcs1v15_vector(&verify_vectors_pkcs1v15[i]) == 0) {
                nb_test_passed += 1;
            }
        }
    }

    if ((nb_test_passed == nb_test) && (nb_test > 0)) {
        return 0;
    }
    return -1;
}

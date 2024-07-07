/* Copyright (c) (2010-2012,2014-2016,2018,2019,2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CRYPTO_TEST_EC_INTERNAL_H_
#define _CORECRYPTO_CRYPTO_TEST_EC_INTERNAL_H_

#include "cc_debug.h"
#include "testbyteBuffer.h"
#include "ccec_internal.h"
#include <corecrypto/ccrng.h>
#include <corecrypto/ccec.h>
#include <corecrypto/ccec_priv.h>
#include <corecrypto/ccrng.h>
#include <corecrypto/ccrng_ecfips_test.h>
#include "cc_macros.h"

struct ccecdsa_vector {
    const struct ccdigest_info *di;	// digest
    ccec_const_cp_t (*curve)(void); // curve
    const char *priv_key; // private key
    const char *qx;       // public key
    const char *qy;       // public key
    int        hex_msg;    // ==1 if the message a hex string and need to be treated as hex rather than a string 
    const char *msg;	  // message for signature
    const char *k;		  // random used in ECDSA
    const char *r;		  // Signature r
    const char *s;		  // Signature s
};

struct ccecdh_vector {
    ccec_const_cp_t (*curve)(void); // curve
    const char *QCAVSx;     // CAVS public key Q, x coordinate
    const char *QCAVSy;     // CAVS public key Q, y coordinate
    const char *dIUT;		// CAVS private key
    const char *QIUTx;		// IUT public key Q, x coordinate
    const char *QIUTy;		// IUT public key Q, x coordinate
    const char *ZIUT;       // IUT shared secret
    const int status;
};

#define di_SHA1   &ccsha1_eay_di
#define di_SHA224 &ccsha224_ltc_di
#define di_SHA256 &ccsha256_ltc_di
#define di_SHA384 &ccsha384_ltc_di
#define di_SHA512 &ccsha512_ltc_di

byteBuffer
ccec_test_parse_spki(byteBuffer spki, byteBuffer *algorithmOID, byteBuffer *parameters);

int
ecdsa_known_answer_tests(void);

int
ecdsa_negative_tests(void);

int
ecdh_known_answer_tests(void);

int
ecdh_negative_tests(void);

int
ecwrapping_tests(void);

int
eckeygen_tests(void);

int
keyroll_tests(void);

static inline // Get a full key from the raw scalar
int ccec_recover_full_key(ccec_const_cp_t cp,size_t length, uint8_t *data,ccec_full_ctx_t key)
{
    int result=-1;
    struct ccrng_ecfips_test_state rng;

    cc_require(ccrng_ecfips_test_init(&rng, length, data) == 0,errOut);
    cc_require(ccec_generate_key_internal_fips(cp, (struct ccrng_state *)&rng, key) == 0,errOut);

    // No problem
    result=0;
errOut:
    return result;
}

#endif // _CORECRYPTO_CRYPTO_TEST_EC_INTERNAL_H_

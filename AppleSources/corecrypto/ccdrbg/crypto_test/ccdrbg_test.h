/* Copyright (c) (2011,2014-2016,2019,2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CCDRBG_TEST_H_
#define _CORECRYPTO_CCDRBG_TEST_H_

#include <corecrypto/ccdrbg.h>

/* NIST Vector with PredictionResistance = false */
struct ccdrbg_vector {
    size_t entropyLen;
    const void *entropy;
    size_t nonceLen;
    const void *nonce;
    size_t psLen;
    const void *ps; /* Personalization String */
    size_t ai1Len;
    const void *ai1; /* Additional Input */
    size_t entropyReseedLen;
    const void *entropyReseed;
    size_t aiReseedLen;
    const void *aiReseed; /* Additional Input */
    size_t ai2Len;
    const void *ai2; /* Additional Input */
    size_t randomLen;
    const void *random; /* Returned bytes */
};

/* NIST Vector with PredictionResistance = true */
struct ccdrbg_PR_vector {
    size_t entropyLen;
    const void *entropy;
    size_t nonceLen;
    const void *nonce;
    size_t psLen;
    const void *ps; /* Personalization String */
    size_t ai1Len;
    const void *ai1; /* Additional Input 1*/
    size_t entropy1Len;
    const void *entropy1;
    size_t ai2Len;
    const void *ai2; /* Additional Input 2*/
    size_t entropy2Len;
    const void *entropy2;
    size_t randomLen;
    const void *random; /* Returned bytes */
};

int ccdrbg_limits_test(void);

int ccdrbg_tests_hmac(void);

int ccdrbg_tests_ctr(void);

int ccdrbg_nist_14_3_test_vector(const struct ccdrbg_info *info, const struct ccdrbg_vector *v, unsigned char *bytes);
int ccdrbg_nist_test_vector(const struct ccdrbg_info *drbg, const struct ccdrbg_vector *v, unsigned char *temp);
int ccdrbg_nist_PR_test_vector(const struct ccdrbg_info *drbg, const struct ccdrbg_PR_vector *v, unsigned char *temp);

#endif /* _CORECRYPTO_CCDRBG_TEST_H_ */

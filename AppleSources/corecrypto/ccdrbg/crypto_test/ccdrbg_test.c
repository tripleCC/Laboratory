/* Copyright (c) (2011,2012,2014-2016,2019,2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/ccdrbg.h>
#include "ccdrbg_test.h"

/* Test with no prediction resistance, new style vectors to init, reseed, gen gen instead of init gen, reseed, gen. 
   This function is for CAVS 14.3 version files. */
int ccdrbg_nist_14_3_test_vector(const struct ccdrbg_info *info, const struct ccdrbg_vector *v, unsigned char *bytes)
{
    uint8_t state[info->size];
    struct ccdrbg_state *rng=(struct ccdrbg_state *)state;

    int rc;

    rc=ccdrbg_init(info, rng,
                  v->entropyLen, v->entropy,
                  v->nonceLen, v->nonce,
                  v->psLen, v->ps);
    if(rc) return rc;

    rc = ccdrbg_reseed(info, rng, v->entropyReseedLen, v->entropyReseed, v->aiReseedLen, v->aiReseed);
    if(rc) return rc;

    rc = ccdrbg_generate(info, rng, v->randomLen, bytes, v->ai1Len, v->ai1);
    if(rc) return rc;

    rc = ccdrbg_generate(info, rng, v->randomLen, bytes, v->ai2Len, v->ai2);
    if(rc) return rc;

    ccdrbg_done(info, rng);
    return memcmp(bytes, v->random, v->randomLen);
}

/* Test with no prediction resistance */
int ccdrbg_nist_test_vector(const struct ccdrbg_info *info, const struct ccdrbg_vector *v, unsigned char *bytes)
{
    uint8_t state[info->size];
    struct ccdrbg_state *rng=(struct ccdrbg_state *)state;

    int rc;

    rc=ccdrbg_init(info, rng,
               v->entropyLen, v->entropy,
                  v->nonceLen, v->nonce,
                  v->psLen, v->ps);
    if(rc) return rc;

    rc = ccdrbg_generate(info, rng, v->randomLen, bytes, v->ai1Len, v->ai1);
    if(rc) return rc;

    rc = ccdrbg_reseed(info, rng, v->entropyReseedLen, v->entropyReseed, v->aiReseedLen, v->aiReseed);
    if(rc) return rc;

    rc = ccdrbg_generate(info, rng, v->randomLen, bytes, v->ai2Len, v->ai2);
    if(rc) return rc;

    ccdrbg_done(info, rng);
    return memcmp(bytes, v->random, v->randomLen);
}

/* test with Prediction Resistance */
int ccdrbg_nist_PR_test_vector(const struct ccdrbg_info *info, const struct ccdrbg_PR_vector *v, unsigned char *bytes)
{
    uint8_t state[info->size];
    struct ccdrbg_state *rng=(struct ccdrbg_state *)state;
    int rc;

    rc = ccdrbg_init(info,  rng,
                     v->entropyLen,v->entropy,
                     v->nonceLen, v->nonce,
                     v->psLen, v->ps);
    if(rc) return rc;


    rc = ccdrbg_reseed(info, rng, v->entropy1Len, v->entropy1, v->ai1Len, v->ai1);
    if(rc) return rc;

    rc = ccdrbg_generate(info, rng, v->randomLen , bytes, 0, NULL);
    if(rc) return rc;


    rc = ccdrbg_reseed(info, rng, v->entropy2Len, v->entropy2, v->ai2Len, v->ai2);
    if(rc) return rc;

    rc = ccdrbg_generate(info, rng, v->randomLen , bytes, 0, NULL);
    if(rc) return rc;

    ccdrbg_done(info, rng);
    return memcmp(bytes, v->random, v->randomLen);
}




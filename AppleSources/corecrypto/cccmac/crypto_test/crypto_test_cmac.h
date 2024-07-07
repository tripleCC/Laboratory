/* Copyright (c) (2010,2011,2012,2013,2015,2016,2018,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CRYPTO_TEST_CMAC_H_
#define _CORECRYPTO_CRYPTO_TEST_CMAC_H_

#include <corecrypto/ccaes.h>
#include <corecrypto/cccmac.h>

typedef struct test_vector_t {
    int Count;
    int Key_len;
    char *Key;
    char *SubKey1;
    char *SubKey2;
    int Msg_len;
    char *Msg;
    int Mac_len;
    char *Mac;
    int Result;
} test_vector;

int test_legacy_oneshot(const struct ccmode_cbc *cbc, char *mode_name, const test_vector *vector);
int test_legacy_discrete(const struct ccmode_cbc *cbc, char *mode_name, const test_vector *vector);

int test_cmac_answer(char *mode_name, const test_vector *vector, void*answer, char *test_type);
int showBytesAreEqual(byteBuffer bb1, byteBuffer bb2, char *label);

#endif /* _CORECRYPTO_CRYPTO_TEST_CMAC_H_ */

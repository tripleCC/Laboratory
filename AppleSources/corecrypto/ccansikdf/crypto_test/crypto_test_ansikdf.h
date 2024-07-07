/* Copyright (c) (2014,2015,2016,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef corecrypto_crypto_test_ansikdf_h
#define corecrypto_crypto_test_ansikdf_h

#include "cc_debug.h"
#include <corecrypto/ccansikdf.h>

struct ccansi_kdf_vector {
    const struct ccdigest_info *di;
    size_t shared_secret_length;
    size_t SharedInfo_length;
    size_t key_data_length;
    int COUNT;
    const char * Z;
    const char * SharedInfo;
    const char * key_data;
};

#endif

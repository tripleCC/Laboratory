/* Copyright (c) (2015,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _corecrypto_crypto_test_der_
#define _corecrypto_crypto_test_der_

#include <stdbool.h>

typedef struct ccder_sig_strict_t {
    cc_size nbits;
    char *signature;
    bool valid;
    char *r;
    char *s;
} ccder_sig_test_vector;

#endif /* defined(_corecrypto_crypto_test_der_) */

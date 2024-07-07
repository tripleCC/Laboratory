/* Copyright (c) (2014,2015,2016,2017,2018,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef corecrypto_crypto_test_ecies_h
#define corecrypto_crypto_test_ecies_h

#include "cc_debug.h"
#include <corecrypto/ccrng.h>
#include <corecrypto/ccecies.h>

// int ccecies(TM_UNUSED int argc, TM_UNUSED char *const *argv);

struct ccecies_vector {
    const struct ccdigest_info *di;
    ccec_const_cp_t (*curve)(void);
    uint32_t mac_nbytes;
    uint32_t key_nbytes;
    uint32_t options;
    const char *dec_priv_key; // Decryption private key
    const char *eph_priv_key; // Ephemeral private key
    const char *Z;
    const char *message;
    const char *cipher;
    const char *compact_cipher;
    const char *sharedInfo1;
    const char *sharedInfo2;
};

#endif

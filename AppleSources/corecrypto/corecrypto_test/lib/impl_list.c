/* Copyright (c) (2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/ccsha1.h>
#include <corecrypto/ccsha2.h>
#include <corecrypto/ccaes.h>
#include <corecrypto/cc_priv.h>
#include <stdio.h>
#include "testenv.h"

void tests_print_impls(void)
{
    printf("[IMPLS] === corecrypto ===\n");
        
    struct di_name {
        const struct ccdigest_info *di;
        const char *name;
    };
    struct di_name dis[] = {
        {.di = ccsha1_di(), "SHA1"},
        {.di = ccsha256_di(), "SHA256"},
        {.di = ccsha384_di(), "SHA384"},
        {.di = ccsha512_di(), "SHA512"}
    };
    
    for (size_t i = 0; i < CC_ARRAY_LEN(dis); i++) {
        printf("\t%s = %s\n", dis[i].name, cc_impl_name(dis[i].di->impl));
    }
    printf("\n");
    
#define PRINT_AES_MODE(_mode_) \
    const struct ccmode_##_mode_ *_mode_ = ccaes_##_mode_##_encrypt_mode(); \
    printf("\t%s(encrypt) = %s\n", #_mode_, cc_impl_name(_mode_->impl)); \
    _mode_ = ccaes_##_mode_##_decrypt_mode(); \
    printf("\t%s(decrypt) = %s\n\n", #_mode_, cc_impl_name(_mode_->impl)); \

    PRINT_AES_MODE(ecb);
    PRINT_AES_MODE(xts);
}

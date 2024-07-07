/* Copyright (c) (2016,2019-2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

//  Copyright (c) 2016 Apple Inc. All rights reserved.
//
//

#include <corecrypto/ccmode.h>

#include "testmore.h"
#include "crypto_test_modes.h"

int test_xts(const struct ccmode_xts *encrypt_ciphermode, const struct ccmode_xts *decrypt_ciphermode)
{
    int rc;
    uint8_t key[32] = {0};
    uint8_t iv[16] = {0};
    
    ccxts_ctx_decl(encrypt_ciphermode->size, ctx);
    
    rc = ccxts_init(encrypt_ciphermode, ctx, 16, key, key);
    ok_or_fail(rc == CCERR_XTS_KEYS_EQUAL, "XTS 128-bit key encrypt init verify key1 != key2");
    
    rc = ccxts_init(decrypt_ciphermode, ctx, 16, key, key);
    ok_or_fail(rc == CCERR_XTS_KEYS_EQUAL, "XTS 128-bit key decrypt init verify key1 != key2");
    
    rc = ccxts_init(encrypt_ciphermode, ctx, 32, key, key);
    ok_or_fail(rc == CCERR_XTS_KEYS_EQUAL, "XTS 256-bit key encrypt init verify key1 != key2");
    
    rc = ccxts_init(decrypt_ciphermode, ctx, 32, key, key);
    ok_or_fail(rc == CCERR_XTS_KEYS_EQUAL, "XTS 256-bit key decrypt init verify key1 != key2");
    
    rc = ccxts_one_shot(encrypt_ciphermode, 16, key, key, iv, 0, NULL, NULL);
    ok_or_fail(rc == CCERR_XTS_KEYS_EQUAL, "XTS 128-bit key encrypt one-shot verify key1 != key2");
    
    rc = ccxts_one_shot(decrypt_ciphermode, 16, key, key, iv, 0, NULL, NULL);
    ok_or_fail(rc == CCERR_XTS_KEYS_EQUAL, "XTS 128-bit key decrypt one-shot verify key1 != key2");
    
    rc = ccxts_one_shot(encrypt_ciphermode, 32, key, key, iv, 0, NULL, NULL);
    ok_or_fail(rc == CCERR_XTS_KEYS_EQUAL, "XTS 256-bit key encrypt one-shot verify key1 != key2");
    
    rc = ccxts_one_shot(decrypt_ciphermode, 32, key, key, iv, 0, NULL, NULL);
    ok_or_fail(rc == CCERR_XTS_KEYS_EQUAL, "XTS 256-bit key decrypt one-shot verify key1 != key2");
    
    return 1;
}

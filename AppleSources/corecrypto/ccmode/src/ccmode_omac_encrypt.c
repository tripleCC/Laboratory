/* Copyright (c) (2010,2011,2015,2016,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "ccmode_internal.h"

int ccmode_omac_encrypt(ccomac_ctx *key, size_t nblocks,
                        const void *tweak, const void *in, void *out) {
    const struct ccmode_ecb *ecb = CCMODE_OMAC_KEY_ECB(key);
    size_t tweak_len = CCMODE_OMAC_KEY_TWEAK_LEN(key);

    return (nblocks == 0 && ecb == NULL && tweak_len == 5 && tweak == NULL && in && out);
}

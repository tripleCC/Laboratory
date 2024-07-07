/* Copyright (c) (2018,2019,2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */
//  Created on 7/16/18.
//

#ifndef ccaes_ltc_common_h
#define ccaes_ltc_common_h

#include <corecrypto/ccaes.h>

/* The key schedule structs match the format of the VNG key schedule
 * (vng_aes_keysched) so that these modes are compatible with each other.
 * Keys expanded by LTC-ECB should be usable from VNG-GCM, for example. */

typedef struct {
    struct {
        uint32_t ks[60];
        uint32_t rn;
    } enc, dec;
} ltc_rijndael_keysched;

int ccaes_ecb_encrypt_init(const struct ccmode_ecb *ecb CC_UNUSED, ccecb_ctx *key, size_t rawkey_len, const void *rawkey);
int ccaes_ecb_decrypt_init(const struct ccmode_ecb *ecb CC_UNUSED, ccecb_ctx *key, size_t rawkey_len, const void *rawkey);

void ccaes_ecb_encrypt_roundkey(const ccecb_ctx *ctx, unsigned i, void *roundkey);

#endif /* ccaes_ltc_common_h */

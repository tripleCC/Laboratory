/* Copyright (c) (2017,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_FIPSPOST_POST_AES_SKG_H_
#define _CORECRYPTO_FIPSPOST_POST_AES_SKG_H_

int fipspost_post_aes_skg_enc_ecb_128(uint32_t fips_mode);
int fipspost_post_aes_skg_dec_ecb_128(uint32_t fips_mode);
int fipspost_post_aes_skg_enc_cbc_128(uint32_t fips_mode);
int fipspost_post_aes_skg_dec_cbc_128(uint32_t fips_mode);

#endif

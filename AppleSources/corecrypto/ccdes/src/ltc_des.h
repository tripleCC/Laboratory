/* Copyright (c) (2010,2011,2013,2015,2016,2017,2018,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef	_CORECRYPTO_LTC_DES_H_
#define	_CORECRYPTO_LTC_DES_H_
#if defined(__cplusplus)
extern "C"
{
#endif

typedef struct ltc_des_key {
    uint32_t ek[32], dk[32];
} ltc_des_keysched;

typedef struct ltc_des3_key {
    uint32_t ek[3][32], dk[3][32];
} ltc_des3_keysched;


#define EN0 0
#define DE1 1

int ccdes_ltc_setup(const struct ccmode_ecb *ecb, ccecb_ctx *key,
                    size_t rawkey_len, const void *rawkey);
int ccdes3_ltc_setup(const struct ccmode_ecb *ecb, ccecb_ctx *key,
                     size_t rawkey_len, const void *rawkey);
void desfunc(uint32_t *block, const uint32_t *keys);
void desfunc3(uint32_t *block, const uint32_t keys[3][32]);
void deskey(const unsigned char *key, short edf, uint32_t *keyout);

#if defined(__cplusplus)
}
#endif
#endif /* _CORECRYPTO_LTC_DES_H_ */

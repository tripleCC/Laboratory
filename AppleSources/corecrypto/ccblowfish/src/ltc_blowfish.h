/* Copyright (c) (2010,2011,2013,2015,2016,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_LTC_BLOWFISH_H_
#define _CORECRYPTO_LTC_BLOWFISH_H_

#define	LTC_BLOWFISH_SROWS	4
#define	LTC_BLOWFISH_SCOLS	256

#ifndef __GNUC__
#define LTC_F(x) ((S1[cc_byte(x,3)] + S2[cc_byte(x,2)]) ^ S3[cc_byte(x,1)]) \
+ S4[cc_byte(x,0)]
#else
#define LTC_F(x) ((xkey->S[0][cc_byte(x,3)] + xkey->S[1][cc_byte(x,2)]) ^ \
xkey->S[2][cc_byte(x,1)]) + xkey->S[3][cc_byte(x,0)]
#endif


typedef struct ltc_blowfish_key {
	uint32_t S[LTC_BLOWFISH_SROWS][LTC_BLOWFISH_SCOLS];
	uint32_t K[18];
} ltc_blowfish_keysched;

/* encrypt is needed for key schedule... */
int ccblowfish_ltc_ecb_encrypt(const ccecb_ctx *skey, size_t nblocks,
                               const void *in, void *out);

int ccblowfish_ltc_setup(const struct ccmode_ecb *ecb CC_UNUSED, ccecb_ctx *key,
                         size_t rawkey_len, const void *rawkey);

#endif /* _LTC_BLOWFISH_H_ */

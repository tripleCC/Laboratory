/* Copyright (c) (2010,2012,2015,2017,2018,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CCRC2_H_
#define _CORECRYPTO_CCRC2_H_

#include <corecrypto/ccmode.h>

#define CCRC2_BLOCK_SIZE 8

const struct ccmode_ecb *ccrc2_ecb_decrypt_mode(void);
const struct ccmode_ecb *ccrc2_ecb_encrypt_mode(void);

const struct ccmode_cbc *ccrc2_cbc_decrypt_mode(void);
const struct ccmode_cbc *ccrc2_cbc_encrypt_mode(void);

const struct ccmode_cfb *ccrc2_cfb_decrypt_mode(void);
const struct ccmode_cfb *ccrc2_cfb_encrypt_mode(void);

const struct ccmode_cfb8 *ccrc2_cfb8_decrypt_mode(void);
const struct ccmode_cfb8 *ccrc2_cfb8_encrypt_mode(void);

const struct ccmode_ctr *ccrc2_ctr_crypt_mode(void);

const struct ccmode_ofb *ccrc2_ofb_crypt_mode(void);


#endif /* _CORECRYPTO_CCRC2_H_ */

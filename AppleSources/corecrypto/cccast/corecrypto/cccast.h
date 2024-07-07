/* Copyright (c) (2011,2012,2015,2017-2019,2021,2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CCCAST_H_
#define _CORECRYPTO_CCCAST_H_

#include <corecrypto/ccmode.h>

CC_PTRCHECK_CAPABLE_HEADER()

#define CCCAST_BLOCK_SIZE		8			/* block size in bytes */
#define CCCAST_KEY_LENGTH		16			/* MAX key size in bytes */
#define CCCAST_MIN_KEY_LENGTH	5			/* MIN key size in bytes */

const struct ccmode_ecb *cccast_ecb_decrypt_mode(void);
const struct ccmode_ecb *cccast_ecb_encrypt_mode(void);

const struct ccmode_cbc *cccast_cbc_decrypt_mode(void);
const struct ccmode_cbc *cccast_cbc_encrypt_mode(void);

const struct ccmode_cfb *cccast_cfb_decrypt_mode(void);
const struct ccmode_cfb *cccast_cfb_encrypt_mode(void);

const struct ccmode_cfb8 *cccast_cfb8_decrypt_mode(void);
const struct ccmode_cfb8 *cccast_cfb8_encrypt_mode(void);

const struct ccmode_ctr *cccast_ctr_crypt_mode(void);

const struct ccmode_ofb *cccast_ofb_crypt_mode(void);

#endif /* _CORECRYPTO_CCCAST_H_ */

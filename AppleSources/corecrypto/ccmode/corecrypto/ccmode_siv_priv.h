/* Copyright (c) (2015,2017-2019,2021,2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CCMODE_SIV_PRIV_H_
#define _CORECRYPTO_CCMODE_SIV_PRIV_H_

#include <corecrypto/ccmode_siv.h>

/*!
  @function ccmode_factory_siv_encrypt
  @abstract Do not call this function.
*/
void ccmode_factory_siv_encrypt(struct ccmode_siv *siv,
                                const struct ccmode_cbc *cbc,
                                const struct ccmode_ctr *ctr);

/*!
  @function ccmode_factory_siv_decrypt
  @abstract Do not call this function.
 */
void ccmode_factory_siv_decrypt(struct ccmode_siv *siv,
                                const struct ccmode_cbc *cbc,
                                const struct ccmode_ctr *ctr);

#endif /* _CORECRYPTO_CCMODE_SIV_PRIV_H_ */

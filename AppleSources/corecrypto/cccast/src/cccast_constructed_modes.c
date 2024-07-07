/* Copyright (c) (2012,2015,2017-2019,2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/cccast.h>
#include "ccmode_internal.h"

#include "cccast_internal.h"

const struct ccmode_ecb *cccast_ecb_decrypt_mode(void)
{
    return &cccast_eay_ecb_decrypt_mode;
}

const struct ccmode_ecb *cccast_ecb_encrypt_mode(void)
{
    return &cccast_eay_ecb_encrypt_mode;
}



CCMODE_CBC_FACTORY(cast, encrypt)
CCMODE_CBC_FACTORY(cast, decrypt)

CCMODE_CFB_FACTORY(cast, cfb, encrypt)
CCMODE_CFB_FACTORY(cast, cfb, decrypt)

CCMODE_CFB_FACTORY(cast, cfb8, encrypt)
CCMODE_CFB_FACTORY(cast, cfb8, decrypt)

CCMODE_CTR_FACTORY(cast)

CCMODE_OFB_FACTORY(cast)

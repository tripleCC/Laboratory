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

#include <corecrypto/ccblowfish.h>
#include "ccmode_internal.h"

#include "ccblowfish_internal.h"

const struct ccmode_ecb *ccblowfish_ecb_decrypt_mode(void)
{
    return &ccblowfish_ltc_ecb_decrypt_mode;
}

const struct ccmode_ecb *ccblowfish_ecb_encrypt_mode(void)
{
    return &ccblowfish_ltc_ecb_encrypt_mode;
}


CCMODE_CBC_FACTORY(blowfish, encrypt)
CCMODE_CBC_FACTORY(blowfish, decrypt)

CCMODE_CFB_FACTORY(blowfish, cfb, encrypt)
CCMODE_CFB_FACTORY(blowfish, cfb, decrypt)

CCMODE_CFB_FACTORY(blowfish, cfb8, encrypt)
CCMODE_CFB_FACTORY(blowfish, cfb8, decrypt)

CCMODE_CTR_FACTORY(blowfish)

CCMODE_OFB_FACTORY(blowfish)

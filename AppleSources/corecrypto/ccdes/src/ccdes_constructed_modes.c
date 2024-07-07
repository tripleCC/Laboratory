/* Copyright (c) (2012,2015,2018,2019,2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/ccdes.h>
#include "ccmode_internal.h"

CCMODE_CBC_FACTORY(des, encrypt)
CCMODE_CBC_FACTORY(des, decrypt)

CCMODE_CFB_FACTORY(des, cfb, encrypt)
CCMODE_CFB_FACTORY(des, cfb, decrypt)

CCMODE_CFB_FACTORY(des, cfb8, encrypt)
CCMODE_CFB_FACTORY(des, cfb8, decrypt)

CCMODE_CTR_FACTORY(des)

CCMODE_OFB_FACTORY(des)


CCMODE_CBC_FACTORY(des3, encrypt)
CCMODE_CBC_FACTORY(des3, decrypt)

CCMODE_CFB_FACTORY(des3, cfb, encrypt)
CCMODE_CFB_FACTORY(des3, cfb, decrypt)

CCMODE_CFB_FACTORY(des3, cfb8, encrypt)
CCMODE_CFB_FACTORY(des3, cfb8, decrypt)

CCMODE_CTR_FACTORY(des3)

CCMODE_OFB_FACTORY(des3)

/* Copyright (c) (2010,2011,2015,2019) Apple Inc. All rights reserved.
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
#include "ltc_blowfish.h"

const struct ccmode_ecb ccblowfish_ltc_ecb_encrypt_mode = {
    .size = sizeof(ltc_blowfish_keysched),
    .block_size = CCBLOWFISH_BLOCK_SIZE,
    .init = ccblowfish_ltc_setup,
    .ecb = ccblowfish_ltc_ecb_encrypt
};


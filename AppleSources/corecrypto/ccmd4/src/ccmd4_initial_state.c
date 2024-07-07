/* Copyright (c) (2010,2014,2015,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/ccmd4.h>
#include <corecrypto/cc_priv.h>

/* This is common to MD4 and MD5 */

const uint32_t ccmd4_initial_state[4] = {
    0x67452301,
    0xefcdab89,
    0x98badcfe,
    0x10325476,
};

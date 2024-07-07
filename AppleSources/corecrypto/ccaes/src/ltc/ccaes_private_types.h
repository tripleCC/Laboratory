/* Copyright (c) (2012,2015,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CCAES_PRIVATE_TYPES_H_
#define _CORECRYPTO_CCAES_PRIVATE_TYPES_H_

#include <corecrypto/ccaes.h>
#include <corecrypto/cc_priv.h>

typedef struct ltc_rijndael_key 
{
    uint32_t eK[60], dK[60];
    int Nr;
} ltc_rijndael_keysched;


#endif // _CORECRYPTO_CCAES_PRIVATE_TYPES_H_

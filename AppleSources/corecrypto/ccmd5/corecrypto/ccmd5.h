/* Copyright (c) (2010,2011,2012,2015,2017,2018,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CCMD5_H_
#define _CORECRYPTO_CCMD5_H_

#include <corecrypto/ccdigest.h>

#define CCMD5_BLOCK_SIZE   64
#define CCMD5_OUTPUT_SIZE  16
#define CCMD5_STATE_SIZE   16

/* Selector */
const struct ccdigest_info *ccmd5_di(void);

/* Implementations */
extern const struct ccdigest_info ccmd5_ltc_di;

#endif /* _CORECRYPTO_CCMD5_H_ */

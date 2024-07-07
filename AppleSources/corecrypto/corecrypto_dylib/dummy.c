/* Copyright (c) (2012,2015,2016,2017,2018,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/cc_config.h>

// Xcode requires a global symbol
volatile int cc_dummy;

#if CORECRYPTO_DEBUG

#if defined(__has_include)     /* portability */
#if __has_include(<AvailabilityInternal.h>)
#include <AvailabilityInternal.h>
#endif /* __has_include(<AvailabilityInternal.h>) */
#endif /* defined(__has_include) */

#endif /* CORECRYPTO_DEBUG */


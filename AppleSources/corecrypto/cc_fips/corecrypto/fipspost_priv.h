/* Copyright (c) (2017,2019,2021,2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_FIPSPOST_PRIV_H_
#define _CORECRYPTO_FIPSPOST_PRIV_H_

#include "cc_absolute_time.h"

#if CC_KERNEL

 #include <pexpert/pexpert.h>
 #define PRINTF kprintf
 #define FIPSPOST_TAG "FIPSPOST_KEXT"

#else

 #include <stdio.h>
 #define PRINTF printf

 #if CC_USE_L4
  #define FIPSPOST_TAG "FIPSPOST_L4  "
 #else
  #define FIPSPOST_TAG "FIPSPOST_USER"
 #endif

#endif

#define debugf(fmt, args...) do {                           \
    PRINTF(FIPSPOST_TAG " [%llu] %s:%d: " fmt "\n",         \
           (unsigned long long int)cc_absolute_time(),      \
           __FUNCTION__ , __LINE__, ##args);                \
} while (0);

#define bufferf(b, l, fmt, args...) do {                      \
    const uint8_t *_bptr = (const uint8_t *)b;                \
    PRINTF(FIPSPOST_TAG " [%llu] %s:%d: " fmt ": ",           \
            (unsigned long long int)cc_absolute_time(),       \
            __FUNCTION__, __LINE__, ##args);                  \
    for (int i = 0; i < l; i++) { PRINTF("%02X", _bptr[i]); } \
    PRINTF("\n");                                             \
} while (0);

#define failf(fmt, args...)                                 \
    PRINTF(FIPSPOST_TAG " [%llu] %s:%d: FAILED: " fmt "\n", \
            (unsigned long long int)cc_absolute_time(),     \
            __FUNCTION__, __LINE__, ##args);                \

#define post_assert(TEST) do {                                              \
    if (!(TEST)) {                                                          \
        failf("%s", #TEST);                                                 \
        return CCPOST_LIBRARY_ERROR;                                        \
    }                                                                       \
} while (0);

/*
 * If the FIPS_MODE_FLAG_FORCEFAIL flag is on, offset the expected result by one byte to
 * guarantee failure.
 */
#define POST_FIPS_RESULT_STR(X) (unsigned char *)(FIPS_MODE_IS_FORCEFAIL(fips_mode) ? "\x01" X : X)

#endif

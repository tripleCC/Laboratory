/* Copyright (c) (2014,2015,2016,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */


#include "ccconstanttime.h"

int compare_timing(const void *a, const void *b) {
    uint64_t x = *((const uint64_t*)a);
    uint64_t y = *((const uint64_t*)b);
    return x < y ? -1 : x == y ? 0 : 1;
}


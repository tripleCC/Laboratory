/* Copyright (c) (2014-2017,2019,2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef corecrypto_cccycles_h
#define corecrypto_cccycles_h

#include <corecrypto/cc.h>
#include "testmore.h"

#include "cctime.h"

#define perf_cycle_start(errOut)                \
    int _perf_error=0;                          \
    perf_start();                               \
    if (_perf_error) goto errOut

#define perf_cycle(errOut)                      \
    perf_time_raw();                            \
    if (_perf_error) goto errOut

#endif

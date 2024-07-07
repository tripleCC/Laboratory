/* Copyright (c) (2014-2016,2019-2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef corecrypto_cctime_h
#define corecrypto_cctime_h

#include "cc_absolute_time.h"

#define perf_start() uint64_t _perf_time = cc_absolute_time()

#define perf_time_raw() ((cc_absolute_time() - _perf_time))
#define perf_seconds() (cc_absolute_time_to_sec((double)perf_time_raw()))

#endif

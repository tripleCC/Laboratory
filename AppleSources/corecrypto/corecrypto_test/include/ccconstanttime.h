/* Copyright (c) (2014-2016,2018,2019,2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef __corecrypto__cc_constanttime__
#define __corecrypto__cc_constanttime__

#include "cc_absolute_time.h"
int compare_timing(const void *a, const void *b);

#define TIMING_WITH_QUANTILE(_R, _repeat_number, _quantile, _function, errOut) {   \
    uint64_t _timing_sample[_repeat_number];  \
    /* Get <repeat_number> timing samples */  \
    for (size_t l=0;l<(_repeat_number);l++) {  \
        perf_cycle_start(errOut);            \
        _function;                           \
        _timing_sample[l]=perf_cycle(errOut);      \
    /* Discard measurement if 0 */  \
        if (_timing_sample[l]==0) l--;       \
    }                                       \
    /* Sort the samples */                    \
    qsort(_timing_sample, _repeat_number, sizeof(_timing_sample[0]), compare_timing); \
    /* Return quantile */ \
    _R = (_timing_sample[((_repeat_number)*(_quantile))/100]); \
}

#endif /* defined(__corecrypto__cc_constanttime__) */

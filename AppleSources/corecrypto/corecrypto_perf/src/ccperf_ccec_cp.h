/* Copyright (c) (2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_PERF_CCEC_CP_H_
#define _CORECRYPTO_PERF_CCEC_CP_H_

/* Copyright (c) (2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/cczp.h>
#include <corecrypto/ccec.h>

static ccec_const_cp_t ccec_cp(size_t nbits)
{
    switch (nbits) {
    case (192):
        return ccec_cp_192();
    case (224):
        return ccec_cp_224();
    case (256):
        return ccec_cp_256();
    case (384):
        return ccec_cp_384();
    case (521): /* -- 544 = 521 rounded up to the nearest multiple of 32*/
        return ccec_cp_521();
    default:
        return (ccec_const_cp_t)(const struct cczp *)0;
    }
}

#endif /* _CORECRYPTO_PERF_CCEC_CP_H_ */

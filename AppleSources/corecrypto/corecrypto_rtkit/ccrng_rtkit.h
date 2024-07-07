/* Copyright (c) (2018,2019,2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef __CCRNG_RTKIT_H__
#define __CCRNG_RTKIT_H__
__BEGIN_DECLS

#include <corecrypto/ccrng.h>
#include <RTK_types.h>

struct ccrng_rtkit_state {
    CCRNG_STATE_COMMON
    RTK_dev_handle handle;
};

int ccrng_rtkit_init(struct ccrng_rtkit_state *rng);

__END_DECLS
#endif

/* Copyright (c) (2010-2012,2015,2016,2019,2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "cc_macros.h"
#include "ccmode_internal.h"

int ccmode_xts_init(const struct ccmode_xts *mode, ccxts_ctx *ctx,
                    size_t key_nbytes, const void *data_key,
                    const void *tweak_key) {
    int rc = CCERR_XTS_KEYS_EQUAL;

    if (cc_cmp_safe(key_nbytes, data_key, tweak_key) != 0) {
        rc = CCERR_OK;
    }

    mode->key_sched(mode, ctx, key_nbytes, data_key, tweak_key);
    return rc;
}

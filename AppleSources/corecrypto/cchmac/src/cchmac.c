/* Copyright (c) (2010-2012,2015-2017,2019,2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "cc_internal.h"
#include <corecrypto/cchmac.h>

#include "fipspost_trace.h"

void cchmac(const struct ccdigest_info *di,
            size_t key_len, const void *key,
            size_t data_len, const void *data, unsigned char *mac) {
    CC_ENSURE_DIT_ENABLED

    FIPSPOST_TRACE_EVENT;

    cchmac_di_decl(di, hc);
    cchmac_init(di, hc, key_len, key);
    cchmac_update(di, hc, data_len, data);
    cchmac_final(di, hc, mac);
	cchmac_di_clear(di, hc);
}

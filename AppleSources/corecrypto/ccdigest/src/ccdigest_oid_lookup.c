/* Copyright (c) (2012,2015,2016,2019,2021,2022) Apple Inc. All rights reserved.
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
#include <corecrypto/cc_config.h>
#include "ccdigest_internal.h"
#include <corecrypto/ccasn1.h>

const struct ccdigest_info *ccdigest_oid_lookup(ccoid_t oid, ...)
{
    CC_ENSURE_DIT_ENABLED

    const struct ccdigest_info *di = NULL;
	va_list argp;
	va_start(argp, oid);
    while((di = va_arg(argp, const struct ccdigest_info *)) != NULL) {
        if(ccdigest_oid_equal(di, oid)) break;
    }
	va_end(argp);
    return di;
}

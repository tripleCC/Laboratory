/* Copyright (c) (2012,2015,2017,2019,2021,2022) Apple Inc. All rights reserved.
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
#include "ccn_internal.h"
#include <corecrypto/ccz_priv.h>

void ccz_muli(ccz *r, const ccz *s, uint32_t v)
{
    CC_ENSURE_DIT_ENABLED

    cc_unit td[ccn_nof_sizeof(v)] = { ccn32_v(v) };
    struct ccz ts = { .u = td, .n = ccn_n(ccn_nof_sizeof(v), td), .sac = ccn_nof_sizeof(v), .isa = NULL };
    ccz_mul(r, s, &ts);
}

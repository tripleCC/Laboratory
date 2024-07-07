/* Copyright (c) (2010,2011,2015,2016,2018,2019,2021,2022) Apple Inc. All rights reserved.
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

int ccn_cmpn(cc_size ns, const cc_unit *s, cc_size nt, const cc_unit *t)
{
    CC_ENSURE_DIT_ENABLED

    cc_size nm = CC_MIN(ns, nt);
    int rv = ccn_cmp(nm, s, t);
    int urv = 1;

    // Pick the bigger number.
    if (ns < nt) {
        ns = nt;
        s = t;
        urv = -urv;
    }

    // If the upper part is all zeros, return the ccn_cmp() result.
    if (ccn_is_zero(ns - nm, s + nm)) {
        return rv;
    }

    return urv;
}

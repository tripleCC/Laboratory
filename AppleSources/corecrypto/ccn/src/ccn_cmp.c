/* Copyright (c) (2010,2015,2016,2019,2021,2022) Apple Inc. All rights reserved.
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
#include <corecrypto/ccn.h>
#include <corecrypto/cc_priv.h>
#include "cc_unit_internal.h"

#if CCN_CMP_ASM
int ccn_cmp_asm(cc_size n, const cc_unit *s, const cc_unit *t) __asm__("_ccn_cmp_asm");
#endif

// constant time comparison when assembly is not available
int ccn_cmp(cc_size n, const cc_unit *s, const cc_unit *t)
{
    CC_ENSURE_DIT_ENABLED

#if CCN_CMP_ASM
    return ccn_cmp_asm(n, s, t);
#else

    cc_unit six=0,tix=0;
    cc_unit sel;

    for (cc_size ix=0;ix<n;ix++) {
        sel = cc_unit_eq(s[ix], t[ix]); // ~0 iff (s[ix] == t[ix]), 0 otherwise
        six = cc_unit_sel(sel, six, s[ix]); // Keep the values of the most significant difference
        tix = cc_unit_sel(sel, tix, t[ix]);
    }

    // compute the difference
    int d1 = cc_unit_neq(six, tix)&1; // 0 if (=), 1 otherwise
    int d2 = cc_unit_lt(six, tix)&2;  // 2 if (-), 0 otherwise

    return d1-d2;
#endif /* CCN_CMP_ASM */
}

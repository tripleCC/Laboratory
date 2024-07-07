/* Copyright (c) (2016-2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/cc_priv.h>
#include "ccn_internal.h"

// r = |s-t|
// Returns 1 when t>s, or 0 when t<=s
cc_unit ccn_abs(cc_size n, cc_unit *r, const cc_unit *s, const cc_unit *t)
{
    cc_unit c = ccn_sub_ws(NULL, n, r, s, t);
    ccn_cond_neg(n, c, r, r);
    return c;
}

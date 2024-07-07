/* Copyright (c) (2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "ccn_internal.h"

cc_unit ccn_subn(cc_size n, cc_unit *r, const cc_unit *s, cc_size nt, const cc_unit *t)
{
    cc_assert(n >= nt);
    return ccn_sub1(n - nt, r + nt, s + nt, ccn_sub_ws(NULL, nt, r, s, t));
}

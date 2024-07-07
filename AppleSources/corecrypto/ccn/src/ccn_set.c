/* Copyright (c) (2012,2014,2015,2018,2019,2021,2022) Apple Inc. All rights reserved.
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
#include <corecrypto/cc_priv.h>

#if CCN_SET_ASM
void ccn_set_asm(cc_size n, cc_unit *r, const cc_unit *s) __asm__("_ccn_set_asm");
#endif

void ccn_set(cc_size n, cc_unit *cc_counted_by(n) r, const cc_unit *cc_counted_by(n) s)
{
#if CCN_SET_ASM
    ccn_set_asm(n, r, s);
#else
    cc_memmove(r, s, ccn_sizeof_n(n));
#endif
}

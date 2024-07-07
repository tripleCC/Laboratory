/* Copyright (c) (2012,2014,2015,2019,2021,2022) Apple Inc. All rights reserved.
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

void ccn_zero_multi(cc_size n, cc_unit *r, ...)
{
    cc_unit *u = NULL;
    va_list argp;
    va_start(argp, r);
    ccn_zero(n, r);
    while((u = va_arg(argp, cc_unit *)) != NULL) {
        ccn_clear(n, u);
    }
    va_end(argp);
}

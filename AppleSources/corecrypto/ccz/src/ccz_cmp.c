/* Copyright (c) (2011,2012,2015,2019,2021) Apple Inc. All rights reserved.
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
#include <corecrypto/ccz_priv.h>

int ccz_cmp(const ccz *s, const ccz *t)
{
    CC_ENSURE_DIT_ENABLED

    if (ccz_sign(s) == ccz_sign(t))
        return ccn_cmpn(ccz_n(s), s->u, ccz_n(t), t->u) * ccz_sign(s);
    else if (ccz_n(t) == 0 && ccz_n(s) == 0)
        return 0;
    else
        return ccz_sign(s) < ccz_sign(t) ? -1 : 1;
}

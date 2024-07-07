/* Copyright (c) (2014,2015,2019,2021) Apple Inc. All rights reserved.
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
#include <corecrypto/cc_priv.h>

int cc_cmp_safe (size_t num, const void * ptr1, const void * ptr2)
{
    CC_ENSURE_DIT_ENABLED

    size_t i;
    const uint8_t *s=(const uint8_t *)ptr1;
    const uint8_t *t=(const uint8_t *)ptr2;
    uint8_t flag=((num<=0)?1:0); // If 0 return an error
    for (i=0;i<num;i++)
    {
        flag|=(s[i]^t[i]);
    }
    CC_HEAVISIDE_STEP(flag,flag); // flag=(flag==0)?0:1;
    return flag; // 0 iff all bytes were equal, 1 if there is any difference
}

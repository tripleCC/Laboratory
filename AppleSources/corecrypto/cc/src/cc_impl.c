/* Copyright (c) (2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/cc.h>

#define CC_IMPL_ITEM(k, v)                      \
    case CC_IMPL_##k:                           \
    return #k;

const char *cc_impl_name(cc_impl_t impl)
{
    switch (impl) {

        CC_IMPL_LIST

    default:
        return "UNKNOWN";
    }
}

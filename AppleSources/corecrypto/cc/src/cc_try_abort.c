/* Copyright (c) (2016-2019,2021) Apple Inc. All rights reserved.
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

#if CC_PROVIDES_ABORT

#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wmissing-noreturn"
#endif

void cc_try_abort(const char *msg)
{
    cc_abort(msg);
}

#ifdef __clang__
#pragma clang diagnostic pop
#endif

#else

void cc_try_abort(CC_UNUSED const char *msg)
{

}

#endif

void cc_try_abort_if(bool condition, const char *msg)
{
    if (CC_UNLIKELY(condition)) {
        cc_try_abort(msg);
    }
}

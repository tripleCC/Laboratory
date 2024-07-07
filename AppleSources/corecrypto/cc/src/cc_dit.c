/* Copyright (c) (2021,2022) Apple Inc. All rights reserved.
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

#if CC_DIT_MAYBE_SUPPORTED

// Ignore "unreachable code" warnings when compiling against SDKs
// that don't support checking for DIT support at runtime.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunreachable-code"

void cc_disable_dit(volatile bool *dit_was_enabled)
{
     if (!CC_HAS_DIT()) {
         return;
     }

#if CC_BUILT_FOR_TESTING
     // DIT should be enabled.
     cc_try_abort_if(!cc_is_dit_enabled(), "DIT not enabled");
#endif

     // Disable DIT, if this was the frame that enabled it.
     if (*dit_was_enabled) {
         // Encoding of <msr dit, #0>.
         __asm__ __volatile__(".long 0xd503405f");
         cc_assert(!cc_is_dit_enabled());
     }
}

#pragma clang diagnostic pop

#endif // CC_DIT_MAYBE_SUPPORTED

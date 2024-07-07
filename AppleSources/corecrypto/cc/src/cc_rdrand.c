/* Copyright (c) (2019,2021-2023) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "cc_runtime_config.h"
#include "cc_internal.h"

#if defined(__x86_64__)

static bool cc_rdrand_internal(uint64_t *rand)
{
    if (CC_HAS_RDRAND()) {
        __asm__ __volatile__("1: rdrand %0; jnc 1b" : "=r"(*rand) :: "cc");
        return true;
    }

    *rand = 0;
    return false;
}

#else

static bool cc_rdrand_internal(uint64_t *rand)
{
    *rand = 0;
    return false;
}

#endif

#if CC_BUILT_FOR_TESTING
bool (*cc_rdrand_mock)(uint64_t *rand);
#endif

bool cc_rdrand(uint64_t *rand)
{

#if CC_BUILT_FOR_TESTING
    if (cc_rdrand_mock) {
        return cc_rdrand_mock(rand);
    }
#endif

    return cc_rdrand_internal(rand);
}

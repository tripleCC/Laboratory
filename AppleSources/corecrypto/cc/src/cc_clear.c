/* Copyright (c) (2014-2019,2021-2023) Apple Inc. All rights reserved.
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
#include <corecrypto/cc.h>
#include <corecrypto/cc_config.h>
#include "fipspost_trace.h"

#if CC_HAS_SECUREZEROMEMORY
#include <windows.h>
#endif

#if !(CC_HAS_MEMSET_S || CC_HAS_SECUREZEROMEMORY || CC_HAS_EXPLICIT_BZERO)
/*
 * Pointer to memset is volatile so that the compiler must dereference
 * it and can't assume it points to any function in particular
 * (such as memset, which it then might further "optimize").
 */
    #if CC_EFI
        static void (*const volatile zero_mem_ptr)(void *, size_t) = EfiCommonLibZeroMem;
    #else
        static void* (*const volatile memset_ptr)(void*, int, size_t) = memset;
    #endif
#endif

void cc_clear(size_t len, void *dst)
{
    FIPSPOST_TRACE_EVENT;

#if CC_HAS_MEMSET_S
    memset_s(dst, len, 0, len);
#elif CC_HAS_SECUREZEROMEMORY
    SecureZeroMemory(dst, len);
#elif CC_HAS_EXPLICIT_BZERO
    explicit_bzero(dst, len);
#else
    #if CC_EFI
        (zero_mem_ptr)(dst, len);
    #else
        (memset_ptr)(dst, 0, len);
    #endif

    /* One more safeguard, should all hell break loose - a memory barrier.
     * The volatile function pointer _should_ work, but compilers are by
     * spec allowed to load `memset_ptr` into a register and skip the
     * call if `memset_ptr == memset`. However, too many systems rely
     * on such behavior for compilers to try and optimize it. */
    __asm__ __volatile__("" : : "r"(dst) : "memory");
#endif
}

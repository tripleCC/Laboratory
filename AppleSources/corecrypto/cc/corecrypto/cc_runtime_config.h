/* Copyright (c) (2012,2014-2023) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef CORECRYPTO_CC_RUNTIME_CONFIG_H_
#define CORECRYPTO_CC_RUNTIME_CONFIG_H_

#include <corecrypto/cc_config.h>
#include <corecrypto/cc.h>

#if defined(__x86_64__) || defined(__i386__)

#define CC_HAS_DIT() (0)

#if CC_KERNEL
    #include <i386/cpuid.h>
    #define CC_HAS_RDRAND() ((cpuid_features() & CPUID_FEATURE_RDRAND) != 0)
    #define CC_HAS_AESNI() ((cpuid_features() & CPUID_FEATURE_AES) != 0)
    #define CC_HAS_SupplementalSSE3() ((cpuid_features() & CPUID_FEATURE_SSSE3) != 0)
    #define CC_HAS_AVX1() ((cpuid_features() & CPUID_FEATURE_AVX1_0) != 0)
    #define CC_HAS_AVX2() ((cpuid_info()->cpuid_leaf7_features & CPUID_LEAF7_FEATURE_AVX2) != 0)
    #define CC_HAS_AVX512_AND_IN_KERNEL()    ((cpuid_info()->cpuid_leaf7_features & CPUID_LEAF7_FEATURE_AVX512F) !=0)
    #define CC_HAS_BMI2() ((cpuid_info()->cpuid_leaf7_features & CPUID_LEAF7_FEATURE_BMI2) != 0)
    #define CC_HAS_ADX() ((cpuid_info()->cpuid_leaf7_features & CPUID_LEAF7_FEATURE_ADX) != 0)

#elif CC_DARWIN && CC_INTERNAL_SDK
    #include <System/i386/cpu_capabilities.h>
    #define CC_HAS_RDRAND() (_get_cpu_capabilities() & kHasRDRAND)
    #define CC_HAS_AESNI() (_get_cpu_capabilities() & kHasAES)
    #define CC_HAS_SupplementalSSE3() (_get_cpu_capabilities() & kHasSupplementalSSE3)
    #define CC_HAS_AVX1() (_get_cpu_capabilities() & kHasAVX1_0)
    #define CC_HAS_AVX2() (_get_cpu_capabilities() & kHasAVX2_0)
    #define CC_HAS_AVX512_AND_IN_KERNEL() 0
    #define CC_HAS_BMI2() (_get_cpu_capabilities() & kHasBMI2)
    #define CC_HAS_ADX() (_get_cpu_capabilities() & kHasADX)

#else
    #define CC_HAS_AESNI() __builtin_cpu_supports("aes")
    #define CC_HAS_SupplementalSSE3() __builtin_cpu_supports("ssse3")
    #define CC_HAS_AVX1() __builtin_cpu_supports("avx")
    #define CC_HAS_AVX2() __builtin_cpu_supports("avx2")
    #define CC_HAS_AVX512_AND_IN_KERNEL() 0
    #define CC_HAS_BMI2() __builtin_cpu_supports("bmi2")
#if CC_LINUX || !CC_INTERNAL_SDK
    #include <cpuid.h>

    CC_INLINE bool _cpu_supports_rdrand(void)
    {
        unsigned int eax, ebx, ecx, edx;
        __cpuid(1, eax, ebx, ecx, edx);
        return ecx & bit_RDRND;
    }

    CC_INLINE bool _cpu_supports_adx(void)
    {
        unsigned int eax, ebx, ecx, edx;
        __cpuid_count(7, 0, eax, ebx, ecx, edx);
        return ebx & bit_ADX;
    }

    #define CC_HAS_RDRAND() _cpu_supports_rdrand()
    #define CC_HAS_ADX() _cpu_supports_adx()
#else
    #define CC_HAS_RDRAND() 0
    #define CC_HAS_ADX() 0
#endif

#endif

#endif  // defined(__x86_64__) || defined(__i386__)

#if defined(__arm64__)

#if CC_TXM

    #define CC_HAS_SHA512() (CC_ARM_FEATURE_SHA512)
    #define CC_HAS_SHA3() (0)

    extern bool cc_dit_supported(void);
    #define CC_HAS_DIT() (cc_dit_supported())

#elif CC_DARWIN && CC_INTERNAL_SDK
    #include <System/arm/cpu_capabilities.h>

#if __has_feature(address_sanitizer)
 #define CC_COMMPAGE_CPU_CAPABILITIES \
        (*((volatile __attribute__((address_space(1))) uint64_t *)_COMM_PAGE_CPU_CAPABILITIES64))
#else
 #define CC_COMMPAGE_CPU_CAPABILITIES \
        (*((volatile uint64_t *)_COMM_PAGE_CPU_CAPABILITIES64))
#endif

    CC_INLINE bool _cpu_supports(uint64_t flag)
    {
        return CC_COMMPAGE_CPU_CAPABILITIES & flag;
    }

    #define CC_HAS_SHA512() _cpu_supports(kHasARMv82SHA512)
    #define CC_HAS_SHA3() _cpu_supports(kHasARMv82SHA3)
    #define CC_HAS_DIT() _cpu_supports(kHasFeatDIT)
#else
    #define CC_HAS_SHA512() (CC_ARM_FEATURE_SHA512)
    #define CC_HAS_SHA3() (0)
    #define CC_HAS_DIT() (0)
#endif

#endif // defined(__arm64__)

#endif /* CORECRYPTO_CC_RUNTIME_CONFIG_H_ */

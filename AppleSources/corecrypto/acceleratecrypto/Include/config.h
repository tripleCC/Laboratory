/* Copyright (c) (2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */


#if (defined(__x86_64__) || defined(__i386__))

#if BUILDKERNEL

    #include <i386/cpuid.h>
    #define HAS_AESNI() ((cpuid_features() & CPUID_FEATURE_AES) != 0)
    #define HAS_SupplementalSSE3() ((cpuid_features() & CPUID_FEATURE_SSSE3) != 0)
    #define HAS_AVX1() ((cpuid_features() & CPUID_FEATURE_AVX1_0) != 0)
    #define HAS_AVX2() ((cpuid_info()->cpuid_leaf7_features & CPUID_LEAF7_FEATURE_AVX2) != 0)
    #define HAS_AVX512_AND_IN_KERNEL()    ((cpuid_info()->cpuid_leaf7_features & CPUID_LEAF7_FEATURE_AVX512F) !=0)

#elif (defined(__APPLE__) && defined(__MACH__) && (__has_include(<System/i386/cpu_capabilities.h>) || __has_include(<System/arm/cpu_capabilities.h>)))   // XNU_KERNEL_AVAILABLE

    #include <System/i386/cpu_capabilities.h>

    extern int _cpu_capabilities;
    #define HAS_AESNI() (_cpu_capabilities & kHasAES)
    #define HAS_SupplementalSSE3() (_cpu_capabilities & kHasSupplementalSSE3)
    #define HAS_AVX1() (_cpu_capabilities & kHasAVX1_0)
    #define HAS_AVX2() (_cpu_capabilities & kHasAVX2_0)
    #define HAS_AVX512_AND_IN_KERNEL() 0

#else

#if (defined(__AES__))
    #define HAS_AESNI() __AES__
#else
    #define HAS_AESNI() 0
#endif // defined(__AES__)

#if (defined(__SSSE3__))
    #define HAS_SupplementalSSE3() __SSSE3__
#else
    #define HAS_SupplementalSSE3() 0
#endif // defined(__SSE3__)

#if (defined(__AVX__))
    #define HAS_AVX1() __AVX__
#else
    #define HAS_AVX1() 0
#endif // defined(__AVX__)

#if (defined(__AVX2__))
    #define HAS_AVX2() __AVX2__
#else
    #define HAS_AVX2() 0
#endif // defined(__AVX2__)

    #define HAS_AVX512_AND_IN_KERNEL()  0

#endif

#endif // (defined(__x86_64__) || defined(__i386__))


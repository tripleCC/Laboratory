/* Copyright (c) (2017,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_FIPSPOST_GET_HMAC_H_
#define _CORECRYPTO_FIPSPOST_GET_HMAC_H_

#include <corecrypto/ccsha2.h>

struct mach_header;

/*
 * The pre-calculated SHA256 HMAC gets placed here for integrity
 * testing.  The current value is a random number.  Use a different random
 * number for each architecture type supported.
 */
#define FIPSPOST_PRECALC_HMAC_SIZE CCSHA256_OUTPUT_SIZE
#define FIPSPOST_HMAC_VALUE fipspost_precalc_hmac
#define FIPSPOST_PRECALC_HMAC_VARIABLE                                      \
__attribute__((section("__TEXT,__fips_hmacs"))) const unsigned char FIPSPOST_HMAC_VALUE[FIPSPOST_PRECALC_HMAC_SIZE]

#define FIPSPOST_PRECALC_HMAC(ARCH, MODE)                                   \
      { ARCH, MODE, 0x10, 0xdc, 0xe5, 0x34, 0x6f, 0x01,                     \
        0xdd, 0x82, 0xf8, 0xad, 0xe5, 0x8f, 0xa1, 0xcc,                     \
        0xc1, 0x32, 0xe5, 0xa8, 0x53, 0xc8, 0x39, 0xa3,                     \
        0x84, 0x5f, 0x3b, 0xcb, 0x39, 0x9e, 0xd1, 0x7b }

/* Comprehensive list, in the order of mach/machine.h */
#define FIPSPOST_PRECALC_HMAC_VALUE_X86_64      FIPSPOST_PRECALC_HMAC(0x86, 0x64)
#define FIPSPOST_PRECALC_HMAC_VALUE_X86_32      FIPSPOST_PRECALC_HMAC(0x86, 0x32)
#define FIPSPOST_PRECALC_HMAC_VALUE_ARM_4T      FIPSPOST_PRECALC_HMAC(0xa4, 0x01)
#define FIPSPOST_PRECALC_HMAC_VALUE_ARM_6       FIPSPOST_PRECALC_HMAC(0xa6, 0x00)
#define FIPSPOST_PRECALC_HMAC_VALUE_ARM_V5TEJ   FIPSPOST_PRECALC_HMAC(0xa5, 0x01)
#define FIPSPOST_PRECALC_HMAC_VALUE_ARM_XSCALE  FIPSPOST_PRECALC_HMAC(0xa5, 0x02)
#define FIPSPOST_PRECALC_HMAC_VALUE_ARM_7A      FIPSPOST_PRECALC_HMAC(0xa7, 0x0a)
#define FIPSPOST_PRECALC_HMAC_VALUE_ARM_7F      FIPSPOST_PRECALC_HMAC(0xa7, 0x0f)
#define FIPSPOST_PRECALC_HMAC_VALUE_ARM_7S      FIPSPOST_PRECALC_HMAC(0xa7, 0x05)
#define FIPSPOST_PRECALC_HMAC_VALUE_ARM_7K      FIPSPOST_PRECALC_HMAC(0xa7, 0x04)
#define FIPSPOST_PRECALC_HMAC_VALUE_ARM_6M      FIPSPOST_PRECALC_HMAC(0xa6, 0x01)
#define FIPSPOST_PRECALC_HMAC_VALUE_ARM_7M      FIPSPOST_PRECALC_HMAC(0xa7, 0x06)
#define FIPSPOST_PRECALC_HMAC_VALUE_ARM_7EM     FIPSPOST_PRECALC_HMAC(0xa7, 0x07)

#define FIPSPOST_PRECALC_HMAC_VALUE_ARM_64      FIPSPOST_PRECALC_HMAC(0xa8, 0x64)
#define FIPSPOST_PRECALC_HMAC_VALUE_ARM_64_V8   FIPSPOST_PRECALC_HMAC(0xa8, 0x68)
#define FIPSPOST_PRECALC_HMAC_VALUE_ARM_64E     FIPSPOST_PRECALC_HMAC(0xa8, 0x6e)
#define FIPSPOST_PRECALC_HMAC_VALUE_ARM_64_32   FIPSPOST_PRECALC_HMAC(0xa8, 0x32)

#define FIPSPOST_CREATE_PRECALC_HMAC(ARCH, VARIANT)                         \
    FIPSPOST_PRECALC_HMAC_VARIABLE = FIPSPOST_PRECALC_HMAC_VALUE ## _ ## ARCH ## _ ## VARIANT;

/*
 * Declare the individual variants based on the current architecture. Use the
 * raw compiler flags because each archive must have a different value, even if
 * they're all classed as '__arm__', to avoid duplicate values in a FAT file.
 */
#if defined(__x86_64__)
#define FIPSPOST_DECLARE_PRECALC_HMAC FIPSPOST_CREATE_PRECALC_HMAC(X86, 64)
#elif defined(__i386__)
#define FIPSPOST_DECLARE_PRECALC_HMAC FIPSPOST_CREATE_PRECALC_HMAC(X86, 32)
#elif defined(__ARM_ARCH_4T__)
#define FIPSPOST_DECLARE_PRECALC_HMAC FIPSPOST_CREATE_PRECALC_HMAC(ARM, 4T)
#elif defined(__ARM_ARCH_6K__)
#define FIPSPOST_DECLARE_PRECALC_HMAC FIPSPOST_CREATE_PRECALC_HMAC(ARM, 6)
// Unknown compiler flags for V5TEJ
// Unknown compiler flags for XSCALE
#elif defined (__ARM_ARCH_7A__) && !defined (__ARM_ARCH_7K__)
#define FIPSPOST_DECLARE_PRECALC_HMAC FIPSPOST_CREATE_PRECALC_HMAC(ARM, 7A)
#elif defined (__ARM_ARCH_7F__)
#define FIPSPOST_DECLARE_PRECALC_HMAC FIPSPOST_CREATE_PRECALC_HMAC(ARM, 7F)
#elif defined (__ARM_ARCH_7S__)
#define FIPSPOST_DECLARE_PRECALC_HMAC FIPSPOST_CREATE_PRECALC_HMAC(ARM, 7S)
#elif defined (__ARM_ARCH_7K__)
#define FIPSPOST_DECLARE_PRECALC_HMAC FIPSPOST_CREATE_PRECALC_HMAC(ARM, 7K)
#elif defined(__ARM_ARCH_6M__)
#define FIPSPOST_DECLARE_PRECALC_HMAC FIPSPOST_CREATE_PRECALC_HMAC(ARM, 6M)
#elif defined (__ARM_ARCH_7M__)
#define FIPSPOST_DECLARE_PRECALC_HMAC FIPSPOST_CREATE_PRECALC_HMAC(ARM, 7M)
#elif defined(__ARM_ARCH_7EM__)
#define FIPSPOST_DECLARE_PRECALC_HMAC FIPSPOST_CREATE_PRECALC_HMAC(ARM, 7EM)
#elif defined(__arm64e__)
#define FIPSPOST_DECLARE_PRECALC_HMAC FIPSPOST_CREATE_PRECALC_HMAC(ARM, 64E)
#elif defined(__ARM64_ARCH_8_32__)
#define FIPSPOST_DECLARE_PRECALC_HMAC FIPSPOST_CREATE_PRECALC_HMAC(ARM, 64_32)
#elif defined(__ARM_ARCH_ISA_A64)
#define FIPSPOST_DECLARE_PRECALC_HMAC FIPSPOST_CREATE_PRECALC_HMAC(ARM, 64)
// Unknown compiler flags for 64_V8
#else
#error Unsupported architecture type; add as necessary in the order of mach/machine.h.
#endif

#define FIPSPOST_EXTERN_PRECALC_HMAC extern FIPSPOST_PRECALC_HMAC_VARIABLE;

int fipspost_get_hmac(const struct mach_header* pmach_header, unsigned char* sha256HMACBuffer, size_t max_offset);
#endif

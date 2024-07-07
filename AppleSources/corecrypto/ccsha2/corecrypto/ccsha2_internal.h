/* Copyright (c) (2010-2012,2014-2019,2021-2023) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CCSHA2_INTERNAL_H_
#define _CORECRYPTO_CCSHA2_INTERNAL_H_

#include <corecrypto/ccdigest.h>

#ifndef CCSHA2_DISABLE_SHA512
#define CCSHA2_DISABLE_SHA512 0
#endif

#define CCSHA2_SHA256_USE_SHA512_K (CC_SMALL_CODE && !CCSHA2_DISABLE_SHA512)

#if CCSHA256_ARMV6M_ASM
extern const struct ccdigest_info ccsha256_v6m_di;
void ccsha256_v6m_compress(ccdigest_state_t c, size_t num, const void *p) __asm__("_ccsha256_v6m_compress");
#endif

void ccsha256_ltc_compress(ccdigest_state_t state, size_t nblocks, const void *buf);
void ccsha512_ltc_compress(ccdigest_state_t state, size_t nblocks, const void *in);

#if CCSHA2_VNG_INTEL && defined(__x86_64__)
extern const struct ccdigest_info ccsha224_vng_intel_AVX2_di;
extern const struct ccdigest_info ccsha224_vng_intel_AVX1_di;
extern const struct ccdigest_info ccsha256_vng_intel_AVX2_di;
extern const struct ccdigest_info ccsha256_vng_intel_AVX1_di;
extern const struct ccdigest_info ccsha384_vng_intel_AVX2_di;
extern const struct ccdigest_info ccsha384_vng_intel_AVX1_di;
extern const struct ccdigest_info ccsha384_vng_intel_SupplementalSSE3_di;
extern const struct ccdigest_info ccsha512_vng_intel_AVX2_di;
extern const struct ccdigest_info ccsha512_vng_intel_AVX1_di;
extern const struct ccdigest_info ccsha512_vng_intel_SupplementalSSE3_di;
extern const struct ccdigest_info ccsha512_256_vng_intel_AVX2_di;
extern const struct ccdigest_info ccsha512_256_vng_intel_AVX1_di;
extern const struct ccdigest_info ccsha512_256_vng_intel_SupplementalSSE3_di;
#endif

#if CC_USE_L4
extern const struct ccdigest_info ccsha256_trng_di;
#endif

extern const uint32_t ccsha256_K[64];
extern const uint64_t ccsha512_K[80];

void ccsha512_final(const struct ccdigest_info *di, ccdigest_ctx_t ctx, unsigned char *digest);

extern const uint32_t ccsha224_initial_state[8];
extern const uint32_t ccsha256_initial_state[8];
extern const uint64_t ccsha384_initial_state[8];
extern const uint64_t ccsha512_initial_state[8];
extern const uint64_t ccsha512_256_initial_state[8];

#endif /* _CORECRYPTO_CCSHA2_INTERNAL_H_ */

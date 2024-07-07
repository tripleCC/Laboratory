/* Copyright (c) (2016,2017,2019,2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/ccsha2.h>
#include <corecrypto/ccdigest_priv.h>
#include <corecrypto/cc_priv.h>
#include <corecrypto/cc_config.h>
#include "ccsha2_internal.h"
#include "AccelerateCrypto.h"

#if CC_USE_ASM && CCSHA2_VNG_INTEL && defined(__x86_64__)

static void ccsha384_vng_intel_ssse3_compress(ccdigest_state_t c, size_t num, const void *p)
{
    AccelerateCrypto_SHA512_compress_ssse3((uint64_t*) c, num, p);
}

static void ccsha384_vng_intel_avx1_compress(ccdigest_state_t c, size_t num, const void *p)
{
    AccelerateCrypto_SHA512_compress_AVX1((uint64_t*) c, num, p);
}

static void ccsha384_vng_intel_avx2_compress(ccdigest_state_t c, size_t num, const void *p)
{
    AccelerateCrypto_SHA512_compress_AVX2((uint64_t*) c, num, p);
}

const struct ccdigest_info ccsha384_vng_intel_AVX2_di = {
    .output_size = CCSHA384_OUTPUT_SIZE,
    .state_size = CCSHA512_STATE_SIZE,
    .block_size = CCSHA512_BLOCK_SIZE,
    .oid_size = ccoid_sha384_len,
    .oid = CC_DIGEST_OID_SHA384,
    .initial_state = ccsha384_initial_state,
    .compress = ccsha384_vng_intel_avx2_compress,
    .final = ccsha512_final,
    .impl = CC_IMPL_SHA384_VNG_INTEL_AVX2,
};

const struct ccdigest_info ccsha384_vng_intel_AVX1_di = {
    .output_size = CCSHA384_OUTPUT_SIZE,
    .state_size = CCSHA512_STATE_SIZE,
    .block_size = CCSHA512_BLOCK_SIZE,
    .oid_size = ccoid_sha384_len,
    .oid = CC_DIGEST_OID_SHA384,
    .initial_state = ccsha384_initial_state,
    .compress = ccsha384_vng_intel_avx1_compress,
    .final = ccsha512_final,
    .impl = CC_IMPL_SHA384_VNG_INTEL_AVX1,
};

const struct ccdigest_info ccsha384_vng_intel_SupplementalSSE3_di = {
    .output_size = CCSHA384_OUTPUT_SIZE,
    .state_size = CCSHA512_STATE_SIZE,
    .block_size = CCSHA512_BLOCK_SIZE,
    .oid_size = ccoid_sha384_len,
    .oid = CC_DIGEST_OID_SHA384,
    .initial_state = ccsha384_initial_state,
    .compress = ccsha384_vng_intel_ssse3_compress,
    .final = ccsha512_final,
    .impl = CC_IMPL_SHA384_VNG_INTEL_SUPPLEMENTAL_SSE3,
};

#endif

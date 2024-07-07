/* Copyright (c) (2021-2023) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/ccsha3.h>
#include "ccsha3_internal.h"
#include "cckeccak_internal.h"
#include "cc_runtime_config.h"
#include "AccelerateCrypto.h"

#if (defined(__arm64__) && CCSHA3_VNG_ARM) || (defined(__x86_64__) && CCSHA3_VNG_INTEL)
static void ccsha3_384_vng_compress(ccdigest_state_t state, size_t nblocks, const void *in)
{
    cckeccak_absorb_blocks((cckeccak_state_t)ccdigest_u64(state), CCSHA3_384_RATE, nblocks, in, (cckeccak_permutation)AccelerateCrypto_SHA3_keccak);
}

static void ccsha3_384_vng_final(const struct ccdigest_info *di, ccdigest_ctx_t ctx, uint8_t *digest)
{
    ccsha3_final(di, ctx, digest, (cckeccak_permutation)AccelerateCrypto_SHA3_keccak);
}

static const struct ccdigest_info ccsha3_384_vng_di = {
    .output_size = CCSHA3_384_OUTPUT_NBYTES,
    .state_size = CCSHA3_STATE_NBYTES,
    .block_size = CCSHA3_384_RATE,
    .oid_size = CCSHA3_OID_LEN,
    .oid = CC_DIGEST_OID_SHA3_384,
    .initial_state = ccsha3_keccak_p1600_initial_state,
    .compress = &ccsha3_384_vng_compress,
    .final = &ccsha3_384_vng_final,
};
#endif

#if defined(__arm64__) && CCSHA3_VNG_ARM
static void ccsha3_384_vng_hwassist_compress(ccdigest_state_t state, size_t nblocks, const void *in)
{
    cckeccak_absorb_blocks((cckeccak_state_t)ccdigest_u64(state), CCSHA3_384_RATE, nblocks, in, (cckeccak_permutation)AccelerateCrypto_SHA3_keccak_hwassist);
}

static void ccsha3_384_vng_hwassist_final(const struct ccdigest_info *di, ccdigest_ctx_t ctx, uint8_t *digest)
{
    ccsha3_final(di, ctx, digest, (cckeccak_permutation)AccelerateCrypto_SHA3_keccak_hwassist);
}

static const struct ccdigest_info ccsha3_384_vng_hwassist_di = {
    .output_size = CCSHA3_384_OUTPUT_NBYTES,
    .state_size = CCSHA3_STATE_NBYTES,
    .block_size = CCSHA3_384_RATE,
    .oid_size = CCSHA3_OID_LEN,
    .oid = CC_DIGEST_OID_SHA3_384,
    .initial_state = ccsha3_keccak_p1600_initial_state,
    .compress = &ccsha3_384_vng_hwassist_compress,
    .final = &ccsha3_384_vng_hwassist_final,
};
#endif

static void ccsha3_384_c_compress(ccdigest_state_t state, size_t nblocks, const void *in)
{
    cckeccak_absorb_blocks((cckeccak_state_t)ccdigest_u64(state), CCSHA3_384_RATE, nblocks, in, cckeccak_f1600_c);
}

static void ccsha3_384_c_final(const struct ccdigest_info *di, ccdigest_ctx_t ctx, uint8_t *digest)
{
    ccsha3_final(di, ctx, digest, cckeccak_f1600_c);
}

const struct ccdigest_info ccsha3_384_c_di = {
    .output_size = CCSHA3_384_OUTPUT_NBYTES,
    .state_size = CCSHA3_STATE_NBYTES,
    .block_size = CCSHA3_384_RATE,
    .oid_size = CCSHA3_OID_LEN,
    .oid = CC_DIGEST_OID_SHA3_384,
    .initial_state = ccsha3_keccak_p1600_initial_state,
    .compress = &ccsha3_384_c_compress,
    .final = &ccsha3_384_c_final,
};

const struct ccdigest_info *ccsha3_384_di(void)
{
#if defined(__arm64__) && CCSHA3_VNG_ARM
    if (CC_HAS_SHA3()) {
        return &ccsha3_384_vng_hwassist_di;
    }

    return &ccsha3_384_vng_di;
#else
 #if defined(__x86_64__) && CCSHA3_VNG_INTEL
    if (CC_HAS_BMI2()) {
        return &ccsha3_384_vng_di;
    }
 #endif
    return &ccsha3_384_c_di;
#endif
}

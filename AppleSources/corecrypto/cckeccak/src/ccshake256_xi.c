/* Copyright (c) (2022,2023) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "ccshake_internal.h"
#include "ccxof_internal.h"
#include "AccelerateCrypto.h"

#if (defined(__arm64__) && CCSHA3_VNG_ARM) || (defined(__x86_64__) && CCSHA3_VNG_INTEL)
static void ccshake256_vng_absorb(const struct ccxof_info *xi, ccxof_state_t state, size_t nblocks, const uint8_t *in)
{
    cckeccak_absorb_blocks((cckeccak_state_t)state, xi->block_nbytes, nblocks, in, (cckeccak_permutation)AccelerateCrypto_SHA3_keccak);
}

static void ccshake256_vng_absorb_last(const struct ccxof_info *xi, ccxof_state_t state, size_t in_nbytes, const uint8_t *in)
{
    cckeccak_absorb_and_pad((cckeccak_state_t)state, xi->block_nbytes, in_nbytes, in, 0x1f, (cckeccak_permutation)AccelerateCrypto_SHA3_keccak);
}

static void ccshake256_vng_squeeze(const struct ccxof_info *xi, ccxof_state_t state, size_t out_nbytes, uint8_t *out)
{
    cckeccak_squeeze((cckeccak_state_t)state, xi->block_nbytes, out_nbytes, out, (cckeccak_permutation)AccelerateCrypto_SHA3_keccak);
}

static const struct ccxof_info ccxof_shake256_vng_xi = {
    .state_nbytes = CCKECCAK_STATE_NBYTES,
    .block_nbytes = CCSHAKE256_RATE,
    .init = &ccshake_init,
    .absorb = &ccshake256_vng_absorb,
    .absorb_last = &ccshake256_vng_absorb_last,
    .squeeze = &ccshake256_vng_squeeze
};
#endif

#if defined(__arm64__) && CCSHA3_VNG_ARM
static void ccshake256_vng_hwassist_absorb(const struct ccxof_info *xi, ccxof_state_t state, size_t nblocks, const uint8_t *in)
{
    cckeccak_absorb_blocks((cckeccak_state_t)state, xi->block_nbytes, nblocks, in, (cckeccak_permutation)AccelerateCrypto_SHA3_keccak_hwassist);
}

static void ccshake256_vng_hwassist_absorb_last(const struct ccxof_info *xi, ccxof_state_t state, size_t in_nbytes, const uint8_t *in)
{
    cckeccak_absorb_and_pad((cckeccak_state_t)state, xi->block_nbytes, in_nbytes, in, 0x1f, (cckeccak_permutation)AccelerateCrypto_SHA3_keccak_hwassist);
}

static void ccshake256_vng_hwassist_squeeze(const struct ccxof_info *xi, ccxof_state_t state, size_t out_nbytes, uint8_t *out)
{
    cckeccak_squeeze((cckeccak_state_t)state, xi->block_nbytes, out_nbytes, out, (cckeccak_permutation)AccelerateCrypto_SHA3_keccak_hwassist);
}

static const struct ccxof_info ccxof_shake256_vng_hwassist_xi = {
    .state_nbytes = CCKECCAK_STATE_NBYTES,
    .block_nbytes = CCSHAKE256_RATE,
    .init = &ccshake_init,
    .absorb = &ccshake256_vng_hwassist_absorb,
    .absorb_last = &ccshake256_vng_hwassist_absorb_last,
    .squeeze = &ccshake256_vng_hwassist_squeeze
};
#endif

static void ccshake256_c_absorb(const struct ccxof_info *xi, ccxof_state_t state, size_t nblocks, const uint8_t *in)
{
    cckeccak_absorb_blocks((cckeccak_state_t)state, xi->block_nbytes, nblocks, in, cckeccak_f1600_c);
}

static void ccshake256_c_absorb_last(const struct ccxof_info *xi, ccxof_state_t state, size_t in_nbytes, const uint8_t *in)
{
    cckeccak_absorb_and_pad((cckeccak_state_t)state, xi->block_nbytes, in_nbytes, in, 0x1f, cckeccak_f1600_c);
}

static void ccshake256_c_squeeze(const struct ccxof_info *xi, ccxof_state_t state, size_t out_nbytes, uint8_t *out)
{
    cckeccak_squeeze((cckeccak_state_t)state, xi->block_nbytes, out_nbytes, out, cckeccak_f1600_c);
}

CC_UNUSED
static const struct ccxof_info ccxof_shake256_c_xi = {
    .state_nbytes = CCKECCAK_STATE_NBYTES,
    .block_nbytes = CCSHAKE256_RATE,
    .init = &ccshake_init,
    .absorb = &ccshake256_c_absorb,
    .absorb_last = &ccshake256_c_absorb_last,
    .squeeze = &ccshake256_c_squeeze
};

const struct ccxof_info *ccshake256_xi(void)
{
#if defined(__arm64__) && CCSHA3_VNG_ARM
    if (CC_HAS_SHA3()) {
        return &ccxof_shake256_vng_hwassist_xi;
    }

    return &ccxof_shake256_vng_xi;
#else
 #if defined(__x86_64__) && CCSHA3_VNG_INTEL
    if (CC_HAS_BMI2()) {
        return &ccxof_shake256_vng_xi;
    }
 #endif

    return &ccxof_shake256_c_xi;
#endif
}

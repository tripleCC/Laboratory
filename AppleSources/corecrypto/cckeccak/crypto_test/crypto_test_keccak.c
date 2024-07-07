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

#include "cckeccak_internal.h"
#include "cc_runtime_config.h"
#include "testmore.h"
#include "testbyteBuffer.h"
#include "cc_priv.h"
#include "cc_memory.h"
#include "ccrng.h"
#include "AccelerateCrypto.h"

#if defined(__arm64__) && CCSHA3_VNG_ARM
static void AccelerateCrypto_SHA3_keccak_hwassist_wrapper(cckeccak_state_t state)
{
#if CC_INTERNAL_SDK
    if (CC_HAS_SHA3()) {
        AccelerateCrypto_SHA3_keccak_hwassist((uint64_t *)state);
    } else
#endif
    {
        AccelerateCrypto_SHA3_keccak((uint64_t *)state);
    }
}
#elif defined(__x86_64__) && CCSHA3_VNG_INTEL
static void AccelerateCrypto_SHA3_keccak_intel_wrapper(cckeccak_state_t state)
{
    if (CC_HAS_BMI2()) {
        AccelerateCrypto_SHA3_keccak((uint64_t *)state);
    } else {
        cckeccak_f1600_c(state);
    }
}
#endif

cckeccak_permutation permutations[] = {
    cckeccak_f1600_c,
#if defined(__arm64__) && CCSHA3_VNG_ARM
    (cckeccak_permutation)AccelerateCrypto_SHA3_keccak,
    (cckeccak_permutation)AccelerateCrypto_SHA3_keccak_hwassist_wrapper,
#elif defined(__x86_64__) && CCSHA3_VNG_INTEL
    (cckeccak_permutation)AccelerateCrypto_SHA3_keccak_intel_wrapper,
#endif
};

// Test vectors from the `KeccakSpongeIntermediateValues_*.txt` files, available in the archives of https://keccak.team/ .
struct keccak_kat {
    size_t rate;
    uint8_t padding_lsb;
    size_t m_nbytes;
    char *m;
    char *state_after_absorb_blocks;
    char *state_after_absorb_and_pad;
    size_t out_nbytes;
    char *out;
};

const struct keccak_kat keccak_kats[] = {
#include "cckeccak.kat"
};

static void test_keccak(const struct keccak_kat *kat, cckeccak_permutation permutation)
{
    // Initialize the state
    struct cckeccak_state state;
    cckeccak_init_state(&state);

    // Load the message
    byteBuffer m_buf = hexStringToBytes(kat->m);
    is(m_buf->len, kat->m_nbytes, "Length of message does not match");

    // Determine the number of blocks that can be absorbed
    size_t nblocks = m_buf->len / kat->rate;

    // Absorb the blocks
    cckeccak_absorb_blocks(&state, kat->rate, nblocks, m_buf->bytes, permutation);

    // Check the state after having absorbed all the blocks.
    byteBuffer state_buf = hexStringToBytes(kat->state_after_absorb_blocks);
    is(state_buf->len, CCKECCAK_STATE_NUINT64 * sizeof(uint64_t), "Length of state does not match the expected size");
    for (size_t i = 0; i < CCKECCAK_STATE_NUINT64; i++) {
        uint64_t s = cc_load64_le(state_buf->bytes + (i * sizeof(uint64_t)));
        is(state.lanes[i], s, "State after absorbing blocks does not match");
    }

    // Absorb the rest of the message and pad
    cckeccak_absorb_and_pad(
        &state, kat->rate, kat->m_nbytes - nblocks * kat->rate, m_buf->bytes + nblocks * kat->rate, kat->padding_lsb, permutation);

    // Check the state after absorbing and padding
    byteBuffer state_after_buf = hexStringToBytes(kat->state_after_absorb_and_pad);
    is(state_after_buf->len, CCKECCAK_STATE_NUINT64 * sizeof(uint64_t), "Length of state does not match the expected size");
    for (size_t i = 0; i < CCKECCAK_STATE_NUINT64; i++) {
        uint64_t s = cc_load64_le(state_after_buf->bytes + (i * sizeof(uint64_t)));
        is(state.lanes[i], s, "State after absorbing and padding does not match");
    }

    // Squeeze.
    uint8_t *out = (uint8_t *)cc_malloc_clear(kat->out_nbytes);
    cckeccak_squeeze(&state, kat->rate, kat->out_nbytes, out, permutation);

    // Check the output
    byteBuffer out_buf = hexStringToBytes(kat->out);
    is(out_buf->len, kat->out_nbytes, "Length of output does not match the expected size");
    ok_memcmp(out_buf->bytes, out, kat->out_nbytes, "Output does not match");

    free(out);
}

static void test_absorb_pad_different_length(cckeccak_permutation permutation)
{
    // Absorb messages of different length: multiple of `rate`, `rate - 1` and `rate - sizeof(uint64_t)`
    // using both `cckeccak_absorb_blocks` and `cckeccak_absorb_and_pad` for branch coverage,
    // and check equality of the states.
    size_t rate = 136;
    const uint8_t padding = 0x06;
    uint8_t m[rate * 2];
    ccrng_generate(global_test_rng, sizeof(m), &m);

    struct cckeccak_state state;
    struct cckeccak_state state2;

    cckeccak_init_state(&state);
    cckeccak_absorb_and_pad(&state, rate, rate * 2, m, padding, permutation);
    cckeccak_init_state(&state2);
    cckeccak_absorb_blocks(&state2, rate, 2, m, permutation); // absorb 2 blocks of size `rate`
    cckeccak_absorb_and_pad(&state2, rate, /* m_nbytes = */ 0, m + rate * 2, padding, permutation);
    ok_memcmp(state.lanes, state2.lanes, CCKECCAK_STATE_NUINT64 * sizeof(uint64_t), "States do not match");

    cckeccak_init_state(&state);
    cckeccak_absorb_and_pad(&state, rate, rate * 2 - 1, m, padding, permutation);
    cckeccak_init_state(&state2);
    cckeccak_absorb_blocks(&state2, rate, 1, m, permutation); // absorb 1 block of size `rate`
    cckeccak_absorb_and_pad(&state2, rate, /* m_nbytes = */ rate - 1, m + rate, padding, permutation);
    ok_memcmp(state.lanes, state2.lanes, CCKECCAK_STATE_NUINT64 * sizeof(uint64_t), "States do not match");

    cckeccak_init_state(&state);
    cckeccak_absorb_and_pad(&state, rate, rate * 2 - sizeof(uint64_t), m, padding, permutation);
    cckeccak_init_state(&state2);
    cckeccak_absorb_blocks(&state2, rate, 1, m, permutation); // absorb 1 block of size `rate`
    cckeccak_absorb_and_pad(&state2, rate, /* m_nbytes = */ rate - sizeof(uint64_t), m + rate, padding, permutation);
    ok_memcmp(state.lanes, state2.lanes, CCKECCAK_STATE_NUINT64 * sizeof(uint64_t), "States do not match");
}

static void test_rate(size_t rate, cckeccak_permutation permutation)
{
    const uint8_t padding = 0x06;
    uint8_t m[168];
    ccrng_generate(global_test_rng, sizeof(m), &m);
    uint8_t out[10];
    uint8_t out2[sizeof(out)];

    struct cckeccak_state state;
    struct cckeccak_state state2;

    cckeccak_init_state(&state);
    cckeccak_absorb_and_pad(&state, rate, rate, m, padding, permutation);
    cckeccak_init_state(&state2);
    cckeccak_absorb_blocks(&state2, rate, 1, m, permutation);
    cckeccak_absorb_and_pad(&state, rate, /* m_nbytes = */ 0, m + rate, padding, permutation);
    ok_memcmp(state.lanes, state2.lanes, CCKECCAK_STATE_NUINT64 * sizeof(uint64_t), "States do not match");
    cckeccak_squeeze(&state, rate, sizeof(out), out, permutation);
    cckeccak_squeeze(&state2, rate, sizeof(out2), out2, permutation);
    ok_memcmp(out, out2, sizeof(out), "Outputs do not match");
}

static void test_all_fips202_rates(cckeccak_permutation permutation)
{
    // Test all FIPS-202 rates, for branch code coverage.
    test_rate(168, permutation);
    test_rate(144, permutation);
    test_rate(136, permutation);
    test_rate(104, permutation);
    test_rate(72,  permutation);
}

static void test_padding(uint8_t padding, cckeccak_permutation permutation)
{
    uint8_t rate = 136;
    uint8_t m[rate];
    ccrng_generate(global_test_rng, sizeof(m), &m);
    uint8_t out[10];
    uint8_t out2[sizeof(out)];

    struct cckeccak_state state;
    struct cckeccak_state state2;

    cckeccak_init_state(&state);
    cckeccak_absorb_and_pad(&state, rate, rate, m, padding, permutation);
    cckeccak_init_state(&state2);
    cckeccak_absorb_blocks(&state2, rate, 1, m, permutation);
    cckeccak_absorb_and_pad(&state, rate, /* m_nbytes = */ 0, m + rate, padding, permutation);
    ok_memcmp(state.lanes, state2.lanes, CCKECCAK_STATE_NUINT64 * sizeof(uint64_t), "States do not match");
    cckeccak_squeeze(&state, rate, sizeof(out), out, permutation);
    cckeccak_squeeze(&state2, rate, sizeof(out2), out2, permutation);
    ok_memcmp(out, out2, sizeof(out), "Outputs do not match");
}

static void test_all_paddings(cckeccak_permutation permutation)
{
    // Test all paddings, for branch code coverage.
    test_padding(0x01, permutation);
    test_padding(0x06, permutation);
    test_padding(0x1F, permutation);
}

int cckeccak_tests(TM_UNUSED int argc, TM_UNUSED char *const *argv)
{
    int nkeccak_kats = CC_ARRAY_LEN(keccak_kats);
    size_t npermutations = CC_ARRAY_LEN(permutations);
    int ntests = 0;
    ntests += (2 * CCKECCAK_STATE_NUINT64 + 5) * nkeccak_kats; // test_keccak
    ntests += 3;                                               // test_absorb_pad_different_length
    ntests += 5 * 2;                                           // test_all_fips202_rates
    ntests += 3 * 2;                                           // test_all_paddings
    plan_tests((int) (npermutations * (size_t)ntests));

    for (size_t i = 0; i < npermutations; i++)
    {
        for (int j = 0; j < nkeccak_kats; j++) {
            test_keccak(&keccak_kats[j], permutations[i]);
        }
        test_absorb_pad_different_length(permutations[i]);
        test_all_fips202_rates(permutations[i]);
        test_all_paddings(permutations[i]);
    }
    return 0;
}

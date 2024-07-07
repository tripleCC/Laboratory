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
#include "cc_internal.h"

/*
 * The Keccak sponge function relies on a family of permutations: Keccak-p (FIPS-202, Sec. 3).
 *
 * In particular, Keccak[c] uses 24 iterations of Keccak-p over a state of 1600 bits.
 */

#define CCKECCAK_F1600_NROUNDS 24

static void cckeccak_f1600_round(cckeccak_state_t state, uint64_t rc)
{
    // Temporary registers
    uint64_t t0, t1, t2, t3, t4, tmp;

    #define s00 state->lanes[0]
    #define s01 state->lanes[1]
    #define s02 state->lanes[2]
    #define s03 state->lanes[3]
    #define s04 state->lanes[4]
    #define s05 state->lanes[5]
    #define s06 state->lanes[6]
    #define s07 state->lanes[7]
    #define s08 state->lanes[8]
    #define s09 state->lanes[9]
    #define s10 state->lanes[10]
    #define s11 state->lanes[11]
    #define s12 state->lanes[12]
    #define s13 state->lanes[13]
    #define s14 state->lanes[14]
    #define s15 state->lanes[15]
    #define s16 state->lanes[16]
    #define s17 state->lanes[17]
    #define s18 state->lanes[18]
    #define s19 state->lanes[19]
    #define s20 state->lanes[20]
    #define s21 state->lanes[21]
    #define s22 state->lanes[22]
    #define s23 state->lanes[23]
    #define s24 state->lanes[24]

    // Function theta, as per FIPS-202 3.2.1.
    t0 = s00 ^ s05 ^ s10 ^ s15 ^ s20;
    t1 = s01 ^ s06 ^ s11 ^ s16 ^ s21;
    t2 = s02 ^ s07 ^ s12 ^ s17 ^ s22;
    t3 = s03 ^ s08 ^ s13 ^ s18 ^ s23;
    t4 = s04 ^ s09 ^ s14 ^ s19 ^ s24;

    tmp = t4 ^ CC_ROL64(t1, 1);
    s00 ^= tmp;
    s05 ^= tmp;
    s10 ^= tmp;
    s15 ^= tmp;
    s20 ^= tmp;
    tmp = t0 ^ CC_ROL64(t2, 1);
    s01 ^= tmp;
    s06 ^= tmp;
    s11 ^= tmp;
    s16 ^= tmp;
    s21 ^= tmp;
    tmp = t1 ^ CC_ROL64(t3, 1);
    s02 ^= tmp;
    s07 ^= tmp;
    s12 ^= tmp;
    s17 ^= tmp;
    s22 ^= tmp;
    tmp = t2 ^ CC_ROL64(t4, 1);
    s03 ^= tmp;
    s08 ^= tmp;
    s13 ^= tmp;
    s18 ^= tmp;
    s23 ^= tmp;
    tmp = t3 ^ CC_ROL64(t0, 1);
    s04 ^= tmp;
    s09 ^= tmp;
    s14 ^= tmp;
    s19 ^= tmp;
    s24 ^= tmp;

    // Function rho & pi, as per FIPS-202 3.2.2 & 3.2.3
    tmp = CC_ROL64(s01, 1);
    s01 = CC_ROL64(s06, 44);
    s06 = CC_ROL64(s09, 20);
    s09 = CC_ROL64(s22, 61);
    s22 = CC_ROL64(s14, 39);
    s14 = CC_ROL64(s20, 18);
    s20 = CC_ROL64(s02, 62);
    s02 = CC_ROL64(s12, 43);
    s12 = CC_ROL64(s13, 25);
    s13 = CC_ROL64(s19, 8);
    s19 = CC_ROL64(s23, 56);
    s23 = CC_ROL64(s15, 41);
    s15 = CC_ROL64(s04, 27);
    s04 = CC_ROL64(s24, 14);
    s24 = CC_ROL64(s21, 2);
    s21 = CC_ROL64(s08, 55);
    s08 = CC_ROL64(s16, 45);
    s16 = CC_ROL64(s05, 36);
    s05 = CC_ROL64(s03, 28);
    s03 = CC_ROL64(s18, 21);
    s18 = CC_ROL64(s17, 15);
    s17 = CC_ROL64(s11, 10);
    s11 = CC_ROL64(s07, 6);
    s07 = CC_ROL64(s10, 3);
    s10 = tmp;

    // Function chi, as per FIPS-202 3.2.4
    t0 = ((~s04) & s00);
    t1 = ((~s00) & s01);
    s00 ^= ((~s01) & s02) ^ rc; // Function iota, as per FIPS-202 3.2.5
    s01 ^= ((~s02) & s03);
    s02 ^= ((~s03) & s04);
    s03 ^= t0;
    s04 ^= t1;
    t0 = ((~s09) & s05);
    t1 = ((~s05) & s06);
    s05 ^= ((~s06) & s07);
    s06 ^= ((~s07) & s08);
    s07 ^= ((~s08) & s09);
    s08 ^= t0;
    s09 ^= t1;
    t0 = ((~s14) & s10);
    t1 = ((~s10) & s11);
    s10 ^= ((~s11) & s12);
    s11 ^= ((~s12) & s13);
    s12 ^= ((~s13) & s14);
    s13 ^= t0;
    s14 ^= t1;
    t0 = ((~s19) & s15);
    t1 = ((~s15) & s16);
    s15 ^= ((~s16) & s17);
    s16 ^= ((~s17) & s18);
    s17 ^= ((~s18) & s19);
    s18 ^= t0;
    s19 ^= t1;
    t0 = ((~s24) & s20);
    t1 = ((~s20) & s21);
    s20 ^= ((~s21) & s22);
    s21 ^= ((~s22) & s23);
    s22 ^= ((~s23) & s24);
    s23 ^= t0;
    s24 ^= t1;
}

// The Keccak permutation which underlies the six SHA-3 functions is Keccak-f1600 (FIPS-202 Sec 3.4).
void cckeccak_f1600_c(cckeccak_state_t state)
{
    // Round constants for Keccak (FIPS-202, Sec. 3.2.5).
    const uint64_t keccak_round_constants[CCKECCAK_F1600_NROUNDS] = {
        0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
        0x8000000080008081, 0x8000000000008009, 0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
        0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
        0x000000000000800a, 0x800000008000000a, 0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
    };

    for (unsigned ell = 0; ell < CCKECCAK_F1600_NROUNDS; ell++) {
        cckeccak_f1600_round(state, keccak_round_constants[ell]);
    }
}

// The current code only supports the rates of the SHA-3 functions (FIPS-202 Sec. 6.1 and 6.2)
CC_UNUSED CC_INLINE bool is_fips202_rate(const size_t rate)
{
    return (rate == 168 /* shake128 */) || (rate == 144 /* sha3-224 */) || (rate == 136 /* sha3-256 & shake256 */) ||
           (rate == 104 /* sha3-256 */) || (rate == 72 /* sha3-512 */);
}

// The current code only supports the paddings for the SHA-3 functions (FIPS-202 Sec. 5.1/6.1/6.2),
// and the padding 0x01 -- as in the reference implementation of Keccak in https://github.com/XKCP/XKCP
// [Standalone/CompactFIPS202/C/Keccak-readable-and-compact.c] -- to enable the use of the test vectors in https://keccak.team/ .
//
// - For SHA-3 hash functions, the message is concatenated with "01" and the padding function starts with "1",
//   hence `padding_lsb` = 0b011 = 0x06.
// - For SHA-3 extendable output functions, the message is concatenated with "1111" and the padding function starts with "1",
//   hence `padding_lsb` = 0b11111 = 0x1F.
CC_UNUSED CC_INLINE bool is_valid_padding(const uint8_t padding_lsb)
{
    return (padding_lsb == 0x06 /* sha3-* */) || (padding_lsb == 0x1F /* shake* */) ||
           (padding_lsb == 0x01 /* no bit to be appended */);
}

void cckeccak_init_state(cckeccak_state_t state)
{
    cc_clear(CCKECCAK_STATE_NUINT64 * sizeof(uint64_t), state->lanes);
}

// Absorb full blocks (FIPS-202 Sec. 4 step #6).
void cckeccak_absorb_blocks(cckeccak_state_t state,
                            const size_t rate,
                            const size_t nblocks,
                            const uint8_t *cc_sized_by(rate *nblocks) m,
                            cckeccak_permutation permutation)
{
    cc_assert(is_fips202_rate(rate));

    for (size_t j = 0; j < nblocks; j++) {
        // XOR the message.
        for (size_t i = 0; i < (rate / sizeof(uint64_t)); i++) {
            state->lanes[i] ^= cc_load64_le(m);
            m += sizeof(uint64_t);
        }
        // Apply the permutation.
        permutation(state);
    }
}

// Absorb the message, and add padding (FIPS-202 Sec. 4 steps #1 and #6, and Sec 5.1/6.1/6.2).
void cckeccak_absorb_and_pad(cckeccak_state_t state,
                             const size_t rate,
                             const size_t m_nbytes,
                             const uint8_t *cc_sized_by(m_nbytes) m,
                             const uint8_t padding_lsb,
                             cckeccak_permutation permutation)
{
    cc_assert(is_fips202_rate(rate));
    cc_assert(is_valid_padding(padding_lsb));

    // Absorb all the blocks first.
    const size_t nblocks = m_nbytes / rate;
    cckeccak_absorb_blocks(state, rate, nblocks, m, permutation);
    const size_t remaining_nbytes = m_nbytes - nblocks * rate;
    m += nblocks * rate;

    // Absorb the rest of the message by words of 64 bits.
    size_t i;
    for (i = 0; i < (remaining_nbytes / sizeof(uint64_t)); i++) {
        state->lanes[i] ^= cc_load64_le(m);
        m += sizeof(uint64_t);
    }

    // Absorb the last bytes, if any.
    if (m_nbytes & 0x07) {
        uint8_t tmp[sizeof(uint64_t)] = { 0 };
        cc_memcpy(tmp, m, (remaining_nbytes & 0x07));
        state->lanes[i] ^= cc_load64_le(tmp);
        cc_clear(sizeof(tmp), tmp);
    }

    // Add padding, as per FIPS-202 Sec 5.1/6.1/6.2.
    state->lanes[remaining_nbytes >> 3] ^= (uint64_t)padding_lsb << (8 * (remaining_nbytes & 0x07));
    state->lanes[(rate - 1) >> 3] ^= (uint64_t)128 << (8 * ((rate - 1) & 0x07));
}

// Squeeze to produce the output (FIPS-202 Sec. 4 steps #7-10).
void cckeccak_squeeze(cckeccak_state_t state, const size_t rate, const size_t out_nbytes, uint8_t *cc_sized_by(out_nbytes) out, cckeccak_permutation permutation)
{
    cc_assert(is_fips202_rate(rate));

    // Squeeze all the blocks first.
    size_t remaining_nbytes = out_nbytes;
    while (remaining_nbytes >= rate) {
        permutation(state);
        for (size_t i = 0; i < rate / sizeof(uint64_t); i++) {
            cc_store64_le(state->lanes[i], out);
            out += sizeof(uint64_t);
        }
        remaining_nbytes -= rate;
    }

    // If more bytes are needed, extract them.
    if (remaining_nbytes) {
        // Last squeeze.
        permutation(state);

        // Extract as many 64-bit words as possible.
        size_t i;
        for (i = 0; i < remaining_nbytes / sizeof(uint64_t); i++) {
            cc_store64_le(state->lanes[i], out);
            out += sizeof(uint64_t);
        }

        // Extract the remaining < sizeof(uint64_t) bytes, if any.
        if (remaining_nbytes & 0x07) {
            uint8_t tmp[sizeof(uint64_t)];
            cc_store64_le(state->lanes[i], tmp);
            cc_memcpy(out, tmp, (remaining_nbytes & 0x07));
            cc_clear(sizeof(tmp), tmp);
        }
    }
}

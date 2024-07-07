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

#ifndef _CORECRYPTO_CCKECCAK_INTERNAL_H_
#define _CORECRYPTO_CCKECCAK_INTERNAL_H_

#include <corecrypto/cc.h>
#include "cc_runtime_config.h"

/*
 * Implements the Keccak algorithm as described in [FIPS-202](https://doi.org/10.6028/NIST.FIPS.202) which underlies all the SHA-3
 * functions (hash functions, and extendable-output functions).
 *
 * Keccak is a sponge function: it first absorbs an arbitrarily-long byte-aligned message into the state of the function, after
 * which an arbitrary number of output bytes can be squeezed out of the state.
 *
 * The following API implements the Keccak[c] algorithm (Keccak restricted to a state of 1600 bits), as described in FIPS-202
 * Sec. 5.2.
 *
 * Note that the Keccak state does not keep track of whether the API has been called in order, or that the value of the rate
 * is consistent between the different API calls. Each function in this file should be called only once, in order, and with
 * the same rate; except `cckeccak_absorb_blocks` which can be called multiple times.
 *
 * Example with a rate of 136 and a padding of 0x06:
 *
 * // Initialize.
 * struct cckeccak_state state;
 * cckeccak_init_state(&state);
 *
 * // Optional: absorb some of the blocks of the input.
 * cckeccak_absorb_blocks(&state, 136, 10, input); input += 10 * 136;
 *
 * // Absorb the rest of the input and pad.
 * cckeccak_absorb_and_pad(&state, 136, nbytes, input, 0x06);
 *
 * // Squeeze `out_nbytes` into the output buffer `out`.
 * cckeccak_squeeze(&state, 136, out_nbytes, out);
 *
 */

// Keccak[c] state is a 5 x 5 x 64 array of bits, stored as a 1D array of 25 uint64_t.
#define CCKECCAK_STATE_NUINT64 25
#define CCKECCAK_STATE_NBYTES (CCKECCAK_STATE_NUINT64 * sizeof(uint64_t))

struct cckeccak_state {
    uint64_t lanes[CCKECCAK_STATE_NUINT64];
} CC_ALIGNED(8); // the alignment needs to match that of the state in ccdigest
typedef struct cckeccak_state *cckeccak_state_t;

// We define a function pointer for the cckeccak permutation to allow for usage of hardware-optimized implementations of the permutation
typedef void (* cckeccak_permutation)(cckeccak_state_t state);

// C-implementation of the Keccak-f[1600] permutation
void cckeccak_f1600_c(cckeccak_state_t state);

/// @function cckeccak_init_state
/// @abstract Initialize the state for Keccak[c].
/// @param state a pointer to the Keccak state.
void cckeccak_init_state(cckeccak_state_t state);

/// @function cckeccak_absorb_blocks
/// @abstract Absorb `nblocks` `rate`-byte blocks of a byte-aligned message into the Keccak[c] state.
/// @param state         A pointer to an initialized Keccak state.
/// @param rate          The rate of Keccak[c] in bytes, i.e., rate = (1600 - c)/8.
/// @param nblocks       The number of `rate`-byte blocks of message to absorb.
/// @param m             A pointer to the message that contains `rate * nblocks` bytes.
///
/// @warning The current code only supports the rates of the SHA-3 functions (FIPS-202 Sec. 6.1 and 6.2),
///          i.e., must be one of 168, 144, 136, 104, or 72.
///          This function does not perform padding.
void cckeccak_absorb_blocks(cckeccak_state_t state, size_t rate, size_t nblocks, const uint8_t *cc_sized_by(rate *nblocks) m, cckeccak_permutation permutation);

/// @function cckeccak_absorb_and_pad
/// @abstract Absorb a byte-aligned message into the Keccak[c] state, padded using the padding_lsb byte.
/// @param state         A pointer to an initialized Keccak state.
/// @param rate          The rate of Keccak[c] in bytes, i.e., rate = (1600 - c)/8.
/// @param m_nbytes      The number of bytes of message to absorb.
/// @param m             A pointer to the message that contains `m_nbytes` bytes.
/// @param padding_lsb   The padding to use.
///
/// @warning The current code only supports the rates of the SHA-3 functions (FIPS-202 Sec. 6.1 and 6.2),
///          i.e., must be one of 168, 144, 136, 104, or 72.
///          The current code only supports the paddings for the SHA-3 functions (FIPS-202 Sec. 5.1/6.1/6.2),
///          i.e., must be one of 0x06 and 0x1F. Additionally, the padding 0x01 is supported as per the
///          reference implementation of Keccak.
void cckeccak_absorb_and_pad(cckeccak_state_t state,
                             size_t rate,
                             size_t m_nbytes,
                             const uint8_t *cc_sized_by(m_nbytes) m,
                             uint8_t padding_lsb,
                             cckeccak_permutation permutation);

/// @function cckeccak_squeeze
/// @abstract Squeeze `out_nbytes` out of a Keccak[c] state.
/// @param state         A pointer to a Keccak state in which a padded message has been absorbed.
/// @param rate          The rate of Keccak[c] in bytes, i.e., rate = (1600 - c)/8.
/// @param out_nbytes    The number of bytes to squeeze out of the state.
/// @param out           A pointer to the output buffer.
///
/// @warning The current code only supports the rates of the SHA-3 functions (FIPS-202 Sec. 6.1 and 6.2),
///          i.e., must be one of 168, 144, 136, 104, or 72.
void cckeccak_squeeze(cckeccak_state_t state, size_t rate, size_t out_nbytes, uint8_t *cc_sized_by(out_nbytes) out, cckeccak_permutation permutation);

#endif /* _CORECRYPTO_CCKECCAK_INTERNAL_H_ */

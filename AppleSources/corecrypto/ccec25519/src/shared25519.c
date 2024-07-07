/* Copyright (c) (2019,2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */
#include "shared25519_internal.h"
#include "cc_internal.h"

/*!
    @function   is_smaller_than_p
    @abstract   Checks whether `a` is smaller than 2^255-19.

    @param      a  Low-endian, 32-byte number.

    @return     True, iff `a` < 2^255-19.
 */
CC_NONNULL_ALL
static bool is_smaller_than_p(const uint8_t *a)
{
    // The prime's MSB is 0x7f.
    uint8_t diff = a[31] ^ 0x7f;

    // All middle bytes are 0xff.
    for (size_t i = 30; i > 0; i--) {
        diff |= a[i] ^ 0xff;
    }

    // The prime's LSB is 0xed.
    // If diff=0 then we have a match so far.
    // Leave diff=0 iff a[0] >= prime[0].
    diff |= (uint8_t)(((uint16_t)a[0] - (uint16_t)0x00ed) >> 8);

    CC_HEAVISIDE_STEP(diff, diff);
    return (bool)diff;
}

/*!
    @function   is_bigger_than_zero
    @abstract   Checks whether `a` is bigger than zero.

    @param      a  Low-endian, 32-byte number.

    @return     True, iff `a` > 0.
 */
CC_NONNULL_ALL
static bool is_bigger_than_zero(const uint8_t *a)
{
    uint8_t acc = 0;

    for (size_t i = 0; i < 32; i++) {
        acc |= a[i];
    }

    CC_HEAVISIDE_STEP(acc, acc);
    return (bool)acc;
}

/*
   When generating a 255-bit number, there's roughly a 2^-250 chance that this
   ends up being not in the field, i.e. >= 2^255-19. A maximum number of 10
   iterations is therefore sufficient, we should never exceed that.
 */
int frandom(uint8_t *lambda, struct ccrng_state *rng)
{
    for (uint8_t count = 0; count < 10; count++) {
        // Generate a random 255-bit number.
        ccrng_generate(rng, 32, lambda);

        // Clamp to [0, 2^255-1].
        lambda[31] &= 0x7f;

        if (is_bigger_than_zero(lambda) && is_smaller_than_p(lambda)) {
            return CCERR_OK;
        }
    }

    return CCERR_INTERNAL;
}

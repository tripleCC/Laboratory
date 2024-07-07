/* Copyright (c) (2023) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "cc_debug.h"

#include "ccshake_internal.h"
#include "fipspost.h"
#include "fipspost_priv.h"
#include "fipspost_post_shake.h"

int fipspost_post_shake(CC_UNUSED uint32_t fips_mode)
{
    // See http://csrc.nist.gov/groups/ST/toolkit/examples.html#aHashing.
    // Check only bytes 480..511 of the XOF output for a given input.

    // Tail of expected output from calculating SHAKE128 over a 0-bit input message.
    uint8_t SHAKE128_0_BIT[32] = {
        0x43, 0xe4, 0x1b, 0x45, 0xa6, 0x53, 0xf2, 0xa5, 0xc4, 0x49, 0x2c, 0x1a, 0xdd, 0x54, 0x45, 0x12,
        0xdd, 0xa2, 0x52, 0x98, 0x33, 0x46, 0x2b, 0x71, 0xa4, 0x1a, 0x45, 0xbe, 0x97, 0x29, 0x0b, 0x6f
    };

    // Tail of expected output from calculating SHAKE256 over a 0-bit input message.
    uint8_t SHAKE256_0_BIT[32] = {
        0xab, 0x0b, 0xae, 0x31, 0x63, 0x39, 0x89, 0x43, 0x04, 0xe3, 0x58, 0x77, 0xb0, 0xc2, 0x8a, 0x9b,
        0x1f, 0xd1, 0x66, 0xc7, 0x96, 0xb9, 0xcc, 0x25, 0x8a, 0x06, 0x4a, 0x8f, 0x57, 0xe2, 0x7f, 0x2a
    };

    // Tail of expected output from calculating SHAKE128 over a 1600-bit input message.
    uint8_t SHAKE128_1600_BIT[32] = {
        0x44, 0xc9, 0xfb, 0x35, 0x9f, 0xd5, 0x6a, 0xc0, 0xa9, 0xa7, 0x5a, 0x74, 0x3c, 0xff, 0x68, 0x62,
        0xf1, 0x7d, 0x72, 0x59, 0xab, 0x07, 0x52, 0x16, 0xc0, 0x69, 0x95, 0x11, 0x64, 0x3b, 0x64, 0x39
    };

    // Tail of expected output from calculating SHAKE256 over a 1600-bit input message.
    uint8_t SHAKE256_1600_BIT[32] = {
        0x6a, 0x1a, 0x9d, 0x78, 0x46, 0x43, 0x6e, 0x4d, 0xca, 0x57, 0x28, 0xb6, 0xf7, 0x60, 0xee, 0xf0,
        0xca, 0x92, 0xbf, 0x0b, 0xe5, 0x61, 0x5e, 0x96, 0x95, 0x9d, 0x76, 0x71, 0x97, 0xa0, 0xbe, 0xeb
    };

    int status = CCERR_OK;
    uint8_t out[512];
    uint8_t in[1600 / 8];
    memset(in, 0xa3, sizeof(in));
    
    if (FIPS_MODE_IS_FORCEFAIL(fips_mode)) { // flip a bit
        SHAKE128_0_BIT[0] ^= 0x01;
        SHAKE256_0_BIT[0] ^= 0x01;
        SHAKE128_1600_BIT[0] ^= 0x01;
        SHAKE256_1600_BIT[0] ^= 0x01;
    }
    
    ccshake128(0, in, sizeof(out), out);
    if (cc_cmp_safe(sizeof(SHAKE128_0_BIT), out + 480, SHAKE128_0_BIT)) {
        failf("SHAKE128, 0-bit message failed");
        status |= CCPOST_KAT_FAILURE;
    }

    ccshake256(0, in, sizeof(out), out);
    if (cc_cmp_safe(sizeof(SHAKE256_0_BIT), out + 480, SHAKE256_0_BIT)) {
        failf("SHAKE256, 0-bit message failed");
        status |= CCPOST_KAT_FAILURE;
    }

    ccshake128(sizeof(in), in, sizeof(out), out);
    if (cc_cmp_safe(sizeof(SHAKE128_1600_BIT), out + 480, SHAKE128_1600_BIT)) {
        failf("SHAKE128, 1600-bit message failed");
        status |= CCPOST_KAT_FAILURE;
    }

    ccshake256(sizeof(in), in, sizeof(out), out);
    if (cc_cmp_safe(sizeof(SHAKE256_1600_BIT), out + 480, SHAKE256_1600_BIT)) {
        failf("SHAKE256, 1600-bit message failed");
        status |= CCPOST_KAT_FAILURE;
    }

    return status;
}

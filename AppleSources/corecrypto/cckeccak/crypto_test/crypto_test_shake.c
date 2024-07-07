/* Copyright (c) (2022) Apple Inc. All rights reserved.
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
#include "testmore.h"

// See http://csrc.nist.gov/groups/ST/toolkit/examples.html#aHashing.
// Check only bytes 480..511 of the XOF output for a given input.

// SHAKE128 - 0-bit input message.
static const uint8_t SHAKE128_0_BIT[32] = {
    0x43, 0xe4, 0x1b, 0x45, 0xa6, 0x53, 0xf2, 0xa5, 0xc4, 0x49, 0x2c, 0x1a, 0xdd, 0x54, 0x45, 0x12,
    0xdd, 0xa2, 0x52, 0x98, 0x33, 0x46, 0x2b, 0x71, 0xa4, 0x1a, 0x45, 0xbe, 0x97, 0x29, 0x0b, 0x6f
};

// SHAKE256 - 0-bit input message.
static const uint8_t SHAKE256_0_BIT[32] = {
    0xab, 0x0b, 0xae, 0x31, 0x63, 0x39, 0x89, 0x43, 0x04, 0xe3, 0x58, 0x77, 0xb0, 0xc2, 0x8a, 0x9b,
    0x1f, 0xd1, 0x66, 0xc7, 0x96, 0xb9, 0xcc, 0x25, 0x8a, 0x06, 0x4a, 0x8f, 0x57, 0xe2, 0x7f, 0x2a
};

// SHAKE128 - 1600-bit input message.
static const uint8_t SHAKE128_1600_BIT[32] = {
    0x44, 0xc9, 0xfb, 0x35, 0x9f, 0xd5, 0x6a, 0xc0, 0xa9, 0xa7, 0x5a, 0x74, 0x3c, 0xff, 0x68, 0x62,
    0xf1, 0x7d, 0x72, 0x59, 0xab, 0x07, 0x52, 0x16, 0xc0, 0x69, 0x95, 0x11, 0x64, 0x3b, 0x64, 0x39
};

// SHAKE256 - 1600-bit input message.
static const uint8_t SHAKE256_1600_BIT[32] = {
    0x6a, 0x1a, 0x9d, 0x78, 0x46, 0x43, 0x6e, 0x4d, 0xca, 0x57, 0x28, 0xb6, 0xf7, 0x60, 0xee, 0xf0,
    0xca, 0x92, 0xbf, 0x0b, 0xe5, 0x61, 0x5e, 0x96, 0x95, 0x9d, 0x76, 0x71, 0x97, 0xa0, 0xbe, 0xeb
};

static void test_shake(void)
{
    uint8_t out[512];

    uint8_t in[1600 / 8];
    memset(in, 0xa3, sizeof(in));

    ccshake128(0, in, sizeof(out), out);
    ok_memcmp(out + 480, SHAKE128_0_BIT, sizeof(SHAKE128_0_BIT), "SHAKE128, 0-bit message failed");

    ccshake256(0, in, sizeof(out), out);
    ok_memcmp(out + 480, SHAKE256_0_BIT, sizeof(SHAKE256_0_BIT), "SHAKE256, 0-bit message failed");

    ccshake128(sizeof(in), in, sizeof(out), out);
    ok_memcmp(out + 480, SHAKE128_1600_BIT, sizeof(SHAKE128_1600_BIT), "SHAKE128, 1600-bit message failed");

    ccshake256(sizeof(in), in, sizeof(out), out);
    ok_memcmp(out + 480, SHAKE256_1600_BIT, sizeof(SHAKE256_1600_BIT), "SHAKE256, 1600-bit message failed");

    // Test incremental SHAKE128.
    {
        const struct ccxof_info *xi = ccshake128_xi();

        ccshake128_ctx_decl(ctx);
        ccxof_init(xi, ctx);

        // Absorb in various chunk sizes. Start with c = sizeof(in) / 2, half every step.
        for (size_t n = sizeof(in), c = n / 2; n > 0; n -= c, c = CC_MAX(1U, c / 2)) {
            ccxof_absorb(xi, ctx, c, &in[sizeof(in) - n]);
        }

        // Squeeze in various chunk sizes. Start with c = sizeof(out) / 2, half every step.
        for (size_t n = sizeof(out), c = n / 2; n > 0; n -= c, c = CC_MAX(1U, c / 2)) {
            ccxof_squeeze(xi, ctx, c, &out[sizeof(out) - n]);
        }
    }

    ok_memcmp(out + 480, SHAKE128_1600_BIT, sizeof(SHAKE128_1600_BIT), "SHAKE128, 1600-bit message failed");

    // Test incremental SHAKE256.
    {
        const struct ccxof_info *xi = ccshake256_xi();

        ccshake256_ctx_decl(ctx);
        ccxof_init(xi, ctx);

        // Absorb in various chunk sizes. Start with c = sizeof(in) / 2, half every step.
        for (size_t n = sizeof(in), c = n / 2; n > 0; n -= c, c = CC_MAX(1U, c / 2)) {
            ccxof_absorb(xi, ctx, c, &in[sizeof(in) - n]);
        }

        // Squeeze in various chunk sizes. Start with c = sizeof(out) / 2, half every step.
        for (size_t n = sizeof(out), c = n / 2; n > 0; n -= c, c = CC_MAX(1U, c / 2)) {
            ccxof_squeeze(xi, ctx, c, &out[sizeof(out) - n]);
        }
    }

    ok_memcmp(out + 480, SHAKE256_1600_BIT, sizeof(SHAKE256_1600_BIT), "SHAKE256, 1600-bit message failed");
}

int ccshake_tests(TM_UNUSED int argc, TM_UNUSED char *const *argv)
{
    plan_tests(6);

    test_shake();

    return 0;
}

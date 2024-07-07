/* Copyright (c) (2019,2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "ccvrf_internal.h"

int
ccvrf_irtf_ed25519_string_to_point(ge_p3 *point, const uint8_t *string)
{
    if (ge_frombytes_vartime(point, string) != 0) {
        return CCVRF_POINT_DECODE_FAILURE;
    }
    return CCERR_OK;
}

void
ccvrf_irtf_ed25519_point_to_string(uint8_t *string, const ge_p3 *point)
{
    ge_p3_tobytes(string, point);
}

int
ccvrf_irtf_ed25519_decode_proof(const uint8_t *pi, ge_p3 *Gamma, uint8_t *c, uint8_t *s)
{
    int rv = CCERR_OK;
    if ((rv = ccvrf_irtf_ed25519_string_to_point(Gamma, pi)) != CCERR_OK) {
        return rv;
    }

    cc_memcpy(c, pi + 32, 16); // c = pi[32:48]
    cc_memcpy(s, pi + 48, 32); // s = pi[48:80]

    return rv;
}

int
ccvrf_irtf_ed25519_encode_proof(const ge_p3 *Gamma, const uint8_t *c, const uint8_t *s, uint8_t *pi)
{
    ccvrf_irtf_ed25519_point_to_string(pi, Gamma); // pi[0:32] = point_to_string(Gamma)
    cc_memcpy(pi + 32, c, 16); // pi[32:48] = c
    cc_memcpy(pi + 48, s, 32); // s = pi[48:80]

    return CCERR_OK;
}

void
ccvrf_irtf_ed25519_hash_points(const ccvrf_t vrf, const ge_p3 **points, size_t points_len, uint8_t *c)
{
    // ECVRF_hash_points(h, gamma, k*B, k*H)
    cc_assert(points_len == 4);

    size_t hash_input_len = 2 + (CCVRF_IRTF_ED25519_ENCODEDPOINT_LEN * points_len);
    uint8_t hash_input[2 + (CCVRF_IRTF_ED25519_ENCODEDPOINT_LEN * 4)];
    uint8_t c_scalar[MAX_DIGEST_OUTPUT_SIZE];

    hash_input[0] = CCVRF_IRTF_ED25519_SUITE;
    hash_input[1] = CCVRF_IRTF_ED25519_TWO;
    for (size_t i = 0; i < points_len; i++) {
        ccvrf_irtf_ed25519_point_to_string(hash_input + 2 + (CCVRF_IRTF_ED25519_ENCODEDPOINT_LEN * i), points[i]);
    }

    ccdigest(vrf->di, hash_input_len, hash_input, c_scalar);
    cc_memcpy(c, c_scalar, vrf->group_nbytes / 2);

    cc_clear(sizeof(c_scalar), c_scalar);
}

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

#include "cc_internal.h"
#include "ccvrf_internal.h"

static int
ccvrf_irtf_ed25519_verify_internal(const ccvrf_t vrf, const ge_p3 *Y_point, const uint8_t *message,
                           size_t message_nbytes, const uint8_t *proof)
{
    uint8_t H_string[32] = {};
    uint8_t c_scalar[32] = {};
    uint8_t s_scalar[64] = {};
    uint8_t cprime[16] = {};
    ge_p3 H = {};
    ge_p3 Gamma = {};
    ge_p3 U = {};
    ge_p3 V = {};
    ge_p3 p3 = {};
    ge_p1p1 p1 = {};
    ge_cached pc = {};

    int rv = CCERR_OK;
    if ((rv = ccvrf_irtf_ed25519_decode_proof(proof, &Gamma, c_scalar, s_scalar)) != CCERR_OK) {
        return rv;
    }

    cc_memset(c_scalar + vrf->group_nbytes / 2, 0, vrf->group_nbytes / 2);
    cc_memset(s_scalar + vrf->group_nbytes, 0, vrf->group_nbytes);
    sc_reduce(s_scalar);

    ccvrf_irtf_ed25519_hash2curve_elligator2(vrf->di, Y_point, message, message_nbytes, H_string);
    ge_frombytes_vartime(&H, H_string);

    // Compute U = s*B - c*Y
    ge_scalarmult(&p3, c_scalar, Y_point);
    ge_p3_to_cached(&pc, &p3);
    ge_scalarmult_base(&p3, s_scalar);
    ge_sub(&p1, &p3, &pc);
    ge_p1p1_to_p3(&U, &p1);

    // Compute V = s*H - c*Gamma
    ge_scalarmult(&p3, c_scalar, &Gamma);
    ge_p3_to_cached(&pc, &p3);
    ge_scalarmult(&p3, s_scalar, &H);
    ge_sub(&p1, &p3, &pc);
    ge_p1p1_to_p3(&V, &p1);

    // Compute c = ECVRF_hash_points(h, gamma, U, V)
    const ge_p3 *points[] = { &H, &Gamma, &U, &V };
    size_t points_len = CC_ARRAY_LEN(points);
    ccvrf_irtf_ed25519_hash_points(vrf, points, points_len, cprime);

    if (cc_cmp_safe(vrf->group_nbytes / 2, c_scalar, cprime) == 0) {
        return CCERR_OK;
    }

    return CCVRF_VERIFY_FAILURE;
}

static int
ccvrf_irtf_validate_public_key(const uint8_t *pk_string, ge_p3 *Y)
{
    if (ge_has_small_order(pk_string) != 0) {
        return CCVRF_POINT_INVALID_PUBLIC_KEY;
    }

    int rv = CCERR_OK;
    if ((rv = ccvrf_irtf_ed25519_string_to_point(Y, pk_string)) != CCERR_OK) {
        return rv;
    }

    return CCERR_OK;
}

int
ccvrf_irtf_ed25519_verify(const ccvrf_t vrf, const uint8_t *pk, const uint8_t *message, size_t message_nbytes, const uint8_t *proof)
{
    ge_p3 Y;

    int rv = CCERR_OK;
    if ((rv = ccvrf_irtf_validate_public_key(pk, &Y)) != CCERR_OK) {
        return rv;
    }

    return ccvrf_irtf_ed25519_verify_internal(vrf, &Y, message, message_nbytes, proof);
}

int ccvrf_verify(const ccvrf_t vrf, size_t public_key_nbytes, const uint8_t *public_key, size_t message_nbytes, const uint8_t *message, size_t proof_nbytes, const uint8_t *proof)
{
    CC_ENSURE_DIT_ENABLED

    cc_assert(public_key_nbytes == ccvrf_sizeof_public_key(vrf));
    cc_assert(proof_nbytes == ccvrf_sizeof_proof(vrf));

    if (public_key_nbytes != ccvrf_sizeof_public_key(vrf)) {
        return CCERR_PARAMETER;
    }
    if (proof_nbytes != ccvrf_sizeof_proof(vrf)) {
        return CCERR_PARAMETER;
    }

    return vrf->verify(vrf, public_key, message, message_nbytes, proof);
}

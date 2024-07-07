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

// Per https://tools.ietf.org/html/draft-irtf-cfrg-vrf-03#section-5.4.2.2
static void
ccvrf_irtf_nonce_generation(const struct ccdigest_info *di, uint8_t *k_scalar, const uint8_t *sk, const uint8_t *h_string)
{
    uint8_t k_string[64];

    ccdigest_di_decl(di, ctx);
    ccdigest_init(di, ctx);
    ccdigest_update(di, ctx, 32, sk);
    ccdigest_update(di, ctx, 32, h_string);
    ccdigest_final(di, ctx, k_string);

    // k_string[0:32] = string_to_int(k_string) mod q
    sc_reduce(k_string);

    cc_memcpy(k_scalar, k_string, 32);
    cc_clear(sizeof(k_string), k_string);
    ccdigest_di_clear(di, ctx);
}

static int
ccvrf_irtf_ed25519_prove_internal(ccvrf_t vrf, uint8_t *pi, const ge_p3 *Y, const uint8_t *x,
                          const uint8_t *sk, const uint8_t *alpha, size_t alphalen)
{
    uint8_t H_string[32] = {};
    uint8_t k_scalar[32] = {};
    uint8_t c_scalar[32] = {};
    uint8_t s_scalar[32] = {};
    ge_p3 H = {};
    ge_p3 Gamma = {};
    ge_p3 kB = {};
    ge_p3 kH = {};

    // Compute H = ECVRF_hash_to_curve(suite_string, Y, alpha_string)
    ccvrf_irtf_ed25519_hash2curve_elligator2(vrf->di, Y, alpha, alphalen, H_string);
    ge_frombytes_vartime(&H, H_string);

    // Compute Gamma = xH, kB, and kH
    ge_scalarmult(&Gamma, x, &H);
    ccvrf_irtf_nonce_generation(vrf->di, k_scalar, sk, H_string);
    ge_scalarmult_base(&kB, k_scalar);
    ge_scalarmult(&kH, k_scalar, &H);

    // Compute c = ECVRF_hash_points(h, gamma, k*B, k*H)
    const ge_p3 *points[] = { &H, &Gamma, &kB, &kH };
    size_t points_len = CC_ARRAY_LEN(points);
    ccvrf_irtf_ed25519_hash_points(vrf, points, points_len, c_scalar);
    cc_clear(16, c_scalar + 16); // trim the trailing 16 bytes

    // Compute s = c*x + k (mod q)
    sc_muladd(s_scalar, c_scalar, x, k_scalar);

    // Encode and output the proof
    ccvrf_irtf_ed25519_encode_proof(&Gamma, c_scalar, s_scalar, pi);

    cc_clear(sizeof(k_scalar), k_scalar);
    cc_clear(sizeof(H_string), H_string);
    cc_clear(sizeof(c_scalar), c_scalar);
    cc_clear(sizeof(H), &H);
    cc_clear(sizeof(Gamma), &Gamma);
    cc_clear(sizeof(kB), &kB);
    cc_clear(sizeof(kH), &kH);

    return CCERR_OK;
}

int
ccvrf_irtf_ed25519_prove(ccvrf_t vrf, const uint8_t *secret, const uint8_t *message, size_t message_len, uint8_t *proof)
{
    ge_p3 Y;
    uint8_t x[32];
    uint8_t sk[32];

    int result = ccvrf_irtf_ed25519_derive_scalar_internal(vrf, secret, x, sk);
    result |= ccvrf_irtf_ed25519_derive_public_key_internal(vrf, secret, &Y);
    result |= ccvrf_irtf_ed25519_prove_internal(vrf, proof, &Y, x, sk, message, message_len);

    cc_clear(sizeof(x), x);
    cc_clear(sizeof(sk), sk);
    cc_clear(sizeof(Y), &Y);

    return result;
}

int ccvrf_prove(const ccvrf_t vrf, size_t secret_key_nbytes, const uint8_t *secret_key,
                size_t message_nbytes, const uint8_t *message, size_t proof_nbytes, uint8_t *proof)
{
    CC_ENSURE_DIT_ENABLED

    cc_assert(secret_key_nbytes == ccvrf_sizeof_secret_key(vrf));
    cc_assert(proof_nbytes == ccvrf_sizeof_proof(vrf));

    if (secret_key_nbytes != ccvrf_sizeof_secret_key(vrf)) {
        return CCERR_PARAMETER;
    }
    if (proof_nbytes != ccvrf_sizeof_proof(vrf)) {
        return CCERR_PARAMETER;
    }

    return vrf->prove(vrf, secret_key, message, message_nbytes, proof);
}

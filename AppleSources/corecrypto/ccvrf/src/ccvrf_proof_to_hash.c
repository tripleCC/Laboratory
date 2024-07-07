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

// Per https://tools.ietf.org/html/draft-irtf-cfrg-vrf-03#section-5.2
// beta_string = Hash(suite_string || three_string || point_to_string(cofactor * Gamma))
int
ccvrf_irtf_ed25519_proof_to_hash(const ccvrf_t vrf, const uint8_t *proof, uint8_t *beta_string)
{
    ge_p3 Gamma = {};
    uint8_t c_scalar[16] = {};
    uint8_t s_scalar[32] = {};
    uint8_t hash_input[2 + 32];

    int rv = CCERR_OK;
    if ((rv = ccvrf_irtf_ed25519_decode_proof(proof, &Gamma, c_scalar, s_scalar)) != CCERR_OK) {
        return rv;
    }

    // Compute hash_input = suite_string || three_string || point_to_string(cofactor * Gamma)
    hash_input[0] = CCVRF_IRTF_ED25519_SUITE;
    hash_input[1] = CCVRF_IRTF_ED25519_THREE;
    ge_scalarmult_cofactor(&Gamma);
    ccvrf_irtf_ed25519_point_to_string(hash_input + 2, &Gamma);

    // Compute beta_string = Hash(hash_input)
    ccdigest(vrf->di, sizeof(hash_input), hash_input, beta_string);

    return rv;
}

int
ccvrf_proof_to_hash(const ccvrf_t vrf, size_t proof_nbytes, const uint8_t *proof, size_t hash_nbytes, uint8_t *hash)
{
    CC_ENSURE_DIT_ENABLED

    cc_assert(proof_nbytes == ccvrf_sizeof_proof(vrf));
    cc_assert(hash_nbytes == ccvrf_sizeof_hash(vrf));

    if (proof_nbytes != ccvrf_sizeof_proof(vrf)) {
        return CCERR_PARAMETER;
    }
    if (hash_nbytes != ccvrf_sizeof_hash(vrf)) {
        return CCERR_PARAMETER;
    }

    return vrf->proof_to_hash(vrf, proof, hash);
}

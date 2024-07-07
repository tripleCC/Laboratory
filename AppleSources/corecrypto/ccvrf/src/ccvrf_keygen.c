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

static void
ccvrf_irtf_clamp_element(uint8_t *element)
{
    element[0] &= 248;
    element[31] &= 127;
    element[31] |= 64;
}

int
ccvrf_irtf_ed25519_derive_scalar_internal(const ccvrf_t vrf, const uint8_t *secret, uint8_t *scalar, uint8_t *truncated_hash)
{
    uint8_t seed_hash[MAX_DIGEST_OUTPUT_SIZE];

    ccdigest(vrf->di, vrf->group_nbytes, secret, seed_hash);
    ccvrf_irtf_clamp_element(seed_hash);

    cc_memcpy(scalar, seed_hash, vrf->group_nbytes);
    cc_memcpy(truncated_hash, seed_hash + vrf->group_nbytes, vrf->group_nbytes);

    cc_clear(sizeof(seed_hash), seed_hash);

    return CCERR_OK;
}

int
ccvrf_irtf_ed25519_derive_public_key_internal(const ccvrf_t vrf, const uint8_t *secret, ge_p3 *Y)
{
    uint8_t seed_hash[MAX_DIGEST_OUTPUT_SIZE];

    ccdigest(vrf->di, vrf->group_nbytes, secret, seed_hash);
    ccvrf_irtf_clamp_element(seed_hash);

    ge_scalarmult_base(Y, seed_hash);

    cc_clear(sizeof(seed_hash), seed_hash);

    return CCERR_OK;
}

int
ccvrf_irtf_ed25519_derive_public_key(const ccvrf_t vrf, const uint8_t *secret, uint8_t *pk)
{
    ge_p3 Y;

    int result = ccvrf_irtf_ed25519_derive_public_key_internal(vrf, secret, &Y);
    ge_p3_tobytes(pk, &Y);

    return result;
}

int
ccvrf_derive_public_key(const ccvrf_t vrf, size_t secret_key_nbytes, const uint8_t *secret_key, size_t public_key_nbytes, uint8_t *public_key)
{
    CC_ENSURE_DIT_ENABLED

    cc_assert(secret_key_nbytes == ccvrf_sizeof_secret_key(vrf));
    cc_assert(public_key_nbytes == ccvrf_sizeof_public_key(vrf));

    if (secret_key_nbytes != ccvrf_sizeof_secret_key(vrf)) {
        return CCERR_PARAMETER;
    }
    if (public_key_nbytes != ccvrf_sizeof_public_key(vrf)) {
        return CCERR_PARAMETER;
    }

    return vrf->derive_public_key(vrf, secret_key, public_key);
}

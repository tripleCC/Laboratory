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
#include <corecrypto/ccsha2.h>

#include "ccvrf_internal.h"

static struct ccvrf _vrf_irtf_ed25519_draft03 = {
    .publickey_nbytes = CCVRF_IRTF_ED25519_PUBLICKEY_LEN,
    .secretkey_nbytes = CCVRF_IRTF_ED25519_SECRETKEY_LEN,
    .proof_nbytes = CCVRF_IRTF_ED25519_PROOF_LEN,
    .hash_nbytes = CCVRF_IRTF_ED25519_HASH_LEN,
    .group_nbytes = CCVRF_IRTF_ED25519_GROUP_LEN,
    .derive_public_key = ccvrf_irtf_ed25519_derive_public_key,
    .prove = ccvrf_irtf_ed25519_prove,
    .verify = ccvrf_irtf_ed25519_verify,
    .proof_to_hash = ccvrf_irtf_ed25519_proof_to_hash,
    .custom = NULL,
};

void
ccvrf_factory_irtfdraft03(ccvrf_t context, const struct ccdigest_info *di)
{
    CC_ENSURE_DIT_ENABLED

    const struct ccdigest_info *internal_di = ccsha512_di();
    cc_assert(di->output_size == internal_di->output_size);

    if (di->output_size != internal_di->output_size) {
        // Short-circuit, and fail to initialize.
        return;
    }

    *context = _vrf_irtf_ed25519_draft03;
    context->di = di;
}

void
ccvrf_factory_irtfdraft03_default(ccvrf_t context)
{
    CC_ENSURE_DIT_ENABLED

    ccvrf_factory_irtfdraft03(context, ccsha512_di());
}

size_t
ccvrf_sizeof_proof(ccvrf_t vrf)
{
    return vrf->proof_nbytes;
}

size_t
ccvrf_sizeof_hash(ccvrf_t vrf)
{
    return vrf->hash_nbytes;
}

size_t
ccvrf_sizeof_public_key(ccvrf_t vrf)
{
    return vrf->publickey_nbytes;
}

size_t
ccvrf_sizeof_secret_key(const ccvrf_t vrf)
{
    return vrf->secretkey_nbytes;
}

/* Copyright (c) (2022,2023) Apple Inc. All rights reserved.
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
#include "ccdrbg.h"
#include "ccdrbg_internal.h"

bool ccdrbg_must_reseed(const struct ccdrbg_info *info,
                        const struct ccdrbg_state *drbg)
{
    CC_ENSURE_DIT_ENABLED

    return info->must_reseed(drbg);
}

int ccdrbg_init(const struct ccdrbg_info *info,
            struct ccdrbg_state *drbg,
            size_t entropyLength, const void* entropy,
            size_t nonceLength, const void* nonce,
            size_t psLength, const void* ps)
{
    CC_ENSURE_DIT_ENABLED
    
    return info->init(info, drbg, entropyLength, entropy, nonceLength, nonce, psLength, ps);
}

int ccdrbg_reseed(const struct ccdrbg_info *info,
       struct ccdrbg_state *drbg,
       size_t entropyLength, const void *entropy,
       size_t additionalLength, const void *additional)
{
    CC_ENSURE_DIT_ENABLED
    
    return info->reseed(drbg, entropyLength, entropy, additionalLength, additional);
}


int ccdrbg_generate(const struct ccdrbg_info *info,
         struct ccdrbg_state *drbg,
         size_t dataOutLength, void *dataOut,
         size_t additionalLength, const void *additional)
{
    CC_ENSURE_DIT_ENABLED
    
    return info->generate(drbg, dataOutLength, dataOut, additionalLength, additional);
}

void ccdrbg_done(const struct ccdrbg_info *info, struct ccdrbg_state *drbg)
{
    info->done(drbg);
}

size_t ccdrbg_context_size(const struct ccdrbg_info *info)
{
    return info->size;
}

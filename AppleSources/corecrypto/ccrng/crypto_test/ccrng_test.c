/* Copyright (c) (2011,2012,2014-2017,2019,2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/ccrng_test.h>
#include <corecrypto/ccaes.h>
#include "cc_internal.h"

#include <stdlib.h>
#include <stdbool.h>

static int
ccrng_test_generate(struct ccrng_state *r, size_t count, void *bytes)
{
    struct ccrng_test_state *rng = (struct ccrng_test_state *)r;

    return ccdrbg_generate(&rng->drbg_info, rng->drbg_state, count, bytes, 0, NULL);
}

int ccrng_test_init(struct ccrng_test_state *rng,
                    size_t nbytes, const void *seed,
                    const char *personalization_string)
{
    rng->generate = ccrng_test_generate;

    static ccdrbg_df_bc_ctx_t df_ctx;
    int err = ccdrbg_df_bc_init(&df_ctx,
                                ccaes_cbc_encrypt_mode(),
                                16);
    cc_require_or_return(err == CCERR_OK, err);

    static struct ccdrbg_nistctr_custom custom = {
        .keylen = 16,
        .strictFIPS = false, // No reseeding needed
        .df_ctx = (ccdrbg_df_ctx_t *)&df_ctx
    };
    custom.ctr_info = ccaes_ctr_crypt_mode();
    ccdrbg_factory_nistctr(&rng->drbg_info, &custom);
    rng->drbg_state=malloc(rng->drbg_info.size * 2);
    if (personalization_string==NULL) personalization_string=""; // empty string
    return ccdrbg_init(&rng->drbg_info, rng->drbg_state, nbytes, seed, nbytes, seed,
                       strlen(personalization_string), personalization_string);
}

void ccrng_test_done(struct ccrng_test_state *rng)
{
    ccdrbg_done(&rng->drbg_info,rng->drbg_state);
    free(rng->drbg_state);
    rng->drbg_state=NULL; // Prevent reuse
}

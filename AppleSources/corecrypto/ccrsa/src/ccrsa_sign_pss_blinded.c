/* Copyright (c) (2015,2016,2018-2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "ccrsa_internal.h"
#include "ccrng_internal.h"

static int ccrsa_sign_pss_blinded_ws(cc_ws_t ws,
                                     struct ccrng_state *blinding_rng,
                                     const ccrsa_full_ctx_t key,
                                     const struct ccdigest_info* hashAlgorithm,
                                     const struct ccdigest_info* MgfHashAlgorithm,
                                     size_t saltSize, struct ccrng_state *rng,
                                     size_t hSize, const uint8_t *mHash,
                                     size_t *sigSize, uint8_t *sig)
{
    const cc_size modBits = cczp_bitlen(ccrsa_ctx_zm(key));
    const cc_size modBytes = cc_ceiling(modBits, 8);
    const cc_size emBits = modBits-1; //as defined in §8.1.1 of PKCS1-V2
    const cc_size emLen = cc_ceiling(emBits, 8); //In theory, emLen can be one byte less than modBytes
    int rc=0;

    //two FIPS 186-4 imposed conditions
    if(modBits==1024 && hashAlgorithm->output_size==512 && saltSize>hSize-2) return CCRSA_INVALID_INPUT;
    if (saltSize > hSize || hSize != hashAlgorithm->output_size) {
        return CCRSA_INVALID_INPUT;
    }

    //input validation checks
    if(*sigSize<modBytes) return CCRSA_INVALID_INPUT;
    *sigSize=modBytes;

    uint8_t salt[MAX_DIGEST_OUTPUT_SIZE];
    int rc_rng = CCERR_OK;
    if (saltSize > 0) {
        // Save the RNG status code; continue even if it is an error.
        rc_rng = ccrng_generate_fips(rng, saltSize, salt);
    }

    cc_size n = ccrsa_ctx_n(key);
    CC_DECL_BP_WS(ws, bp);
    cc_unit *EM = CC_ALLOC_WS(ws, n);
    //max length of EM in bytes is emLen. But since we pass EM to RSA exponentiation routine, we must have the length in modWords. In 64 bit machine, EM can be 7 bytes longer than what is needed in theory

    const cc_size modWords = n;
    cc_assert(ccn_sizeof_n(modWords) >= emLen);
    EM[0]=EM[modWords-1] = 0; //in case emLen<modWord* sizeof(cc_unit), zeroize
    const size_t ofs = ccn_sizeof_n(modWords) - emLen;
    cc_assert(ofs<=sizeof(cc_unit)); //EM can only be one cc_unit larger
    rc|=ccrsa_emsa_pss_encode(hashAlgorithm, MgfHashAlgorithm, saltSize, salt, hSize, mHash, emBits, (uint8_t *)EM+ofs);     //let it continue, although we know there might be an error
    ccn_swap(modWords, EM);

    rc |= ccrsa_priv_crypt_blinded_ws(ws, blinding_rng, key, EM, EM);

    /* we need to write leading zeroes if necessary */
    if (rc == CCERR_OK && rc_rng == CCERR_OK) {
        ccn_write_uint_padded_ct(modWords, EM, *sigSize, sig);
    } else {
        ccn_clear(modWords, EM); //ccrsa_emsa_pss_encode() directly writes to EM. EM is cleared incase there is an error
        if (rc_rng) {
            rc = rc_rng;
        }
    }

    CC_FREE_BP_WS(ws, bp);
    return rc;
}

int ccrsa_sign_pss_blinded(struct ccrng_state *blinding_rng,
                           const ccrsa_full_ctx_t key,
                           const struct ccdigest_info* hashAlgorithm,
                           const struct ccdigest_info* MgfHashAlgorithm,
                           size_t saltSize, struct ccrng_state *rng,
                           size_t hSize, const uint8_t *mHash,
                           size_t *sigSize, uint8_t *sig)
{
    CC_DECL_WORKSPACE_OR_FAIL(ws, CCRSA_SIGN_PSS_BLINDED_WORKSPACE_N(ccrsa_ctx_n(key)));
    int rv = ccrsa_sign_pss_blinded_ws(ws, blinding_rng, key, hashAlgorithm, MgfHashAlgorithm, saltSize, rng, hSize, mHash, sigSize, sig);
    CC_FREE_WORKSPACE(ws);
    return rv;
}

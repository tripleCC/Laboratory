/* Copyright (c) (2015-2019,2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "ccsrp_internal.h"
#include "ccdh_internal.h"
#include <corecrypto/ccrsa_priv.h> // for MGF

/*!
 @function   ccsrp_sha_interleave_RFC2945_ws
 @abstract   Hash Interleave per SHA_Interleave from RFC2945

 @param      ws        Workspace
 @param      srp       SRP
 @param      s         Shared Secret in array of cc_unit
 @param      dest      Byte array for output of size at least 2*di->outputsize
 */
CC_NONNULL_ALL
static void ccsrp_sha_interleave_RFC2945_ws(cc_ws_t ws,
                                            ccsrp_ctx_t srp,
                                            const cc_unit *s,
                                            uint8_t *dest)
{
    const struct ccdigest_info *di = ccsrp_ctx_di(srp);
    cc_size n = ccsrp_ctx_n(srp);

    CC_DECL_BP_WS(ws, bp);
    uint8_t *buf = (uint8_t *)CC_ALLOC_WS(ws, n);
    uint8_t *E = (uint8_t *)CC_ALLOC_WS(ws, (n + 1) / 2);
    uint8_t *F = (uint8_t *)CC_ALLOC_WS(ws, (n + 1) / 2);
    uint8_t *T = buf;

    size_t digestlen = di->output_size;
    uint8_t G[MAX_DIGEST_OUTPUT_SIZE];

    uint8_t *H = ((uint8_t *)dest) + digestlen;

    // remove all leading zero bytes from the input.
    size_t T_len = ccn_write_uint_size(n, s);
    ccn_write_uint(n, s, T_len, T);

    if (T_len & 1) {
        //  If the length of the resulting string is odd, also remove the first byte.
        T = &buf[1];
        T_len--;
    }
    // Extract the even-numbered bytes into a string E and the odd-numbered bytes into a string F
    for (size_t i = 0; i < T_len / 2; i++) {
        // E[i]=T[2*i];    // E = T[0] | T[2] | T[4] | ...
        // F[i]=T[2*i+1];  // F = T[1] | T[3] | T[5] | ...
        E[T_len / 2 - i - 1] = T[2 * i + 1]; // E = T[0] | T[2] | T[4] | ...
        F[T_len / 2 - i - 1] = T[2 * i];     // F = T[1] | T[3] | T[5] | ...
    }
    ccdigest(di, T_len / 2, E, G); //  G = SHA(E)
    ccdigest(di, T_len / 2, F, H); //  H = SHA(F)

    // Interleave the two hashes back together to form the output, i.e.
    //  result = G[0] | H[0] | G[1] | H[1] | ... | G[19] | H[19]
    for (size_t i = 0; i < digestlen; i++) {
        dest[2 * i] = G[i];
        dest[2 * i + 1] = H[i];
    }

    // With SHA1, the result will be 40 bytes (320 bits) long.
    CC_FREE_BP_WS(ws, bp);
}

/*!
 @function   ccsrp_mgf
 @abstract   Derivation using MGF as defined in RSA PKCS1

 @param      ws        Workspace
 @param      srp       SRP
 @param      s         Shared Secret in array of cc_unit
 @param      dest      Byte array for output of size at least 2*di->output_size
 */
CC_NONNULL_ALL
static int ccsrp_mgf_ws(cc_ws_t ws, ccsrp_ctx_t srp, const cc_unit *s, void *dest)
{
    const struct ccdigest_info *di = ccsrp_ctx_di(srp);
    cc_size n = ccsrp_ctx_n(srp);

    CC_DECL_BP_WS(ws, bp);
    uint8_t *buf = (uint8_t *)CC_ALLOC_WS(ws, n);

    // Skip leading zeros.
    size_t offset = ccsrp_export_ccn(srp, s, buf);

    int rv = ccmgf(di, 2 * di->output_size, dest, ccsrp_ctx_sizeof_n(srp) - offset, buf + offset);

    CC_FREE_BP_WS(ws, bp);
    return rv;
}

int ccsrp_generate_K_from_S_ws(cc_ws_t ws, ccsrp_ctx_t srp, const cc_unit *S)
{
    int rc = CCERR_OK;
    unsigned int kdf_variant = SRP_FLG(srp).variant & CCSRP_OPTION_KDF_MASK;

    if (kdf_variant == CCSRP_OPTION_KDF_HASH) {
        /* K = H(S) */
        ccsrp_digest_ccn_ws(
            ws, srp, S, ccsrp_ctx_K(srp), (SRP_FLG(srp).variant & CCSRP_OPTION_PAD_SKIP_ZEROES_k_U_X));
    } else if (kdf_variant == CCSRP_OPTION_KDF_INTERLEAVED) {
        /* K = SHA_Interleave(S) */
        /* specification is clear, leading zeroes are skipped */
        ccsrp_sha_interleave_RFC2945_ws(ws, srp, S, ccsrp_ctx_K(srp));
    } else if (kdf_variant == CCSRP_OPTION_KDF_MGF1) {
        /* K = MGF1(S) */
        rc = ccsrp_mgf_ws(ws, srp, S, ccsrp_ctx_K(srp));
    } else {
        rc = CCSRP_NOT_SUPPORTED_CONFIGURATION;
    }

    if (rc == CCERR_OK) {
        SRP_FLG(srp).sessionkey = true;
    }

    return rc;
}

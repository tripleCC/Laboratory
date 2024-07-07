/* Copyright (c) (2023) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "cckyber_internal.h"
#include "cckyber_mult.h"

/*! @function cckyber_pack_pubkey
 @abstract Serializes a given public key as the concatenation of the serialized
           vector of polynomials and the public seed used to generate matrix A.

 @param params Kyber parameters.
 @param pubkey Public key.
 @param seed   Public seed.
 @param out    Serialized output key.
 */
CC_INLINE CC_NONNULL_ALL
void cckyber_pack_pubkey(const cckyber_params_t *params,
                         const int16_t *pubkey,
                         const uint8_t *seed,
                         uint8_t *out)
{
    cckyber_polyvec_encode(params, out, pubkey);
    cc_memcpy(out + CCKYBER_POLYVEC_NBYTES(params), seed, CCKYBER_SYM_NBYTES);
}

/*! @function cckyber_indcpa_keypair_ws
 @abstract Computes a public and private key as part of the CPA-secure
           public-key encryption scheme underlying Kyber.

 @param ws      Workspace.
 @param params  Kyber parameters.
 @param pubkey  Public key.
 @param privkey Private key.
 @param coins   Coins (randomness).
 */
static int cckyber_indcpa_keypair_ws(cc_ws_t ws,
                                     const cckyber_params_t *params,
                                     uint8_t *pubkey,
                                     uint8_t *privkey,
                                     const uint8_t coins[CCKYBER_SYM_NBYTES])
{
    uint8_t buf[2 * CCKYBER_SYM_NBYTES];
    const uint8_t *publicseed = buf;
    const uint8_t *noiseseed = buf + CCKYBER_SYM_NBYTES;

    cc_size n = params->k;
    CC_DECL_BP_WS(ws, bp);

    int16_t *a = CCKYBER_ALLOC_POLYVEC_WS(ws, n, n);
    int16_t *e = CCKYBER_ALLOC_POLYVEC_WS(ws, n, 1);

    int16_t *t = CCKYBER_ALLOC_POLYVEC_WS(ws, n, 1);
    int16_t *s = CCKYBER_ALLOC_POLYVEC_WS(ws, n, 1);

    cckyber_hash_g(CCKYBER_SYM_NBYTES, coins, buf);
    cckyber_sample_ntt(params, publicseed, /* transposed = */ 0, a);

    uint8_t nonce = 0;
    for (unsigned k = 0; k < params->k; k++) {
        cckyber_poly_getnoise(&s[k * CCKYBER_N], noiseseed, nonce++);
    }
    for (unsigned k = 0; k < params->k; k++) {
        cckyber_poly_getnoise(&e[k * CCKYBER_N], noiseseed, nonce++);
    }

    // sˆ = NTT(s)
    cckyber_polyvec_ntt_forward(params, s);
    cckyber_polyvec_reduce(params, s);

    // eˆ = NTT(e)
    cckyber_polyvec_ntt_forward(params, e);

    // tˆ = Aˆ ◦ sˆ + eˆ
    for (unsigned k = 0; k < params->k; k++) {
        cckyber_polyvec_basemul(params, &t[k * CCKYBER_N], &a[k * CCKYBER_N * params->k], s);
        cckyber_poly_toplant(&t[k * CCKYBER_N]);
    }

    cckyber_polyvec_add(params, t, t, e);
    cckyber_polyvec_reduce(params, t);

    // ekPKE = ByteEncode_12(tˆ) || ρ
    cckyber_pack_pubkey(params, t, publicseed, pubkey);

    // dkPKE = ByteEncode_12(sˆ)
    cckyber_polyvec_encode(params, privkey, s);

    CC_FREE_BP_WS(ws, bp);
    cc_clear(sizeof(buf), buf);
    return CCERR_OK;
}

int cckyber_indcpa_keypair(const cckyber_params_t *params,
                           uint8_t *pubkey,
                           uint8_t *privkey,
                           const uint8_t coins[CCKYBER_SYM_NBYTES])
{
    CC_DECL_WORKSPACE_OR_FAIL(ws, CCKYBER_INDCPA_KEYPAIR_WORKSPACE_N(params->k));
    int rv = cckyber_indcpa_keypair_ws(ws, params, pubkey, privkey, coins);
    CC_FREE_WORKSPACE(ws);
    return rv;
}

int cckyber_indcpa_encrypt_ws(cc_ws_t ws,
                              const cckyber_params_t *params,
                              const uint8_t *pubkey,
                              const uint8_t msg[CCKYBER_MSG_NBYTES],
                              const uint8_t coins[CCKYBER_SYM_NBYTES],
                              uint8_t *ct)
{
    cc_size n = params->k;
    CC_DECL_BP_WS(ws, bp);

    int16_t *v = CCKYBER_ALLOC_POLY_WS(ws);
    int16_t *m = CCKYBER_ALLOC_POLY_WS(ws);

    int16_t *e1 = CCKYBER_ALLOC_POLYVEC_WS(ws, n, 1);
    int16_t *e2 = CCKYBER_ALLOC_POLY_WS(ws);

    int16_t *r = CCKYBER_ALLOC_POLYVEC_WS(ws, n, 1);
    int16_t *u = CCKYBER_ALLOC_POLYVEC_WS(ws, n, 1);
    int16_t *t = CCKYBER_ALLOC_POLYVEC_WS(ws, n, 1);

    int16_t *at = CCKYBER_ALLOC_POLYVEC_WS(ws, n, n);

    // tˆ = ByteDecode_12(ekPKE[0 : 384*k])
    cckyber_polyvec_decode(params, t, pubkey);

    // ρ = ekPKE[384*k : 384*k + 32]
    const uint8_t *seed = pubkey + CCKYBER_POLYVEC_NBYTES(params);

    uint8_t *pubkey2 = CCKYBER_ALLOC_INDCPA_PUBKEY_WS(ws, n);
    cckyber_pack_pubkey(params, t, seed, pubkey2);

    // Ensure pubkey == ByteEncode(ByteDecode(pubkey)).
    if (cc_cmp_safe(CCKYBER_PUBKEY_NBYTES(params), pubkey2, pubkey)) {
        return CCERR_PARAMETER;
    }

    cckyber_sample_ntt(params, seed, /* transposed = */ 1, at);

    uint8_t nonce = 0;
    for (unsigned k = 0; k < params->k; k++) {
        cckyber_poly_getnoise(&r[k * CCKYBER_N], coins, nonce++);
    }
    for (unsigned k = 0; k < params->k; k++) {
        cckyber_poly_getnoise(&e1[k * CCKYBER_N], coins, nonce++);
    }

    // e2 = SamplePolyCBDη2(PRFη2(r, N))
    cckyber_poly_getnoise(e2, coins, nonce);

    // µ = Decompress_1(ByteDecode_1(m)))
    cckyber_poly_from_msg(m, msg);

    // rˆ = NTT(r)
    cckyber_polyvec_ntt_forward(params, r);

    // u = NTT^−1(AˆT ◦ rˆ) + e1
    for (unsigned k = 0; k < params->k; k++) {
        cckyber_polyvec_basemul(params, &u[k * CCKYBER_N], &at[k * CCKYBER_N * params->k], r);
        cckyber_ntt_inverse(&u[k * CCKYBER_N]);
    }

    cckyber_polyvec_add(params, u, u, e1);
    cckyber_polyvec_reduce(params, u);

    // v = NTT^−1(tˆT ◦ rˆ) + e2 + µ
    cckyber_polyvec_basemul(params, v, t, r);
    cckyber_ntt_inverse(v);

    cckyber_poly_add(v, v, e2);
    cckyber_poly_add(v, v, m);
    cckyber_poly_reduce(v);

    // c1 = ByteEncode_du(Compress_du(u))
    cckyber_polyvec_compress(params, ct, u);

    // c2 = ByteEncode_dv(Compress_dv(v))
    cckyber_poly_compress(params, ct + CCKYBER_POLYVEC_COMPRESSED_NBYTES(params), v);

    CC_FREE_BP_WS(ws, bp);
    return CCERR_OK;
}

int cckyber_indcpa_encrypt(const cckyber_params_t *params,
                           const uint8_t *pubkey,
                           const uint8_t msg[CCKYBER_MSG_NBYTES],
                           const uint8_t coins[CCKYBER_SYM_NBYTES],
                           uint8_t *ct)
{
    CC_DECL_WORKSPACE_OR_FAIL(ws, CCKYBER_INDCPA_ENCRYPT_WORKSPACE_N(params->k));
    int rv = cckyber_indcpa_encrypt_ws(ws, params, pubkey, msg, coins, ct);
    CC_FREE_WORKSPACE(ws);
    return rv;
}

void cckyber_indcpa_decrypt_ws(cc_ws_t ws,
                               const cckyber_params_t *params,
                               const uint8_t *privkey,
                               const uint8_t *ct,
                               uint8_t msg[CCKYBER_MSG_NBYTES])
{
    cc_size n = params->k;
    CC_DECL_BP_WS(ws, bp);

    int16_t *v = CCKYBER_ALLOC_POLY_WS(ws);
    int16_t *w = CCKYBER_ALLOC_POLY_WS(ws);

    int16_t *u = CCKYBER_ALLOC_POLYVEC_WS(ws, n, 1);
    int16_t *s = CCKYBER_ALLOC_POLYVEC_WS(ws, n, 1);

    // c1 = c[0 : 32*du*k]
    const uint8_t *c1 = ct;

    // c2 = c[32*du*k : 32*(du*k + dv)]
    const uint8_t *c2 = ct + CCKYBER_POLYVEC_COMPRESSED_NBYTES(params);

    // u = Decompress_du(ByteDecode_du(c1))
    cckyber_polyvec_decompress(params, u, c1);

    // v = Decompress_dv(ByteDecode_dv(c2))
    cckyber_poly_decompress(params, v, c2);

    // sˆ = ByteDecode_12(dkPKE)
    cckyber_polyvec_decode(params, s, privkey);

    // w = v − NTT^−1(sˆT ◦ NTT(u))
    cckyber_polyvec_ntt_forward(params, u);
    cckyber_polyvec_basemul(params, w, s, u);
    cckyber_ntt_inverse(w);

    cckyber_poly_sub(w, v, w);
    cckyber_poly_reduce(w);

    // m = ByteEncode_1(Compress_1(w))
    cckyber_poly_to_msg(msg, w);
    CC_FREE_BP_WS(ws, bp);
}

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
#include "ccrng_internal.h"

int cckyber_kem_keypair_coins(const cckyber_params_t *params,
                              uint8_t *pubkey,
                              uint8_t *privkey,
                              const uint8_t coins[2 * CCKYBER_SYM_NBYTES])
{
    int rv = cckyber_indcpa_keypair(params, pubkey, privkey, coins);
    cc_require_or_return(rv == CCERR_OK, rv);

    cc_memcpy(privkey + CCKYBER_INDCPA_PRIVKEY_NBYTES(params), pubkey, CCKYBER_PUBKEY_NBYTES(params));
    cckyber_hash_h(CCKYBER_PUBKEY_NBYTES(params), pubkey, privkey + CCKYBER_PRIVKEY_NBYTES(params) - 2 * CCKYBER_SYM_NBYTES);

    /* Value z for pseudo-random output on reject */
    cc_memcpy(privkey + CCKYBER_PRIVKEY_NBYTES(params) - CCKYBER_SYM_NBYTES, coins + CCKYBER_SYM_NBYTES, CCKYBER_SYM_NBYTES);

    return rv;
}

int cckyber_kem_keypair(const cckyber_params_t *params,
                        uint8_t *pubkey,
                        uint8_t *privkey,
                        struct ccrng_state *rng)
{
    uint8_t coins[2 * CCKYBER_SYM_NBYTES];

    int rv = ccrng_generate(rng, sizeof(coins), coins);
    cc_require_or_return(rv == CCERR_OK, rv);

    rv = cckyber_kem_keypair_coins(params, pubkey, privkey, coins);
    cc_clear(sizeof(coins), coins);
    return rv;
}

int cckyber_kem_encapsulate_msg(const cckyber_params_t *params,
                                const uint8_t *pubkey,
                                uint8_t *ek,
                                uint8_t *sk,
                                const uint8_t msg[CCKYBER_SYM_NBYTES])
{
    uint8_t kr[2 * CCKYBER_SYM_NBYTES];

    // The "type check" `len(pubkey) == 384*k + 32` is performed by
    // `cckem_kyber(768|1024)_import_pubkey()`.

    // The "modulus check" `pubkey == ByteEncode12(ByteDecode12(pubkey)` is
    // performed by `cckyber_indcpa_encrypt()` to avoid decoding `pubkey` twice.

    // Multitarget countermeasure for coins + contributory KEM.
    cc_memcpy(kr, msg, CCKYBER_SYM_NBYTES);
    cckyber_hash_h(CCKYBER_PUBKEY_NBYTES(params), pubkey, kr + CCKYBER_SYM_NBYTES);
    cckyber_hash_g(sizeof(kr), kr, kr);

    const uint8_t *key = kr;
    const uint8_t *coins = kr + CCKYBER_SYM_NBYTES;

    int rv = cckyber_indcpa_encrypt(params, pubkey, msg, coins, ek);
    if (rv == CCERR_OK) {
        cc_memcpy(sk, key, CCKYBER_SK_NBYTES);
    }

    cc_clear(sizeof(kr), kr);
    return rv;
}

int cckyber_kem_encapsulate(const cckyber_params_t *params,
                            const uint8_t *pubkey,
                            uint8_t *ek,
                            uint8_t *sk,
                            struct ccrng_state *rng)
{
    uint8_t msg[CCKYBER_SYM_NBYTES];

    int rv = ccrng_generate(rng, sizeof(msg), msg);
    cc_require_or_return(rv == CCERR_OK, rv);

    rv = cckyber_kem_encapsulate_msg(params, pubkey, ek, sk, msg);
    cc_clear(sizeof(msg), msg);
    return rv;
}

/*! @function cckyber_kem_decapsulate_ws
 @abstract Generates a shared key from a given encapsulated and private key.

 @param ws      Workspace.
 @param params  Kyber parameters.
 @param privkey Private key.
 @param ek      Encapsulated key.
 @param sk      Output shared key.

 @return CCERR_OK on success, an error code otherwise.
 */
CC_WARN_RESULT CC_NONNULL_ALL
static int cckyber_kem_decapsulate_ws(cc_ws_t ws,
                                      const cckyber_params_t *params,
                                      const uint8_t *privkey,
                                      const uint8_t *ek,
                                      uint8_t *sk)
{
    uint8_t kr[2 * CCKYBER_SYM_NBYTES];
    uint8_t buf[2 * CCKYBER_SYM_NBYTES];

    // The "ciphertext type check" `len(ek) == 32 * (d_u*k + d_v)` is
    // performed by `cckem_decapsulate()`.

    // The "decapsulation key type check" `len(privkey) == 768*k + 96` is
    // performed by `cckem_kyber(768|1024)_import_privkey()`.

    const uint8_t *pubkey = privkey + CCKYBER_INDCPA_PRIVKEY_NBYTES(params);

    cc_size n = params->k;
    CC_DECL_BP_WS(ws, bp);

    cckyber_indcpa_decrypt_ws(ws, params, privkey, ek, buf);

    // Multitarget countermeasure for coins + contributory KEM.
    cc_memcpy(buf + CCKYBER_SYM_NBYTES, privkey + CCKYBER_PRIVKEY_NBYTES(params) - 2 * CCKYBER_SYM_NBYTES, CCKYBER_SYM_NBYTES);
    cckyber_hash_g(2 * CCKYBER_SYM_NBYTES, buf, kr);

    const uint8_t *key = kr;
    const uint8_t *coins = kr + CCKYBER_SYM_NBYTES;

    // Re-encrypt and compare.
    uint8_t *cmp = CCKYBER_ALLOC_EK_WS(ws, n);
    int rv = cckyber_indcpa_encrypt_ws(ws, params, pubkey, buf, coins, cmp);
    int fail = cc_cmp_safe(CCKYBER_EK_NBYTES(params), ek, cmp);

    // Compute rejection key.
    cckyber_rkprf(privkey + CCKYBER_PRIVKEY_NBYTES(params) - CCKYBER_SYM_NBYTES, CCKYBER_EK_NBYTES(params), ek, sk);

    // Copy true key to return buffer if fail is false.
    cc_static_assert(CCKYBER_SK_NBYTES % CCN_UNIT_SIZE == 0, "CCKYBER_SK_NBYTES not a multiple of sizeof(cc_unit)");
    ccn_mux(ccn_nof_size(CCKYBER_SK_NBYTES), (cc_unit)fail, (cc_unit *)sk, (const cc_unit *)sk, (const cc_unit *)key);

    CC_FREE_BP_WS(ws, bp);
    cc_clear(sizeof(buf), buf);
    cc_clear(sizeof(kr), kr);
    return rv;
}

int cckyber_kem_decapsulate(const cckyber_params_t *params,
                            const uint8_t *privkey,
                            const uint8_t *ek,
                            uint8_t *sk)
{
    CC_DECL_WORKSPACE_OR_FAIL(ws, CCKYBER_KEM_DECAPSULATE_WORKSPACE_N(params->k));
    int rv = cckyber_kem_decapsulate_ws(ws, params, privkey, ek, sk);
    CC_FREE_WORKSPACE(ws);
    return rv;
}

/* Copyright (c) (2010-2019,2021,2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

/*
 * NIST SP 800-90 CTR_DRBG (Random Number Generator)
 */

/*
 In English, this is a Deterministic Random Bit Generator,
 a.k.a. Pseudo-Random Number Generator.

 Strictly speaking, a DRBG is the output stage of a PRNG that
 needs to be seeded from an entropy source. For a full discussion
 of DRBGs, look at NIST SP 800-90. You can search for it. They
 define DRBGs based on hash functions, HMACs, ciphers in counter
 mode, and elliptic curves. This is the cipher one, using AES.
 It's been written and tested with AES-128. It should be generic
 enough to use with AES-256, but is presently untested.

 A DRBG has four routines:
 instantiate()
 generate()
 reseed()
 destroy()

 Further discussion of each routine is below. This implements the
 DRBG with a derivation function, and is intended to be used with
 prediction resistance, but that has to be done in an upper level
 with the entropy source.

 The typical usage is that instantiate() creates the DRBG and
 feeds it its initial entropy, along with a nonce, and optional
 personalization information. The generate() function generates
 random bits. The reseed() function reseeds it with more entropy.
 The destroy() function clears and deallocates the structures.

 Note that while a DRBG is a "bit" generator, this package
 generates bytes. If you need less than a byte, extract it.

 A DRBG must be reseeded every so often. You can get the number
 of calls to it remaining before a mandatory reseed from
 CCADRBGGetReseedCountdown().

 Note that this DRBG is not thread-safe. Its callers must not
 only manage entropy for it, but they must use it appropriately.

 Fortunately, CommonRNG.[ch] has a nice implementation of all that,
 and is probably what you should be using.

 */

#include "cc_internal.h"
#include <corecrypto/ccdrbg.h>
#include <corecrypto/ccmode.h>
#include "ccmode_internal.h"
#include <corecrypto/cc_priv.h>
#include "ccdrbg_internal.h"
#include "ccdrbg_df_internal.h"
#include "cc_macros.h"

// The NIST CTR_DRBG is technically only specified for AES and three-key TDEA,
// so AES is the biggest block we require.
// Reserve eight blocks to take advantage of parallel implementations of AES.
static const uint8_t zeros[CCAES_BLOCK_SIZE * CCAES_CTR_MAX_PARALLEL_NBLOCKS];

static void init_ctr(struct ccdrbg_nistctr_state *drbg_ctx, ccctr_ctx *ctr_ctx)
{
    inc_uint(drbg_ctx->V + DRBG_CTR_BLOCKLEN(drbg_ctx) - DRBG_CTR_CTRLEN, DRBG_CTR_CTRLEN);
    ccctr_init(drbg_ctx->custom.ctr_info, ctr_ctx, drbg_ctx->custom.keylen, drbg_ctx->Key, drbg_ctx->V);
}

static void update_with_ctr(struct ccdrbg_nistctr_state *drbg_ctx, ccctr_ctx *ctr_ctx, const uint8_t *provided_data)
{
    ccctr_update(drbg_ctx->custom.ctr_info, ctr_ctx, DRBG_CTR_KEYLEN(drbg_ctx), provided_data, drbg_ctx->Key);
    provided_data += DRBG_CTR_KEYLEN(drbg_ctx);

    ccctr_update(drbg_ctx->custom.ctr_info, ctr_ctx, DRBG_CTR_BLOCKLEN(drbg_ctx), provided_data, drbg_ctx->V);
}

static void update(struct ccdrbg_nistctr_state *drbg_ctx, const uint8_t *provided_data)
{
    ccctr_ctx_decl(ccctr_context_size(drbg_ctx->custom.ctr_info), ctr_ctx);

    init_ctr(drbg_ctx, ctr_ctx);
    update_with_ctr(drbg_ctx, ctr_ctx, provided_data);

    ccctr_ctx_clear(ccctr_context_size(drbg_ctx->custom.ctr_info), ctr_ctx);
}

static int derive(struct ccdrbg_nistctr_state *drbg_ctx, void *out, unsigned ndata, ...)
{
    cc_iovec_t data[3];
    va_list args;

    if (ndata > CC_ARRAY_LEN(data)) {
        cc_try_abort("ccdrbg_nistctr: too many data");
        return CCDRBG_STATUS_PARAM_ERROR;
    }

    va_start(args, ndata);

    for (unsigned i = 0; i < ndata; i += 1) {
        data[i].nbytes = va_arg(args, size_t);
        data[i].base = va_arg(args, const void *);
    }

    va_end(args);

    return ccdrbg_df_derive_keys(drbg_ctx->custom.df_ctx,
                                 ndata,
                                 data,
                                 DRBG_CTR_SEEDLEN(drbg_ctx),
                                 out);
}

// make sure drbg is initialized, before calling this function
static int
validate_inputs(struct ccdrbg_nistctr_state *drbg_ctx, size_t entropy_nbytes, size_t additionalInput_nbytes, size_t ps_nbytes)
{
    int err = CCDRBG_STATUS_PARAM_ERROR;

    // NIST SP800 compliance checks
    if (drbg_ctx->custom.df_ctx) {
        cc_require(ps_nbytes <= CCDRBG_MAX_PSINPUT_SIZE, out);                      // personalization string too long
        cc_require(entropy_nbytes <= CCDRBG_MAX_ENTROPY_SIZE, out);                 // supplied too much entropy
        cc_require(additionalInput_nbytes <= CCDRBG_MAX_ADDITIONALINPUT_SIZE, out); // additional input too long
        cc_require(entropy_nbytes >= drbg_ctx->custom.ctr_info->ecb_block_size, out);          // supplied too litle entropy
    } else {
        size_t seedlen = DRBG_CTR_SEEDLEN(drbg_ctx); // blocklen + keylen

        cc_require(ps_nbytes <= seedlen, out);              // personalization string too long
        cc_require(entropy_nbytes == seedlen, out);         // supplied too much or too little entropy
        cc_require(additionalInput_nbytes <= seedlen, out); // additional input too long
    }

    err = CCDRBG_STATUS_OK;
out:
    return err;
}

/*
 * NIST SP 800-90 March 2007
 * 10.2.1.4.2 The Process Steps for Reseeding When a Derivation
 *            Function is Used
 */
static int
reseed(struct ccdrbg_state *ctx, size_t entropy_nbytes, const void *entropy, size_t additional_nbytes, const void *additional)
{
    int err;
    struct ccdrbg_nistctr_state *drbg_ctx = (struct ccdrbg_nistctr_state *)ctx;
    uint8_t seed_material[DRBG_CTR_MAX_SEEDLEN];

    err = validate_inputs(drbg_ctx, entropy_nbytes, additional_nbytes, 0);
    if (err != CCDRBG_STATUS_OK) {
        return err;
    }

    if (drbg_ctx->custom.df_ctx) {
        /* [1] seed_material = entropy || additional */
        /* [2] seed_material = Block_Cipher_df(seed_material, seedlen) */
        err = derive(drbg_ctx, seed_material, 2, entropy_nbytes, entropy, additional_nbytes, additional);
        cc_require(err == CCERR_OK, out);
    } else {
        cc_memcpy(seed_material, entropy, entropy_nbytes);
        cc_xor(additional_nbytes, seed_material, seed_material, additional);
    }

    /* [3] (Key, V) = Update(seed_material, Key, V) */
    update(drbg_ctx, seed_material);

    /* [4] reseed_counter = 1 */
    drbg_ctx->reseed_counter = 1;

    err = CCERR_OK;

 out:
    cc_clear(DRBG_CTR_SEEDLEN(drbg_ctx), seed_material);
    return err;
}

static void done(struct ccdrbg_state *ctx)
{
    struct ccdrbg_nistctr_state *drbg_ctx = (struct ccdrbg_nistctr_state *)ctx;
    cc_clear(sizeof(drbg_ctx->Key), drbg_ctx->Key);
    cc_clear(sizeof(drbg_ctx->V), drbg_ctx->V);

    drbg_ctx->reseed_counter = UINT64_MAX;
}

static bool
must_reseed(const struct ccdrbg_state *ctx)
{
    const struct ccdrbg_nistctr_state *drbg_ctx = (const struct ccdrbg_nistctr_state *)ctx;

    return (drbg_ctx->custom.strictFIPS &&
            (drbg_ctx->reseed_counter > CCDRBG_RESEED_INTERVAL));
}

static int generate(struct ccdrbg_state *ctx, size_t out_nbytes, void *out, size_t additional_nbytes, const void *additional)
{
    int err = CCDRBG_STATUS_OK;
    uint8_t *out_bytes;
    size_t nbytes;
    struct ccdrbg_nistctr_state *drbg_ctx = (struct ccdrbg_nistctr_state *)ctx;
    uint8_t additional_buffer[DRBG_CTR_MAX_SEEDLEN];
    uint8_t remainder[DRBG_CTR_MAX_BLOCKLEN];
    size_t remainder_nbytes;

    ccctr_ctx_decl(ccctr_context_size(drbg_ctx->custom.ctr_info), ctr_ctx);

    // Zero-size requests are valid.
    err = CCDRBG_STATUS_PARAM_ERROR;
    cc_require(out_nbytes <= CCDRBG_MAX_REQUEST_SIZE, out);

    // [1] If (reseed_counter > 2^^48), then Return (“Reseed required”, Null, V, Key, reseed_counter).
    err = CCDRBG_STATUS_NEED_RESEED;
    cc_static_assert(sizeof(drbg_ctx->reseed_counter) >= 8, "Reseed counter must be uint64");
    cc_require(!must_reseed((struct ccdrbg_state *)drbg_ctx), out);

    // [2] If (additional_input != Null), then
    if (additional_nbytes > 0) {
        err = CCDRBG_STATUS_PARAM_ERROR;

        if (drbg_ctx->custom.df_ctx) {
            cc_require(additional_nbytes <= CCDRBG_MAX_ADDITIONALINPUT_SIZE, out);
            // [2.1] additional = Block_Cipher_df(additional, seedlen)
            err = derive(drbg_ctx, additional_buffer, 1, additional_nbytes, additional);
            cc_require(err == CCDRBG_STATUS_OK, out);
        } else {
            cc_require(additional_nbytes <= DRBG_CTR_SEEDLEN(drbg_ctx), out);
            cc_clear(sizeof(additional_buffer), additional_buffer);
            cc_memcpy(additional_buffer, additional, additional_nbytes);
        }

        // [2.2] (Key, V) = Update(additional, Key, V)
        update(drbg_ctx, additional_buffer);
    }

    init_ctr(drbg_ctx, ctr_ctx);

    // [3]-[5]
    out_bytes = out;
    remainder_nbytes = -out_nbytes % DRBG_CTR_BLOCKLEN(drbg_ctx);
    while (out_nbytes > 0) {
        nbytes = CC_MIN(sizeof(zeros), out_nbytes);
        ccctr_update(drbg_ctx->custom.ctr_info, ctr_ctx, nbytes, zeros, out_bytes);
        out_nbytes -= nbytes;
        out_bytes += nbytes;
    }

    // Need to discard the remainder of the block, if any, so the
    // Update() routine can start with a fresh block.
    ccctr_update(drbg_ctx->custom.ctr_info, ctr_ctx, remainder_nbytes, zeros, remainder);
    cc_clear(remainder_nbytes, remainder);

    // [6] (Key, V) = Update(additional, Key, V)
    update_with_ctr(drbg_ctx, ctr_ctx, (additional_nbytes > 0 ? additional_buffer : zeros));
    ccctr_ctx_clear(ccctr_context_size(drbg_ctx->custom.ctr_info), ctr_ctx);

    // [7] reseed_counter = reseed_counter + 1
    drbg_ctx->reseed_counter += 1;

    err = CCDRBG_STATUS_OK;

 out:
    cc_clear(sizeof(additional_buffer), additional_buffer);
    return err;
}

/*
 * NIST SP 800-90 March 2007
 * 10.2.1.3.2 The Process Steps for Instantiation When a Derivation
 *            Function is Used
 */

// length of input personalization string ps might be zero
// nonce is not validated, caller needs to make sure nonce is right as per NIST 800-90A section 8.6.7
static int init(const struct ccdrbg_info *info,
                struct ccdrbg_state *ctx,
                size_t entropy_nbytes,
                const void *entropy,
                size_t nonce_nbytes,
                const void *nonce,
                size_t ps_nbytes,
                const void *ps)
{
    int err;
    struct ccdrbg_nistctr_state *drbg_ctx = (struct ccdrbg_nistctr_state *)ctx;
    const struct ccdrbg_nistctr_custom *custom = info->custom;

    cc_clear(sizeof(*drbg_ctx), drbg_ctx);

    drbg_ctx->custom.ctr_info = custom->ctr_info;
    drbg_ctx->custom.keylen = custom->keylen;
    drbg_ctx->custom.strictFIPS = custom->strictFIPS;
    drbg_ctx->custom.df_ctx = custom->df_ctx;

    if (drbg_ctx->custom.keylen > DRBG_CTR_MAX_KEYLEN) {
        cc_try_abort("ccdrbg_nistctr: key length too long");
        return CCDRBG_STATUS_PARAM_ERROR;
    }

    if (drbg_ctx->custom.ctr_info->ecb_block_size != CCAES_BLOCK_SIZE) {
        cc_try_abort("ccdrbg_nistctr: invalid block size");
        return CCDRBG_STATUS_PARAM_ERROR;
    }

    // nonce is not checked, caller needs to make sure nonce is right
    // as per NIST 800-90A section 8.6.7
    err = validate_inputs(drbg_ctx, entropy_nbytes, 0, ps_nbytes);
    cc_require(err == CCERR_OK, out);

    uint8_t seed_material[DRBG_CTR_MAX_SEEDLEN];

    if (drbg_ctx->custom.df_ctx) {
        /* [1] seed_material = entropy || nonce || ps */
        /* [2] seed_material = Block_Cipher_df(seed_material, seedlen) */
        err = derive(drbg_ctx, seed_material, 3,
                     entropy_nbytes, entropy,
                     nonce_nbytes, nonce,
                     ps_nbytes, ps);
        cc_require(err == CCERR_OK, out);
    } else {
        cc_memcpy(seed_material, entropy, entropy_nbytes);
        cc_xor(ps_nbytes, seed_material, seed_material, ps);
    }

    /* [3] Key = 0^keylen */
    cc_clear(DRBG_CTR_KEYLEN(drbg_ctx), drbg_ctx->Key);
    /* [4] V = 0^blocklen */
    cc_clear(DRBG_CTR_BLOCKLEN(drbg_ctx), drbg_ctx->V);

    /* [5] (Key, V) = Update(seed_material, Key, V) */
    update(drbg_ctx, seed_material);

    /* [6] reseed_counter = 1 */
    drbg_ctx->reseed_counter = 1;

 out:
    if (err) {
        done((struct ccdrbg_state *)drbg_ctx);
    }
    cc_clear(sizeof(seed_material), seed_material);
    return err;
}

/* This initialize an info object with the right options */
void ccdrbg_factory_nistctr(struct ccdrbg_info *info, const struct ccdrbg_nistctr_custom *custom)
{
    CC_ENSURE_DIT_ENABLED

    info->size = sizeof(struct ccdrbg_nistctr_state);
    info->init = init;
    info->generate = generate;
    info->reseed = reseed;
    info->done = done;
    info->custom = custom;
    info->must_reseed = must_reseed;
};

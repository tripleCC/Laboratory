/* Copyright (c) (2011,2013-2016,2019-2023) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/ccrsa_priv.h>
#include <corecrypto/ccsha2.h>
#include <corecrypto/ccdigest.h>
#include <corecrypto/ccdrbg.h>
#include "ccdrbg_internal.h"
#include <corecrypto/ccrng.h>
#include <corecrypto/ccrng_drbg.h>
#include "ccrsa_internal.h"
#include "cc_workspaces.h"
#include "cc_macros.h"

/*!
  @function ccrsa_xor_varlen
  @abstract Constant-time, variable-length, conditional XOR function

  @param dst_size Size of the destination buffer
  @param dst Pointer to the destination buffer
  @param cond A conditional value (MUST be 1 or 0); performs the XOR iff 1
  @param src_size Size of the source buffer
  @param src_off Offset into the source buffer
  @param src Pointer to the source buffer

  @discussion The conditional value must be 0 or 1. If it is 0, do
  nothing. If it is 1, copy the source buffer into the destination
  buffer starting from the source offset. The sizes of the two buffers
  needn't match. The running time of this function depends on the
  sizes of the two buffers, but it does not depend on the condition or
  on the offset.
 */
static void
ccrsa_xor_varlen(size_t *dst_size, void *dst,
                 unsigned cond,
                 size_t src_size, size_t src_off, const void *src)
{
    cc_assert((~1U & cond) == 0);

    uint8_t mask = (uint8_t)~(cond - 1);

    uint8_t *d = dst;
    const uint8_t *s = src;
    size_t off = src_off;

    for (size_t i = 0; i < *dst_size; i += 1) {
        uint8_t k = 0;

        for (size_t j = 0; j < src_size; j += 1) {
            uint8_t b = s[j];
            uint8_t m;
            CC_HEAVISIDE_STEP(m, j - off);
            m = (uint8_t)(m - 1);
            k ^= mask & m & b;
        }

        d[i] ^= k;
        off += 1;
    }

    CC_MUXU(*dst_size, (size_t)cond, src_size - src_off, *dst_size);
}

/*!
  @function ccrsa_mux_varlen
  @abstract Constant-time, variable-length, multiplexer

  @param dst_size Size of the destination buffer
  @param dst Pointer to the destination buffer
  @param cond A conditional value to select the source (MUST be 1 or 0)
  @param src1_size Size of the first source buffer
  @param src1_off Offset into the first source buffer
  @param src1 Pointer to the first source buffer
  @param src0_size Size of the second source buffer
  @param src0_off Offset into the second source buffer
  @param src0 Pointer to the second source buffer

  @discussion Copy one of the two source buffers into the destination
  depending on the condition. If it is 1, select the first source
  buffer; if it is 0, select the second source buffer. The condition
  must be 0 or 1. The sizes of the buffers needn't match. The running
  time of this function depends on the sizes of the buffers, but it
  does not depend on the condition or on the offsets.
 */
static void
ccrsa_mux_varlen(size_t *dst_size, void *dst,
                 unsigned cond,
                 size_t src1_size, size_t src1_off, const void *src1,
                 size_t src0_size, size_t src0_off, const void *src0)
{
    cc_assert((~1U & cond) == 0);

    cc_clear(*dst_size, dst);

    size_t tmp1_size = *dst_size;
    ccrsa_xor_varlen(&tmp1_size, dst,
                     cond,
                     src1_size, src1_off, src1);

    size_t tmp0_size = *dst_size;
    ccrsa_xor_varlen(&tmp0_size, dst,
                     cond ^ 1,
                     src0_size, src0_off, src0);

    CC_MUXU(*dst_size, cond, tmp1_size, tmp0_size);

    cc_clear(sizeof(tmp1_size), &tmp1_size);
    cc_clear(sizeof(tmp0_size), &tmp0_size);
}

/*
 The s_size argument is really meant to be a size_t rather than a cc_size.  It's the size
 in bytes of the key for which this decoding is being done.  's' on the other hand is a
 cc_unit array large enough to contain the blocksize of the key.  We need to start the
 decoding "right justified" within s for s_size bytes.
 */

static int
ccrsa_eme_pkcs1v15_decode_generate_random(ccrsa_full_ctx_t key,
                                          size_t block_nbytes, const void *block,
                                          size_t rand_nbytes, void *rand,
                                          size_t *rand_offset)
{
    struct ccdrbg_info drbg_info;
    struct ccdrbg_nisthmac_custom drbg_custom = {
        .di = ccsha256_di(),
        .strictFIPS = 0,
    };
    ccdrbg_factory_nisthmac(&drbg_info, &drbg_custom);

    uint8_t entropy[CCSHA256_OUTPUT_SIZE] = { 0 };
    uint8_t nonce[CCSHA256_OUTPUT_SIZE];
    const char ps[] = "ccrsa_eme_pkcs1v15_decode_generate_random";

    // Hash the key and the attacker-controlled block separately to
    // alleviate concerns of side-channel interactions in the
    // compression function.

    if (key) {
        ccdigest(ccsha256_di(),
                 ccn_sizeof_n(ccrsa_ctx_n(key)),
                 ccrsa_ctx_d(key),
                 entropy);
    }

    ccdigest(ccsha256_di(), block_nbytes, block, nonce);

    struct ccdrbg_nisthmac_state drbg_state;
    struct ccdrbg_state *drbg = (struct ccdrbg_state *)&drbg_state;
    int err = ccdrbg_init(&drbg_info, drbg,
                          sizeof(entropy), entropy,
                          sizeof(nonce), nonce,
                          sizeof(ps) - 1, ps);
    cc_require(err == CCERR_OK, out);

    struct ccrng_drbg_state rng_drbg;
    struct ccrng_state *rng = (struct ccrng_state *)&rng_drbg;
    err = ccrng_drbg_init_withdrbg(&rng_drbg, &drbg_info, drbg);
    cc_require(err == CCERR_OK, out);

    err = ccrng_generate(rng, rand_nbytes, rand);
    cc_require(err == CCERR_OK, out);

    uint64_t rand_off64;
    err = ccrng_uniform(rng, rand_nbytes + 1, &rand_off64);
    cc_require(err == CCERR_OK, out);

    *rand_offset = (size_t)rand_off64;

 out:
    cc_clear(sizeof(entropy), entropy);
    cc_clear(sizeof(nonce), nonce);
    cc_clear(sizeof(rand_off64), &rand_off64);
    ccdrbg_done(&drbg_info, drbg);
    if (err != CCERR_OK) {
        cc_clear(rand_nbytes, rand);
        cc_clear(sizeof(*rand_offset), rand_offset);
    }
    return err;
}

int ccrsa_eme_pkcs1v15_decode_safe_ws(cc_ws_t ws,
                                      ccrsa_full_ctx_t key,
                                      size_t *r_size, uint8_t *r,
                                      size_t s_size, cc_unit *s)
{
    if ((*r_size < s_size) ||
        (s_size < 11)) {
        return CCRSA_INVALID_INPUT;
    }

    CC_DECL_BP_WS(ws, bp);

    cc_size n = ccrsa_n_from_size(s_size);
    ccn_swap(n, s);

    uint8_t *in = ccrsa_block_start(s_size, s, 0);
    size_t inlen = s_size;

    size_t rand_size = s_size - 11;
    void *rand = CC_ALLOC_WS(ws, n);
    size_t rand_offset;

    int retval = ccrsa_eme_pkcs1v15_decode_generate_random(key,
                                                           inlen, in,
                                                           rand_size, rand,
                                                           &rand_offset);
    cc_require(retval == CCERR_OK, out);

    unsigned decoding_failure = 0;

    // Expected structure is
    // 00:02:PS:00:Msg

    // -- Check for expected prefix 00:02
    CC_HEAVISIDE_STEP(decoding_failure, in[0] | (in[1] ^ 0x02));

    size_t zero_idx = 0;
    uint8_t looking_for_zero = 1;

    // Encoding must be PS || 0x00 || M.
    // Find the position of the 0x00 marker in constant-time.
    for (size_t i = 2; i < inlen; i++) {
        uint8_t is_not_zero;
        CC_HEAVISIDE_STEP(is_not_zero, in[i]);

        // Update zero_idx until we hit 0x00.
        CC_MUXU(zero_idx, looking_for_zero, i, zero_idx);

        looking_for_zero &= is_not_zero;
    }

    // Fail if we found no 0x00 marker.
    decoding_failure |= looking_for_zero;

    // Compute the padding length
    size_t mlen = inlen - zero_idx - 1;
    size_t padlen = inlen - mlen - 3;

    // -- Check (padlen < 8)
    uint8_t is_gt7;
    CC_HEAVISIDE_STEP(is_gt7, padlen >> 3);
    decoding_failure |= is_gt7 ^ 1;

    ccrsa_mux_varlen(r_size, r,
                     decoding_failure,
                     rand_size, rand_offset, rand,
                     inlen, zero_idx + 1, in);

 out:
    // Revert to the original formatting.
    ccn_swap(n, s);

    cc_clear(sizeof(rand_offset), &rand_offset);
    cc_clear(sizeof(decoding_failure), &decoding_failure);
    cc_clear(sizeof(zero_idx), &zero_idx);
    cc_clear(sizeof(looking_for_zero), &looking_for_zero);
    cc_clear(sizeof(mlen), &mlen);
    cc_clear(sizeof(padlen), &padlen);

    CC_FREE_BP_WS(ws, bp);

    return retval;
}

int ccrsa_eme_pkcs1v15_decode_safe(ccrsa_full_ctx_t key,
                                   size_t *r_size, uint8_t *r,
                                   size_t s_size, cc_unit *s)
{
    CC_ENSURE_DIT_ENABLED

    CC_DECL_WORKSPACE_OR_FAIL(ws, CCRSA_EME_PKCS1V15_DECODE_SAFE_WORKSPACE_N(ccrsa_ctx_n(key)));
    int rv = ccrsa_eme_pkcs1v15_decode_safe_ws(ws, key, r_size, r, s_size, s);
    CC_FREE_WORKSPACE(ws);
    return rv;
}

int ccrsa_eme_pkcs1v15_decode(size_t *r_size, uint8_t *r,
                              size_t s_size, cc_unit *s)
{
    CC_ENSURE_DIT_ENABLED

    cc_size n = ccrsa_n_from_size(s_size);

    CC_DECL_WORKSPACE_OR_FAIL(ws, CCRSA_EME_PKCS1V15_DECODE_SAFE_WORKSPACE_N(n));
    int rv = ccrsa_eme_pkcs1v15_decode_safe_ws(ws, NULL, r_size, r, s_size, s);
    CC_FREE_WORKSPACE(ws);
    return rv;

}

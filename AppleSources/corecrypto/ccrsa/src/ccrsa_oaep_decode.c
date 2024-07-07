/* Copyright (c) (2011-2016,2018-2022) Apple Inc. All rights reserved.
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
#include <corecrypto/ccrng.h>
#include "ccrsa_internal.h"

/*
 The s_size argument is really meant to be a size_t rather than a cc_size.  It's the size
 in bytes of the key for which this decoding is being done.  's' on the other hand is a
 cc_unit array large enough to contain the blocksize of the key.  We need to start the
 decoding "right justified" within s for s_size bytes.

 written from PKCS #1 v2.2
 */

int ccrsa_oaep_decode_parameter_ws(cc_ws_t ws,
                                   const struct ccdigest_info* di,
                                   size_t *r_len, uint8_t *r,
                                   size_t s_size, cc_unit* s,
                                   size_t parameter_data_len,
                                   const uint8_t *parameter_data)
{
    size_t encoded_len = s_size - 1;
    size_t  DB_len = encoded_len - di->output_size;
    cc_size n = ccn_nof_size(DB_len);

    volatile int retval = CCERR_OK;

    ccn_swap(ccrsa_n_from_size(s_size), s);
    uint8_t *encoded = ccrsa_block_start(s_size, s, 0);

    // Independent of the content of s so ok to early abort.
    if (encoded_len < 2 * di->output_size + 1) {
        return CCRSA_INVALID_CONFIG;
    }

    CC_DECL_BP_WS(ws, bp);
    cc_unit *DB = CC_ALLOC_WS(ws, n);
    cc_unit *dbMask = CC_ALLOC_WS(ws, n);

    // a) Hash the label
    uint8_t lHash[MAX_DIGEST_OUTPUT_SIZE];
    ccdigest(di, parameter_data_len, parameter_data, lHash);

    // b) Encoded message is broken down into:
    // EM = Y || maskedSeed || maskedDB

    // Make a local copy in buffer aligned on cc_unit for the verification
    cc_unit seed[ccn_nof_size(MAX_DIGEST_OUTPUT_SIZE)];
    cc_memcpy(seed, &encoded[1], di->output_size);
    cc_memcpy(DB, &encoded[1+di->output_size], DB_len);

    // c) seedMask = MGF(maskedDB,hLen);
    cc_unit seedMask[ccn_nof_size(MAX_DIGEST_OUTPUT_SIZE)];
    ccmgf(di, di->output_size, seedMask, DB_len, DB);

    // d) seed = maskedSeed XOR seedMask
    ccn_xor(ccn_nof_size(di->output_size), seed, seed, seedMask);

    // e) dbMask = MGF(seed,k-hLen - 1);
    ccmgf(di, DB_len, dbMask, di->output_size, seed);

    // f) DB = maskedDB XOR dbMask
    ccn_xor(ccn_nof_size(DB_len), DB, DB, dbMask);

    // g) Separate DB into an octet string
    // DB = lHash' || PS || 0x01 || M

    // Y == 0 ?
    CC_HEAVISIDE_STEP(retval, encoded[0]);

    // lHash == lHash' ?
    retval |= cc_cmp_safe(di->output_size, lHash, DB);

    size_t one_idx = 0;
    uint8_t looking_for_one = 1;
    uint8_t *ptr = (uint8_t *)DB;

    // Padding must be PS(0*) || 0x01 || M.
    // Find the position of the 0x01 marker in constant-time.
    for (size_t i = di->output_size; i < DB_len; i++) {
        uint8_t is_not_zero, is_not_one;
        CC_HEAVISIDE_STEP(is_not_zero, ptr[i]);
        CC_HEAVISIDE_STEP(is_not_one, ptr[i] ^ 0x01);

        // Update one_idx until we hit the first 0x01.
        CC_MUXU(one_idx, looking_for_one, i, one_idx);

        looking_for_one &= is_not_one;

        // Fail if there's a non-zero byte before the 0x01 marker.
        retval |= looking_for_one & is_not_zero;
    }

    // Fail if we found no 0x01 marker.
    retval |= looking_for_one;

    if (retval) {
        goto decode_err;
    }

    size_t mlen = DB_len - one_idx - 1;
    if (*r_len < mlen) {
        retval = CCRSA_INVALID_INPUT;
        goto param_err;
    }

    cc_memcpy(r, ptr + one_idx + 1, mlen);
    *r_len = mlen;

decode_err:
    if (retval) {
        retval = CCRSA_PRIVATE_OP_ERROR;
    }

param_err:
    cc_clear(sizeof(lHash), lHash);
    cc_clear(sizeof(seed), seed);
    cc_clear(sizeof(seedMask), seedMask);

    CC_FREE_BP_WS(ws, bp);
    return retval;
}

int ccrsa_oaep_decode_parameter(const struct ccdigest_info* di,
                                size_t *r_len, uint8_t *r,
                                size_t s_size, cc_unit* s,
                                size_t parameter_data_len,
                                const uint8_t *parameter_data)
{
    CC_ENSURE_DIT_ENABLED

    size_t DB_len = s_size - 1 - di->output_size;
    CC_DECL_WORKSPACE_OR_FAIL(ws, CCRSA_OAEP_DECODE_PARAMETER_WORKSPACE_N(ccn_nof_size(DB_len)));
    int rv = ccrsa_oaep_decode_parameter_ws(ws, di, r_len, r, s_size, s, parameter_data_len, parameter_data);
    CC_FREE_WORKSPACE(ws);
    return rv;
}

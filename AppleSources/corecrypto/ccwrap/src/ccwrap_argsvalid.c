/* Copyright (c) (2018,2019,2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "ccwrap_internal.h"

bool ccwrap_argsvalid(const struct ccmode_ecb *ecb,
                      size_t pbytes,
                      size_t cbytes)
{
    size_t n;

    // keywrap only implemented for 128-bit blocks
    if (ecb->block_size != CCWRAP_SEMIBLOCK * 2) {
        return false;
    }

    // valid plaintexts are two or more semiblocks
    // P[1], ..., P[n]

    // valid ciphertexts are three or more semiblocks
    // C[0], C[1], ..., C[n]
    // with IV = C[0]

    // ciphertext is one semiblock longer than plaintext

    if (pbytes % CCWRAP_SEMIBLOCK != 0) {
        return false;
    }

    if (cbytes % CCWRAP_SEMIBLOCK != 0) {
        return false;
    }

    if (pbytes + CCWRAP_SEMIBLOCK != cbytes) {
        return false;
    }

    // validate plaintext length explicitly
    // and ciphertext length implicitly

    n = pbytes / CCWRAP_SEMIBLOCK;

    if (n < 2) {
        return false;
    }

    if (n >= CCWRAP_MAXSEMIBLOCKS) {
        return false;
    }

    return true;
}

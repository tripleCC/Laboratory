/* Copyright (c) (2010,2011,2015,2018,2019,2021) Apple Inc. All rights reserved.
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
#include "ccn_internal.h"

size_t ccn_write_uint_size(cc_size n, const cc_unit *s)
{
    CC_ENSURE_DIT_ENABLED

    return CC_BITLEN_TO_BYTELEN(ccn_bitlen(n, s));
}

/* Write a big integer as big endian in byte buffer.
 It requires the output buffer to be big enough for the big integer
 Execution time depends on input sizes, not on values
 */
int ccn_write_uint_padded_ct(cc_size n, const cc_unit *s, size_t out_size, uint8_t *to)
{
    CC_ENSURE_DIT_ENABLED

    int offset = 0;
    cc_size i;
    if (out_size >= __INT_MAX__ || ccn_sizeof_n(n) >= __INT_MAX__) {
        return CCERR_PARAMETER;
    }

    if (out_size > ccn_sizeof_n(n)) { // Extra zeroes
        size_t leading_zeros = out_size - ccn_sizeof_n(n);
        cc_clear(leading_zeros, to);
        to += leading_zeros;
        out_size -= leading_zeros;
        offset += leading_zeros;
    }
    if (out_size >= ccn_write_uint_size(n, s)) { // Make sure the full big integer can fit
        offset += (out_size - ccn_write_uint_size(n, s));
        to += out_size;
        for (i = 0; out_size >= CCN_UNIT_SIZE; i++) {
            to -= CCN_UNIT_SIZE;
            CC_STORE_UNIT_BE(s[i], to);
            out_size -= CCN_UNIT_SIZE;
        }
        // Most significant cc_unit
        if (out_size) {
            cc_unit v = s[i];
            for (size_t j = 0; j < out_size; j++) {
                *--to = (uint8_t)v;
                v >>= 8;
            }
        }
    } else {
        // Does not fit
        offset = CCERR_PARAMETER;
    }
    return offset;
}

/* Emit bytes starting at the far end of the outgoing byte
   stream, which is the l.s. byte of giant data. In order to prevent
   writing out leading zeros, we special case the m.s. digit. */
void ccn_write_uint(cc_size n, const cc_unit *s, size_t out_size, void *out)
{
    CC_ENSURE_DIT_ENABLED

    cc_unit v;
    uint8_t *ix = out;

    size_t s_size = ccn_write_uint_size(n, s);
    if (out_size > s_size) {
        out_size = s_size;
    }

    /* Start at the end. */
    ix += out_size;
    cc_size i = (s_size - out_size) >> (CCN_LOG2_BITS_PER_UNIT - 3); // divide by CCN_UNIT_SIZE;
    cc_size j = (s_size - out_size) & (CCN_UNIT_SIZE - 1);           // % CCN_UNIT_SIZE

    v = s[i] >> j * 8;
    while (out_size >= CCN_UNIT_SIZE) {
        /* one loop per unit */
        /* j is the byte index in the cc_unit, it starts at 0 excepts for the first execution of the loop */
        out_size -= (CCN_UNIT_SIZE - j);
        for (; j < CCN_UNIT_SIZE; ++j) {
            /* one loop per byte in v */
            *--ix = (uint8_t)v;
            v >>= 8;
        }
        j = 0;
        if ((i+1) < n) {v = s[++i];}
    }

    /* Handle the m.s. cc_unit, by writing out only as many bytes as are left.
       Since we already wrote out i units above the answer is (use i instead
       of n - 1 here to properly handle the case where n == 0. */
    for (; out_size > 0; --out_size) {
        /* One loop per byte in the last unit v */
        *--ix = (uint8_t)v;
        v >>= 8;
    }
}

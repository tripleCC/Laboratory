/* Copyright (c) (2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/ccn.h>

void ccn_set_bit(cc_unit *cc_indexable x, size_t k, cc_unit v)
{
    if (v) {
        x[k >> CCN_LOG2_BITS_PER_UNIT] |= (cc_unit)1 << (k & (CCN_UNIT_BITS - 1));
    } else {
        x[k >> CCN_LOG2_BITS_PER_UNIT] &= ~((cc_unit)1 << (k & (CCN_UNIT_BITS - 1)));
    }
}

size_t ccn_write_uint_padded(cc_size n, const cc_unit *cc_counted_by(n) s, size_t out_size, uint8_t *cc_sized_by(out_size) out)
{
    size_t offset = 0;
    // Try first the non-truncation case
    int offset_int = ccn_write_uint_padded_ct(n, s, out_size, out);
    if (offset_int >= 0) {
        // It worked
        offset = (size_t)offset_int;
    } else {
        // Truncation case, execution depends on the position of the MSByte
        ccn_write_uint(n, s, out_size, out);
    }
    return offset;
}

void ccn_zero(cc_size n, cc_unit *cc_sized_by(n) r) {
    cc_clear(ccn_sizeof_n(n),r);
}

void ccn_seti(cc_size n, cc_unit *cc_counted_by(n) r, cc_unit v) {
    assert(n > 0);
    r[0] = v;
    ccn_zero(n - 1, r + 1);
}

void ccn_swap(cc_size n, cc_unit *cc_counted_by(n) r) {
    cc_unit *local_r = r;
    cc_unit *e;
    for (e = local_r + n - 1; local_r < e; ++local_r, --e) {
        cc_unit t = CC_UNIT_TO_BIG(*local_r);
        *local_r = CC_UNIT_TO_BIG(*e);
        *e = t;
    }
    if (n & 1)
        *local_r = CC_UNIT_TO_BIG(*local_r);
}

void ccn_xor(cc_size n, cc_unit *cc_counted_by(n) r, const cc_unit *cc_counted_by(n) s, const cc_unit *cc_counted_by(n) t) {
    cc_size _n = n;
    while (_n--) {
        r[_n] = s[_n] ^ t[_n];
    }
}

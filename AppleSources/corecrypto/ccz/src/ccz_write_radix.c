/* Copyright (c) (2012-2015,2017-2019,2021,2022) Apple Inc. All rights reserved.
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
#include <corecrypto/ccz_priv.h>
#include "ccn_internal.h"

static const uint8_t DIGITS[] = {'0', '1', '2', '3', '4', '5', '6', '7',
                                 '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};

// Computes t := t / 10 and returns the remainder.
CC_WARN_RESULT CC_NONNULL_ALL
static cc_unit ccn_divmod10(ccz *t)
{
    // t < 10 => t % 10 = t
    if (ccz_cmpi(t, 10) < 0) {
        cc_unit r = t->u[0];
        ccz_zero(t);
        return r;
    }

    ccz tr, tt;
    ccz_init(t->isa, &tr);
    ccz_init(t->isa, &tt);

    // Normalize the divisor.
    size_t k = ccz_bitlen(t) - 4;

    ccz_set(&tr, t);
    ccz_zero(t);

    ccz_seti(&tt, 10);
    ccz_lsl(&tt, &tt, k);

    for (size_t b = 0; b <= k; b += 1) {
        if (ccz_cmp(&tr, &tt) >= 0) {
            ccz_sub(&tr, &tr, &tt);
            ccz_set_bit(t, k - b, 1);
        }

        ccz_lsr(&tt, &tt, 1);
    }

    ccz_set_n(t, ccn_n(ccz_n(t), t->u));

    cc_unit r = tr.u[0];
    ccz_free(&tr);
    ccz_free(&tt);

    return r;
}

/*! @function ccz_write_radix_10
 @abstract Writes the number `s` to `out` in decimal form.

 @discussion Pass `out_nbytes=0` and `out=NULL` if you only want to determine
             the required size of the output buffer.

 @param s           ccz instance.
 @param out_nbytes  Length of the output buffer.
 @param out         Output buffer (optional).

 @return The number of bytes written to `out`, or, if `out=NULL`, the required
         minimum size of the output buffer to write the full decimal form.
 */
CC_WARN_RESULT CC_NONNULL((1))
static size_t ccz_write_radix_10(const ccz *s, size_t out_nbytes, uint8_t *out)
{
    cc_assert((out_nbytes == 0) == (out == NULL));

    ccz t;
    ccz_init(s->isa, &t);

    ccz_set(&t, s);
    ccz_set_n(&t, ccn_n(ccz_n(&t), t.u));

    size_t nbytes = 0;
    uint8_t *r = out + out_nbytes;

    while (!ccz_is_zero(&t) && (!r || out < r)) {
        cc_unit v = ccn_divmod10(&t);
        nbytes += 1;

        if (r) {
            *(--r) = DIGITS[v];
        }
    }

    // Pad remaining space with leading zeros.
    if (r > out) {
        cc_memset(out, '0', out_nbytes - nbytes);
    }

    ccz_free(&t);

    return nbytes;
}

size_t ccz_write_radix_size(const ccz *s, unsigned radix)
{
    CC_ENSURE_DIT_ENABLED

    cc_size n = ccz_n(s);
    size_t sign = ccz_sign(s) < 0 ? 1 : 0;

    // We support (hexa)decimal only.
    if (radix != 10 && radix != 16) {
        return 0;
    }

    if (ccz_is_zero(s)) {
        return 1;
    }

    if (radix == 16) {
        return cc_ceiling(ccn_bitlen(n, s->u), 4) + sign;
    }

    return ccz_write_radix_10(s, 0, NULL) + sign;
}

/*! @function ccz_write_radix_16
 @abstract Writes the number `s` to `out` in hexadecimal form.

 @param s           ccz instance.
 @param out_nbytes  Length of the output buffer.
 @param out         Output buffer (optional).
 */
CC_NONNULL((1))
static void ccz_write_radix_16(const ccz *s, size_t out_nbytes, uint8_t *out)
{
    size_t nbits = ccn_bitlen(ccz_n(s), s->u);
    size_t nibbles = cc_ceiling(nbits, 4);
    size_t unibbles = CCN_UNIT_SIZE * 2;

    uint8_t *r = out + out_nbytes;

    for (size_t i = 0; i < nibbles && r > out; i += 1) {
        *(--r) = DIGITS[(s->u[i / unibbles] >> ((i % unibbles) * 4)) & 0xf];
    }

    // Pad remaining space with leading zeros.
    if (out_nbytes > nibbles) {
        cc_memset(out, '0', out_nbytes - nibbles);
    }
}

int ccz_write_radix(const ccz *s, size_t out_size, void *out, unsigned radix)
{
    CC_ENSURE_DIT_ENABLED

    if (radix != 10 && radix != 16) {
        return CCZ_INVALID_RADIX_ERROR;
    }

    if (out_size < 1) {
        return CCERR_PARAMETER;
    }

    uint8_t *p = out;
    if (!ccz_is_zero(s) && ccz_sign(s) < 0) {
        // Don't write only the sign.
        if (out_size < 2) {
            return CCERR_PARAMETER;
        }

        *(p++) = '-';
        out_size -= 1;
    }

    if (radix == 10) {
        (void)ccz_write_radix_10(s, out_size, p);
    } else {
        ccz_write_radix_16(s, out_size, p);
    }

    return CCERR_OK;
}

/* Copyright (c) (2012,2015,2017-2021) Apple Inc. All rights reserved.
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

static int ccz_read_radix_10(ccz *r, size_t data_nbytes, const uint8_t *data)
{
    for (size_t i = 0; i < data_nbytes; i += 1) {
        uint8_t ch = *(data++);

        // Check for characters 0-9.
        if (ch < 48 || ch > 57) {
            return CCZ_INVALID_INPUT_ERROR;
        }

        // ignore carry
        (void)ccn_mul1(ccn_nof(4 * i), r->u, r->u, 10);
        ccn_add1(ccn_nof(4 * (i + 1)), r->u, r->u, ch - 48);
    }

    ccz_set_n(r, ccn_n(ccz_n(r), r->u));

    return CCERR_OK;
}

static int ccz_read_radix_16(ccz *r, size_t data_nbytes, const uint8_t *data)
{
    const uint8_t *in = data + data_nbytes;
    size_t unibbles = CCN_UNIT_SIZE * 2;

    for (size_t i = 0; in > data; i += 1) {
        uint8_t ch = *(--in);

        // Convert letters a-f to upper case.
        if (ch >= 97 && ch <= 102) {
            ch &= ~32;
        }

        // Check for characters 0-9 and A-F.
        if (ch < 48 || (ch > 57 && ch < 65) || ch > 70) {
            return CCZ_INVALID_INPUT_ERROR;
        }

        // Convert characters 0-9 or A-F to nibbles.
        if (ch <= 57) {
            ch = ch - 48;
        } else {
            ch = 10 + ch - 65;
        }

        r->u[i / unibbles] |= (cc_unit)ch << ((i % unibbles) * 4);
    }

    return CCERR_OK;
}

int ccz_read_radix(ccz *r, size_t data_size, const char *data, unsigned radix)
{
    CC_ENSURE_DIT_ENABLED

    if (radix != 10 && radix != 16) {
        return CCZ_INVALID_RADIX_ERROR;
    }

    if (data_size == 0) {
        return CCERR_PARAMETER;
    }

    int sign = 1;

    // Handle sign.
    if (*data == '-') {
        data++;
        data_size -= 1;
        sign = -1;
    } else if (*data == '+') {
        data++;
        data_size -= 1;
    }

    // We can't parse only the sign.
    if (data_size == 0) {
        return CCERR_PARAMETER;
    }

    // Skip leading zeros.
    while (*data == '0') {
        data_size -= 1;
        data++;
    }

    // Reserve space.
    cc_size n = ccn_nof(data_size * 4);
    ccz_set_capacity(r, n);

    ccz_set_n(r, n);
    ccn_clear(n, r->u);
    ccz_set_sign(r, sign);

    int rv = CCERR_OK;

    if (radix == 10) {
        rv = ccz_read_radix_10(r, data_size, (const uint8_t *)data);
    } else {
        rv = ccz_read_radix_16(r, data_size, (const uint8_t *)data);
    }

    // Avoid negative zeros.
    if (rv == CCERR_OK && ccz_is_zero(r)) {
        ccz_set_sign(r, 1);
    }

    return rv;
}

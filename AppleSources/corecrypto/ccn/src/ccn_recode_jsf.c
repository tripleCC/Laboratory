/* Copyright (c) (2010,2011,2014-2021,2023) Apple Inc. All rights reserved.
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

static const uint8_t F_2_2_11[32] = {
    12, 12, 12, 12,                  // [0, 4>
    14, 14, 14, 14, 14, 14, 14, 14,  // [4, 12>
    12, 12,                          // [12, 14>
    10, 10, 10, 10,                  // [14, 18>
    9, 9, 9, 9,                      // [18, 22>
    11, 11,                          // [22, 24>
    12, 12, 12, 12, 12, 12, 12, 12   // [24, 32>
};

void ccn_recode_jsf_init(struct ccn_rjsf_state *r, size_t nbits, const cc_unit *s, const cc_unit *t)
{
    r->s = s;
    r->t = t;

    const cc_unit* e[2] = { r->s, r->t };

    for (size_t i = 0; i < 2; i += 1) {
        r->u[i] = (uint8_t)((ccn_bit(e[i], nbits - 1) << 3) |
                            (ccn_bit(e[i], nbits - 2) << 2) |
                            (ccn_bit(e[i], nbits - 3) << 1) |
                            (ccn_bit(e[i], nbits - 4) << 0));
    }
}

void ccn_recode_jsf_column(struct ccn_rjsf_state *r, size_t k, int c[2])
{
    uint8_t h[2];

    for (unsigned i = 0; i < 2; i += 1) {
        h[i] = r->u[i] & 0x1f;

        if (r->u[i] & 0x20) {
            h[i] = 31 - h[i];
        }
    }

    const cc_unit* e[2] = { r->s, r->t };

    for (unsigned i = 0; i < 2; i += 1) {
        uint8_t cmask = 0;

        if (k >= 5) {
            cmask = (uint8_t)ccn_bit(e[i], k - 5);
        }

        if (h[i] >= F_2_2_11[h[i ^ 1]]) {
            cmask += 0x20;
            c[i] = r->u[i] & 0x20 ? -1 : 1;
        } else {
            c[i] = 0;
        }

        r->u[i] = (uint8_t)(r->u[i] << 1) ^ cmask;
    }
}

size_t ccn_recode_jsf_index(int c[2])
{
    cc_assert(c[0] != 0 || c[1] != 0);

    // P, Q, or P+Q.
    size_t idx = (size_t)((c[1] & 1) << 1) | (c[0] & 1);

    // P-Q?
    if (c[0] != -c[1]) {
        idx -= 1;
    }

    return idx;
}

int ccn_recode_jsf_direction(int c[2])
{
    cc_assert(c[0] != 0 || c[1] != 0);

    // -P, -Q, -P-Q, or -P+Q?
    if ((c[0] == -1) || (c[0] == 0 && c[1] == -1)) {
        return -1;
    }

    return 1;
}

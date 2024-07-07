/* Copyright (c) (2011,2012,2015,2018,2019,2021) Apple Inc. All rights reserved.
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
#include <corecrypto/ccpad.h>
#include "ccmode_internal.h"

size_t ccpad_xts_decrypt(const struct ccmode_xts *xts, ccxts_ctx *key, ccxts_tweak *tweak,
                       size_t nbytes, const void *in, void *out)
{
    CC_ENSURE_DIT_ENABLED

    const unsigned char *cipher = in;
    unsigned char *plain = out;
    size_t tail = nbytes & 15;
    size_t head = nbytes - tail;

    if (tail) {
        cc_unit *T;
        T=xts->xts(key, tweak, (head >> 4) - 1, cipher, plain);
        uint8_t ctemp[16], ptemp[16];

        /* Store current blocks tweak in ctemp, and advance tweak in context
           to next block. */
        cc_memcpy(ctemp, T, 16);
        ccmode_xts_mult_alpha(T);

        cipher += head - 16;
        plain += head - 16;
        /* ptemp = tweak decrypt block m-1 */
        xts->xts(key, tweak, 1, cipher, ptemp);

        /* Reset tweak in the context to the previous blocks tweak we stored. */
        cc_memcpy(T, ctemp, 16);

        /* Pm = first ptlen % 16 bytes of PP */
        size_t x;
        for (x = 0; x < tail; ++x) {
            ctemp[x] = cipher[16 + x];
            plain[16 + x] = ptemp[x];
        }
        for (; x < 16; ++x) {
            ctemp[x] = ptemp[x];
        }

        /* Pm-1 = Tweak decrypt ctemp */
        xts->xts(key, tweak, 1, ctemp, plain);
    } else {
        xts->xts(key, tweak, head >> 4, cipher, plain);
    }
    return nbytes;
}

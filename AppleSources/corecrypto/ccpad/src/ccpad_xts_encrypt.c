/* Copyright (c) (2011,2012,2015,2019,2021) Apple Inc. All rights reserved.
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

void ccpad_xts_encrypt(const struct ccmode_xts *xts, ccxts_ctx *key, ccxts_tweak *tweak,
                       size_t nbytes, const void *in, void *out) {
    CC_ENSURE_DIT_ENABLED

    const unsigned char *plain = in;
    unsigned char *cipher = out;
    size_t tail = nbytes & 15;
    size_t head = nbytes - tail;

    if (tail) {
        xts->xts(key, tweak, (head >> 4) - 1, plain, cipher);
        cipher += head - 16;
        plain += head - 16;
        uint8_t ctemp[16], ptemp[16];
        /* ctemp = tweak encrypt penultimate block into ctemp. */
        xts->xts(key, tweak, 1, plain, ctemp);
        cipher += 16;
        plain += 16;

        /* Copy tail bytes of ctemp to last block of output, while
           preserving the plaintext in ptemp.  */
        size_t x;
        for (x = 0; x < tail; ++x) {
            ptemp[x] = plain[x];
            cipher[x] = ctemp[x];
        }

        /* Copy last 16 - tail bytes from ctemp into last bytes of ptemp. */
        for (; x < 16; ++x) {
            ptemp[x] = ctemp[x];
        }

        /* Tweak encrypt ptemp into the penultiate block. */
        xts->xts(key, tweak, 1, ptemp, cipher - 16);
    } else {
        xts->xts(key, tweak, head >> 4, plain, cipher);
    }
}

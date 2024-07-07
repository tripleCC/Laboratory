/* Copyright (c) (2013-2019,2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/cc.h>
#include "cccmac_internal.h"

CC_INLINE void cc_bytestring_shift_left(size_t len, void *rv, const void *sv) {
    const uint8_t *s = (const uint8_t *) sv;
    uint8_t *r = (uint8_t *) rv;
    uint8_t c = 0;
    while(len--) {
        uint8_t v = s[len];
        r[len] = (uint8_t)((v << 1) + c);
        c = (v >> 7);
    }
}

/*
     cccmac_sl_test_xor
     is the multiplication of S and 0...010 (x) in the finite field
     represented using the primitive polynomial
     x^128 + x^7 + x^2 + x + 1.

     "2" is the hexadecimal representation of the polynomial "x".
     Therefore the multiplication by "x" is refered as "doubling" in RFC 5297

     The operation on a 128-bit input string is performed using a
     left-shift of the input followed by a conditional xor operation on
     the result with the constant:

     00000000 00000000 00000000 00000087

     The condition under which the xor operation is performed is when the
     bit being shifted off is one.
*/
void cccmac_sl_test_xor(uint8_t *r, const uint8_t *s) {
    uint8_t t;
    uint8_t s0=s[0];
    cc_static_assert(CMAC_BLOCKSIZE == 16, "CMAC_BLOCKSIZE must be 16");
    // Mult
    cc_bytestring_shift_left(16, r, s);
    // Conditional XOR
    t = (s0 & 0x80)>>7;
    t = (0-t) & 0x87;
    r[15] = r[15] ^ t;
}

int cccmac_generate_subkeys(const struct ccmode_cbc *cbc, size_t key_nbytes, const void *key, uint8_t *subkey1, uint8_t *subkey2)
{
    const uint8_t iv[CMAC_BLOCKSIZE] = { 0 };
    uint8_t L[CMAC_BLOCKSIZE] = { 0 };

    int rv;
    if ((rv = cccbc_one_shot(cbc, key_nbytes, key, iv, 1, L, L))) {
        return rv;
    }

    cccmac_sl_test_xor(subkey1, L);
    cccmac_sl_test_xor(subkey2, subkey1);
    cc_clear(CMAC_BLOCKSIZE,L);

    return CCERR_OK;
}

/* Copyright (c) (2021,2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/ccsha1.h>
#include <corecrypto/ccsha2.h>
#include <corecrypto/ccsha3.h>
#include <corecrypto/cchkdf.h>
#include "cc_debug.h"

#include "fipspost.h"
#include "fipspost_priv.h"
#include "fipspost_post_hkdf.h"

#define FIPSPOST_POST_HKDF_DK_NBYTES 32

int fipspost_post_hkdf(CC_UNUSED uint32_t fips_mode)
{
    const struct ccdigest_info *sha1 = ccsha1_di();
    const struct ccdigest_info *sha256 = ccsha256_di();
    const struct ccdigest_info *sha512 = ccsha512_di();

#if !CC_KERNEL
    const struct ccdigest_info *sha3_224 = ccsha3_224_di();
    const struct ccdigest_info *sha3_256 = ccsha3_256_di();
    const struct ccdigest_info *sha3_384 = ccsha3_384_di();
    const struct ccdigest_info *sha3_512 = ccsha3_512_di();
#endif

    uint8_t ikm[32] = { 0 };
    uint8_t salt[16] = { 0 };
    uint8_t info[8] = { 0 };
    uint8_t dk[FIPSPOST_POST_HKDF_DK_NBYTES] = { 0 };

    if (FIPS_MODE_IS_FORCEFAIL(fips_mode)) {
        ikm[0] = 0x01; // Flip a bit
    }

    typedef struct {
        const struct ccdigest_info *digest_info;
        unsigned char *digest_name;
        uint8_t dk[FIPSPOST_POST_HKDF_DK_NBYTES];
    } hkdf_test;

    hkdf_test tests[] = {
        { sha1, (unsigned char *)"sha1", { 0x79, 0x21, 0x9d, 0x02, 0x63, 0x6e, 0xfe, 0xd2, 0xd0, 0xa8, 0x65,
                                           0x2e, 0xee, 0x81, 0x5e, 0x26, 0xf1, 0xfb, 0x50, 0x45, 0x87, 0x2b,
                                           0x31, 0x88, 0x95, 0x46, 0x68, 0xbd, 0x16, 0xbc, 0xee, 0xdf } },
        { sha256, (unsigned char *)"sha256", { 0x9b, 0xb8, 0xd9, 0x4b, 0x81, 0x1c, 0xe4, 0x11, 0x0d, 0x35, 0x81,
                                               0x43, 0x68, 0xb1, 0xbe, 0x5f, 0x63, 0xad, 0x1f, 0x4d, 0xc0, 0xa4,
                                               0x37, 0x2d, 0x1f, 0x3b, 0xdb, 0x16, 0xa8, 0xb9, 0x72, 0xf6 } },
        { sha512, (unsigned char *)"sha512", { 0xb5, 0x0c, 0x08, 0x6f, 0x1b, 0xf8, 0x55, 0x4e, 0x2b, 0x0a, 0x5d,
                                               0xf2, 0x13, 0xbd, 0xbf, 0xad, 0x88, 0x64, 0x15, 0xe3, 0x27, 0x7e,
                                               0xb3, 0xc4, 0x32, 0x56, 0x3d, 0x1b, 0x8f, 0xd4, 0xc7, 0xcb } },
#if !CC_KERNEL
/* # SHA-3
import hkdf
import hashlib
printdigest = lambda s: print("0x" + ", 0x".join(s[i:i+2] for i in range(0, len(s), 2)))
printdigest(hkdf.Hkdf(bytes([0]*16), bytes([0]*32), hash=hashlib.sha3_224).expand(bytes([0]*8), 32).hex())
printdigest(hkdf.Hkdf(bytes([0]*16), bytes([0]*32), hash=hashlib.sha3_256).expand(bytes([0]*8), 32).hex())
printdigest(hkdf.Hkdf(bytes([0]*16), bytes([0]*32), hash=hashlib.sha3_384).expand(bytes([0]*8), 32).hex())
printdigest(hkdf.Hkdf(bytes([0]*16), bytes([0]*32), hash=hashlib.sha3_512).expand(bytes([0]*8), 32).hex())
*/
        { sha3_224, (unsigned char *)"sha3_224", { 0x86, 0xdc, 0xaa, 0x8d, 0xbf, 0xcb, 0xe7, 0xb9, 0x60, 0xc1, 0xf2, 0x7a, 0xde, 0x9d, 0x8e, 0x23, 0x5d, 0xec, 0x97, 0x88, 0xdc, 0x7b, 0xe1, 0x99, 0x57, 0x71, 0x13, 0xb3, 0x40, 0x22, 0x83, 0xb9 } },
        { sha3_256, (unsigned char *)"sha3_256", { 0x23, 0xec, 0x76, 0x2c, 0x43, 0xbc, 0x55, 0x75, 0x76, 0x70, 0x9d, 0xdf, 0xdc, 0x9f, 0x41, 0xaf, 0x80, 0x03, 0xde, 0x98, 0x61, 0xac, 0x58, 0x1d, 0x8a, 0x66, 0x43, 0x55, 0xb6, 0x81, 0x4f, 0xb8 } },
        { sha3_384, (unsigned char *)"sha3_384", { 0x3b, 0x88, 0x64, 0x80, 0x34, 0xe7, 0xfe, 0x5c, 0xa1, 0xac, 0xbc, 0x59, 0xf6, 0x1a, 0xfb, 0x9b, 0xd7, 0x1e, 0xf3, 0xee, 0x60, 0xa8, 0xa7, 0x61, 0x0d, 0xaf, 0x28, 0xf0, 0x74, 0xae, 0x0d, 0x5c } },
        { sha3_512, (unsigned char *)"sha3_512", { 0x28, 0x72, 0x64, 0xfb, 0x98, 0xcc, 0x34, 0xde, 0x47, 0xb3, 0xa1, 0xe8, 0x15, 0x48, 0xe6, 0x29, 0x23, 0x47, 0x0a, 0xa0, 0x79, 0xd9, 0x40, 0x55, 0x56, 0x8f, 0x33, 0x69, 0x51, 0xb4, 0x65, 0x2b } },
#endif
    };

    int status = CCERR_OK;

    for (size_t i = 0; i < sizeof(tests) / sizeof(hkdf_test); i++) {
        hkdf_test *current_test = &(tests[i]);
        cchkdf(current_test->digest_info, sizeof(ikm), ikm, sizeof(salt), salt, sizeof(info), info, sizeof(dk), dk);

        if (cc_cmp_safe(FIPSPOST_POST_HKDF_DK_NBYTES, dk, current_test->dk)) {
            failf("HKDF with digest %s", current_test->digest_name);
            status = CCPOST_KAT_FAILURE;
        }
    }
    return status;
}

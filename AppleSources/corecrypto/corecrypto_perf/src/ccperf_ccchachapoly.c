/* Copyright (c) (2016-2019,2023) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "ccperf.h"
#include <corecrypto/ccchacha20poly1305.h>

static struct ccchachapoly_perf_test {
    const char *name;
} ccchachapoly_perf_tests[] = {
    {"ccchacha20poly1305_info_default"}
};

static double perf_ccchachapoly_encrypt_and_sign(size_t loops, size_t *psize, const void *test CC_UNUSED)
{
    uint8_t key[32];
    cc_clear(32,key);

    uint8_t nonce[8];
    cc_clear(8,nonce);

    uint8_t authtag[16];
    cc_clear(16,authtag);

    unsigned char *temp = malloc(*psize);
    
    const struct ccchacha20poly1305_info *info = ccchacha20poly1305_info();

    perf_start();
    while(loops--)
        ccchacha20poly1305_encrypt_oneshot(info, key, nonce, 0, NULL, *psize, temp, temp, authtag);
    
    double seconds = perf_seconds();
    free(temp);
    return seconds;
}

static double perf_ccchachapoly_decrypt_and_verify(size_t loops, size_t *psize, const void *test CC_UNUSED)
{
    // From benchmarking, this test is suspiciously fast, which makes me suspect
    // that there is a "fail early" fast path; We aren't even trying to supply
    // a valid auth tag here.

    uint8_t key[32];
    cc_clear(32,key);

    uint8_t nonce[8];
    cc_clear(8,nonce);

    uint8_t authtag[16];
    cc_clear(16,authtag);

    unsigned char *temp = malloc(*psize);
    
    const struct ccchacha20poly1305_info *info = ccchacha20poly1305_info();

    perf_start();
    while(loops--)
        ccchacha20poly1305_decrypt_oneshot(info, key, nonce, 0, NULL, *psize, temp, temp, authtag);
    
    double seconds = perf_seconds();
    free(temp);
    return seconds;
}

static void ccperf_family_ccchachapoly_once(int argc CC_UNUSED, char *argv[] CC_UNUSED)
{
}

F_DEFINE_SIZE_ARRAY(ccchachapoly, encrypt_and_sign, ccperf_size_bytes, symmetric_crypto_data_nbytes)
F_DEFINE_SIZE_ARRAY(ccchachapoly, decrypt_and_verify, ccperf_size_bytes, symmetric_crypto_data_nbytes)

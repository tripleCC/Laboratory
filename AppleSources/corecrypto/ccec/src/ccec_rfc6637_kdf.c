/* Copyright (c) (2014,2015,2017-2019,2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/ccec_priv.h>
#include "ccec_internal.h"
#include <corecrypto/ccaes.h>
#include <corecrypto/ccdigest.h>
#include <corecrypto/ccsha2.h>
#include <corecrypto/ccwrap.h>

const struct ccec_rfc6637 ccec_rfc6637_sha256_kek_aes128 = {
    .name = "wrap-sha256-kex-aes128wrap",
    .kdfhash_id = ccpgp_digest_sha256,
    .difun = ccsha256_di,
    .kek_id = ccpgp_cipher_aes128,
    .keysize = CCAES_KEY_SIZE_128,
};

const struct ccec_rfc6637 ccec_rfc6637_sha512_kek_aes256 = {
    .name = "wrap-sha512-kek-aes128",
    .kdfhash_id = ccpgp_digest_sha512,
    .difun = ccsha512_di,
    .kek_id = ccpgp_cipher_aes256,
    .keysize = CCAES_KEY_SIZE_256,
};

const struct ccec_rfc6637_curve ccec_rfc6637_dh_curve_p256 = {
    .curve_oid = (const uint8_t *)"\x08\x2A\x86\x48\xCE\x3D\x03\x01\x07",
    .public_key_alg = ccec_rfc6637_ecdh_public_key_id,
};

const struct ccec_rfc6637_curve ccec_rfc6637_dh_curve_p521 = {
    .curve_oid = (const uint8_t *)"\x05\x2B\x81\x04\x00\x23",
    .public_key_alg = ccec_rfc6637_ecdh_public_key_id,
};

void
ccec_rfc6637_kdf(const struct ccdigest_info *di,
                 const struct ccec_rfc6637_curve *curve,
                 const struct ccec_rfc6637 *wrap,
                 size_t skey_size, const void *skey,
                 size_t fingerprint_size, const void *fingerprint,
                 void *hash)
{
    ccdigest_di_decl(di, dictx);

    ccdigest_init(di, dictx);
    ccdigest_update(di, dictx, 4, "\x00\x00\x00\x01");
    ccdigest_update(di, dictx, skey_size, skey);

    /* params */
    ccdigest_update(di, dictx, 1, &curve->curve_oid[0]);
    ccdigest_update(di, dictx, curve->curve_oid[0], &curve->curve_oid[1]);
    ccdigest_update(di, dictx, 1, &curve->public_key_alg);
    ccdigest_update(di, dictx, 2, "\x03\x01");
    ccdigest_update(di, dictx, 1, &wrap->kdfhash_id);
    ccdigest_update(di, dictx, 1, &wrap->kek_id);
    ccdigest_update(di, dictx, 20, "Anonymous Sender    ");
    ccdigest_update(di, dictx, fingerprint_size, fingerprint);
    ccdigest_final(di, dictx, hash);
    ccdigest_di_clear(di, dictx);
}

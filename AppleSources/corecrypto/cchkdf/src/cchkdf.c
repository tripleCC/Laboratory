/* Copyright (c) (2014,2015,2017-2022) Apple Inc. All rights reserved.
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
#include <corecrypto/cchkdf.h>
#include <corecrypto/cchmac.h>
#include <corecrypto/cc.h>
#include <corecrypto/cc_priv.h>

int cchkdf_extract(const struct ccdigest_info *di,
                   size_t salt_nbytes,
                   const void *salt,
                   size_t ikm_nbytes,
                   const void *ikm,
                   void *prk)
{
    CC_ENSURE_DIT_ENABLED

    const uint8_t zeros[MAX_DIGEST_OUTPUT_SIZE] = { 0 };

    if (salt_nbytes == 0) {
        salt = zeros;
        salt_nbytes = di->output_size;
    }

    cchmac(di, salt_nbytes, salt, ikm_nbytes, ikm, prk);
    return CCERR_OK;
}

int cchkdf_expand(const struct ccdigest_info *di,
                  size_t prk_nbytes,
                  const void *prk,
                  size_t info_nbytes,
                  const void *info,
                  size_t dk_nbytes,
                  void *dk)
{
    CC_ENSURE_DIT_ENABLED

    uint8_t T[MAX_DIGEST_OUTPUT_SIZE];

    size_t n = cc_ceiling(dk_nbytes, di->output_size);
    if (n > 255) {
        return CCERR_PARAMETER;
    }

    if (prk_nbytes < di->output_size) {
        return CCERR_PARAMETER;
    }

    cchmac_di_decl(di, hc);

    // Initialize HMAC once and copy its state over for every loop iteration.
    // That saves some cycles and allows passing prk == dk.
    cchmac_di_decl(di, hci);
    cchmac_init(di, hci, prk_nbytes, prk);

    size_t Tlen = 0;
    size_t offset = 0;
    for (size_t i = 1; i <= n; ++i) {
        // Copy initialized HMAC state.
        cc_memcpy(hc, hci, cchmac_di_size(di));

        cchmac_update(di, hc, Tlen, T);
        cchmac_update(di, hc, info_nbytes, info);
        uint8_t b = (uint8_t)i;
        cchmac_update(di, hc, 1, &b);
        cchmac_final(di, hc, T);

        if (i == n) {
            cc_memcpy((uint8_t *)dk + offset, T, dk_nbytes - offset);
        } else {
            cc_memcpy((uint8_t *)dk + offset, T, di->output_size);
        }

        offset += di->output_size;
        Tlen = di->output_size;
    }

    cchmac_di_clear(di, hci);
    cchmac_di_clear(di, hc);
    cc_clear(di->output_size, T);
    return CCERR_OK;
}

int cchkdf(const struct ccdigest_info *di,
           size_t ikm_nbytes,
           const void *ikm,
           size_t salt_nbytes,
           const void *salt,
           size_t info_nbytes,
           const void *info,
           size_t dk_nbytes,
           void *dk)
{
    CC_ENSURE_DIT_ENABLED

    uint8_t prk[MAX_DIGEST_OUTPUT_SIZE];

    int result = cchkdf_extract(di, salt_nbytes, salt, ikm_nbytes, ikm, prk);
    if (result == CCERR_OK) {
        result = cchkdf_expand(di, di->output_size, prk, info_nbytes, info, dk_nbytes, dk);
    }

    cc_clear(di->output_size, prk);
    return result;
}

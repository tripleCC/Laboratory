/* Copyright (c) (2017,2019,2021,2023) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "cc_debug.h"

#include "fipspost.h"
#include "fipspost_priv.h"
#include "fipspost_post_integrity.h"
#include "fipspost_get_hmac.h"

FIPSPOST_EXTERN_PRECALC_HMAC;

int fipspost_post_integrity(uint32_t fips_mode, struct mach_header *pmach_header)
{
    int result = CCPOST_GENERIC_FAILURE;

    unsigned char hmac_buffer[FIPSPOST_PRECALC_HMAC_SIZE];
    if (fipspost_get_hmac(pmach_header, hmac_buffer, 0)) {
        failf("could not create the hash");
        goto exit;
    }

    if (FIPS_MODE_IS_FORCEFAIL(fips_mode)) {
        hmac_buffer[0] = hmac_buffer[0] ^ 1;
    }

    int cmp = cc_cmp_safe(FIPSPOST_PRECALC_HMAC_SIZE, hmac_buffer, FIPSPOST_HMAC_VALUE);
    if (cmp) {
        bufferf(hmac_buffer, FIPSPOST_PRECALC_HMAC_SIZE, "MAC generated");
        bufferf(FIPSPOST_HMAC_VALUE, FIPSPOST_PRECALC_HMAC_SIZE, "  In variable");
        result = CCPOST_INTEGRITY_ERROR;
        goto exit;
    }

    result = CCERR_OK;

 exit:
    cc_clear(sizeof(hmac_buffer), hmac_buffer);
    return result;
}

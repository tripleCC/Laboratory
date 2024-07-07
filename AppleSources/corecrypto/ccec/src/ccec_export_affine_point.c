/* Copyright (c) (2021) Apple Inc. All rights reserved.
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
#include <corecrypto/ccec_priv.h>
#include "ccec_internal.h"
#include "cc_macros.h"

size_t ccec_export_affine_point_size(ccec_const_cp_t cp, int format) {
    CC_ENSURE_DIT_ENABLED

    if (format == CCEC_FORMAT_COMPACT) {
        return ccec_compact_export_size_cp(0, cp);
    } else if (format == CCEC_FORMAT_COMPRESSED) {
        return ccec_compressed_x962_export_pub_size(cp);
    } else if (format == CCEC_FORMAT_UNCOMPRESSED) {
        return ccec_x963_export_size_cp(0, cp);
    } else if (format == CCEC_FORMAT_HYBRID) {
        return ccec_x963_export_size_cp(0, cp);
    } else {
        return 0;
    }
}

int ccec_export_affine_point(ccec_const_cp_t cp, int format, ccec_const_affine_point_t point, size_t *out_nbytes, uint8_t *out)
{
    CC_ENSURE_DIT_ENABLED

    // Check that the output buffer is large enough
    size_t expected_size = ccec_export_affine_point_size(cp, format);
    cc_require_or_return(expected_size > 0, CCERR_PARAMETER);
    cc_require_or_return(*out_nbytes >= expected_size, CCERR_BUFFER_TOO_SMALL);
    *out_nbytes = expected_size;
    
    // Set the first byte
    if (format == CCEC_FORMAT_COMPRESSED) {
        out[0] = 0x02;
    } else if (format == CCEC_FORMAT_UNCOMPRESSED) {
        out[0] = 0x04;
    } else if (format == CCEC_FORMAT_HYBRID) {
        out[0] = 0x06;
    }
    
    cc_size n = ccec_cp_n(cp);
    
    // Export x
    uint8_t *out_x = out + ((format != CCEC_FORMAT_COMPACT) ? 1 : 0);
    int rv = ccn_write_uint_padded_ct(n, ccec_point_x(point, cp), ccec_cp_prime_size(cp), out_x);
    cc_require_or_return(rv >= 0, CCERR_INTERNAL);

    // If the format is uncompressed or hybrid, export y
    if ((format == CCEC_FORMAT_UNCOMPRESSED) || (format == CCEC_FORMAT_HYBRID)) {
        uint8_t *out_y = out_x + ccec_cp_prime_size(cp);
        rv = ccn_write_uint_padded_ct(n, ccec_point_y(point, cp), ccec_cp_prime_size(cp), out_y);
        cc_require_or_return(rv >= 0, CCERR_INTERNAL);
    }
    
    // If the format is compressed or hybrid, store the parity of y in the first byte
    if ((format == CCEC_FORMAT_COMPRESSED) || (format == CCEC_FORMAT_HYBRID)) {
        out[0] |= (uint8_t)(ccec_point_y(point, cp)[0]&1);
    }
    
    return CCERR_OK;
}

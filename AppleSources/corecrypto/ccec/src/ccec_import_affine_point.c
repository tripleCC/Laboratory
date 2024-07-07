/* Copyright (c) (2021,2023) Apple Inc. All rights reserved.
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

int ccec_import_affine_point_ws(cc_ws_t ws,
                                ccec_const_cp_t cp,
                                int format,
                                size_t in_nbytes,
                                const uint8_t *in,
                                ccec_affine_point_t point)
{
    int rv;
    cc_size n = ccec_cp_n(cp);

    if (in_nbytes == 0) {
        return CCERR_PARAMETER;
    }

    // If the point is the point at infinity, returns an error
    if (in_nbytes == 1 && in[0] == 0x00) {
        return CCEC_POINT_CANNOT_BE_UNIT;
    }

    // Check that the input length and first byte are correct
    int rv_encoding_error;
    if (format == CCEC_FORMAT_COMPACT) {
        rv_encoding_error = CCEC_COMPACT_POINT_ENCODING_ERROR;
        cc_require_or_return(in_nbytes == ccec_compact_export_size_cp(0, cp), rv_encoding_error);
    } else if (format == CCEC_FORMAT_COMPRESSED) {
        rv_encoding_error = CCEC_COMPRESSED_POINT_ENCODING_ERROR;
        cc_require_or_return((in_nbytes == ccec_compressed_x962_export_pub_size(cp)) && (in[0] == 0x02 || in[0] == 0x03),
                             CCEC_COMPRESSED_POINT_ENCODING_ERROR);
    } else if (format == CCEC_FORMAT_UNCOMPRESSED) {
        rv_encoding_error = CCEC_UNCOMPRESSED_POINT_ENCODING_ERROR;
        cc_require_or_return((in_nbytes == ccec_x963_export_size_cp(0, cp)) && (in[0] == 0x04),
                             CCEC_UNCOMPRESSED_POINT_ENCODING_ERROR);
    } else if (format == CCEC_FORMAT_HYBRID) {
        rv_encoding_error = CCEC_HYBRID_POINT_ENCODING_ERROR;
        cc_require_or_return((in_nbytes == ccec_x963_export_size_cp(0, cp)) && (in[0] == 0x06 || in[0] == 0x07),
                             CCEC_HYBRID_POINT_ENCODING_ERROR);
    } else {
        return CCERR_PARAMETER;
    }

    CC_DECL_BP_WS(ws, bp);
    cc_unit *t = CC_ALLOC_WS(ws, n);

    // Read x
    const uint8_t *in_x = in + ((format != CCEC_FORMAT_COMPACT) ? 1 : 0);
    rv = ccn_read_uint(n, ccec_point_x(point, cp), ccec_cp_prime_size(cp), in_x);
    cc_require(rv == CCERR_OK, errOut);
    cc_require_action(ccn_cmp(n, ccec_point_x(point, cp), ccec_cp_p(cp)) == -1, errOut, rv = rv_encoding_error); // check x < p

    // If the format is compressed or compact, compute y; else read y.
    if (format == CCEC_FORMAT_COMPACT || format == CCEC_FORMAT_COMPRESSED) {
        rv = ccec_affine_point_from_x_ws(ws, cp, point, ccec_point_x(point, cp));
        cc_require(rv == CCERR_OK, errOut);
    } else {
        const uint8_t *in_y = in + 1 + ccec_cp_prime_size(cp);
        rv = ccn_read_uint(n, ccec_point_y(point, cp), ccec_cp_prime_size(cp), in_y);
        cc_require(rv == CCERR_OK, errOut);
    }

    // We now have a tentative point (x, y).
    // - If the format is compact, the convention for y is y = min(y', p-y');
    //   https://datatracker.ietf.org/doc/draft-jivsov-ecc-compact/
    // - If the format is compressed or hybrid, the first byte contains the parity of y
    if (format == CCEC_FORMAT_COMPACT || format == CCEC_FORMAT_COMPRESSED) {
        cczp_negate(ccec_cp_zp(cp), t, ccec_point_y(point, cp));
        cc_unit s;
        if (format == CCEC_FORMAT_COMPACT) {
            s = ccn_cmp(n, t, ccec_point_y(point, cp)) < 0; // convention for y is y = min(y', p-y');
        } else /* format == CCEC_FORMAT_COMPRESSED */ {
            s = (ccec_point_y(point, cp)[0] & 1) != (in[0] & 1); // select according to the parity of the first byte
        }
        ccn_mux(n, s, ccec_point_y(point, cp), t, ccec_point_y(point, cp));
    } else if (format == CCEC_FORMAT_HYBRID) {
        cc_require_action((ccec_point_y(point, cp)[0] & 1) == (in[0] & 1), errOut, rv = CCEC_HYBRID_POINT_ENCODING_ERROR);
    }

errOut:
    CC_FREE_BP_WS(ws, bp);
    return rv;
}

int ccec_import_affine_point(ccec_const_cp_t cp, int format, size_t in_nbytes, const uint8_t *in, ccec_affine_point_t point)
{
    CC_ENSURE_DIT_ENABLED

    cc_size n = ccec_cp_n(cp);
    CC_DECL_WORKSPACE_OR_FAIL(ws, CCEC_IMPORT_AFFINE_POINT_WORKSPACE_N(n));
    int rv = ccec_import_affine_point_ws(ws, cp, format, in_nbytes, in, point);
    CC_FREE_WORKSPACE(ws);
    return rv;
}

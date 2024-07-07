/* Copyright (c) (2019,2021,2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CCDER_INTERNAL_H_
#define _CORECRYPTO_CCDER_INTERNAL_H_

#include <corecrypto/cc_priv.h>
#include <corecrypto/ccder.h>
#include <corecrypto/ccder_blob.h>

CC_PTRCHECK_CAPABLE_HEADER()

CC_NONNULL((1, 3)) CC_NODISCARD
bool ccder_blob_decode_tl_internal(ccder_read_blob *from, ccder_tag expected_tag, size_t *lenp, bool strict);

/*!
 @function   ccder_blob_decode_uint_skip_leading_zeroes
 @abstract   Advance ccder_read_blob to the most significant non-zero byte of the uint
 Per ITU-T Rec. X.690 (07/2002), section 8.3 "If the contents octets of an integer value
 encoding consist of more than one octet, then the bits of the first octet
 and bit 8 of the second octet, Shall not all be ones and shall not be zero".
 Here we only allow unsigned integers.

 @param      from        Byte range of the uint, inout.

 @result     Returns true if the range range was successfully advanced.
             When false, the range is zeroed.
 */

CC_NONNULL((1)) CC_NODISCARD CC_INLINE
bool ccder_blob_decode_uint_skip_leading_zeroes(ccder_read_blob *from) {
    const uint8_t *der = from->der;
    const uint8_t *const der_end = from->der_end;
    if (der == der_end) {
        // ISO/IEC 8825-1:2003 (E) 8.3.1 The encoding of an integer value shall be primitive
        // The contents octets shall consist of one or more octets.
        goto error;
    }
    
    // Sign
    if (der[0] & 0x80) {
        // Negative value, not authorized for unsigned integer
        goto error;
    }
    
    // Leading byte
    if (der[0] == 0) {
        der++;

        // At this point, we expect the most significant bit set
        if (der != der_end && !(der[0] & 0x80)) {
            goto error;
        }
    }
    from->der = der;
    from->der_end = der_end;
    return true;
    
error:
    from->der = NULL;
    from->der_end = NULL;
    return false;
}

#if !CC_PTRCHECK
CC_NONNULL((1, 2)) CC_INLINE
const uint8_t *ccder_decode_uint_skip_leading_zeroes(size_t *len, const uint8_t *der) {
    ccder_read_blob blob = { der, der + *len };
    if (ccder_blob_decode_uint_skip_leading_zeroes(&blob)) {
        *len = ccder_blob_size(blob);
        return blob.der;
    } else {
        return NULL;
    }
}
#endif

#endif /* _CORECRYPTO_CCDER_INTERNAL_H_ */

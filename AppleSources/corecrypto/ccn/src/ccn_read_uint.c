/* Copyright (c) (2010,2011,2015,2018,2019,2021) Apple Inc. All rights reserved.
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
#include "ccn_internal.h"

int ccn_read_uint(cc_size n, cc_unit *r, size_t data_nbytes, const uint8_t *data)
{
    CC_ENSURE_DIT_ENABLED

    int rc = 0;

    /* Result in place is not supported */
    cc_assert((const void *)data != (void *)r);

    /* process potential overflow with MS byte of data */
    while (data_nbytes > ccn_sizeof_n(n)) {
        /* capture any non zero byte */
        rc |= *data++;
        data_nbytes--;
    }

    /* check that input fits in the allocated cc_unit array */
    if (rc != 0) {
        return CCERR_PARAMETER;
    }

    /* write the bytes, starting with the LS byte of data */
    const uint8_t *d = data + data_nbytes;
    cc_size ix;
    /* process full cc_unit */
    for (ix = 0; data_nbytes >= CCN_UNIT_SIZE; ix++) {
        d -= CCN_UNIT_SIZE;
        CC_LOAD_UNIT_BE(r[ix], d);
        data_nbytes -= CCN_UNIT_SIZE;
    }
    /* process most significant partial cc_unit */
    if (data_nbytes) {
        cc_unit v = 0;
        d -= data_nbytes;
        while (data_nbytes-- > 0) {
            v = (v << 8) | *d++;
        }
        r[ix++] = v;
    }
    /* Pad with zeros */
    for (; ix < n; ++ix) {
        r[ix] = 0;
    }
    return 0;
}

/* Copyright (c) (2018,2019,2021) Apple Inc. All rights reserved.
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
#include <corecrypto/ccwrap.h>

size_t ccwrap_unwrapped_size(const size_t data_size)
{
    CC_ENSURE_DIT_ENABLED

    if (data_size < CCWRAP_SEMIBLOCK) {
        // data is malformed and possibly malicious
        // just avoid underflow for now
        // actually detect and handle error in ccwrap_auth_decrypt
        return 0;
    }

    return (data_size - CCWRAP_SEMIBLOCK);
}

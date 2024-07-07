/* Copyright (c) (2012,2014-2019,2021) Apple Inc. All rights reserved.
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
#include <corecrypto/cc_priv.h>
#include "cc_macros.h"
#include "cc_debug.h"
#include "ccwrap_internal.h"

int ccwrap_auth_decrypt_withiv(const struct ccmode_ecb *ecb_mode,
                               ccecb_ctx *ecb_key,
                               size_t nbytes,
                               const void *in,
                               size_t *obytes,
                               void *out,
                               const void *iv)
{
    CC_ENSURE_DIT_ENABLED

    int j;
    size_t i, n;
    int ret = CCERR_INTERNAL;
    const uint8_t *in_bytes = in;
    uint8_t *out_bytes = out;
    uint64_t R[2];

    *obytes = ccwrap_unwrapped_size(nbytes);
    cc_require_action(ccwrap_argsvalid(ecb_mode, *obytes, nbytes), out, ret = CCERR_PARAMETER);

    n = (nbytes / CCWRAP_SEMIBLOCK) - 1;
    cc_memcpy(&R[0], in_bytes, sizeof(R[0]));
    cc_memmove(out, in_bytes + CCWRAP_SEMIBLOCK, *obytes);

    for (j = 5; j >= 0; j -= 1) {
        for (i = n; i >= 1; i -= 1) {
            cc_memcpy(&R[1], (out_bytes + ((i - 1) * CCWRAP_SEMIBLOCK)), sizeof(R[1]));
            R[0] ^= CC_H2BE64((n * (size_t)j) + i);
            ecb_mode->ecb(ecb_key, 1, R, R);
            cc_memcpy((out_bytes + ((i - 1) * CCWRAP_SEMIBLOCK)), &R[1], sizeof(R[1]));
        }
    }

    cc_require_action(cc_cmp_safe(sizeof(R[0]), &R[0], iv) == 0, out, ret = CCERR_INTEGRITY);

    ret = CCERR_OK;

out:
    cc_clear(sizeof(R), R);
    if (ret != CCERR_OK) {
        *obytes = 0;
        cc_clear(ccwrap_unwrapped_size(nbytes), out);
    }
    return ret;
}

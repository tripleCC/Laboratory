/* Copyright (c) (2012,2014-2016,2018,2019,2021) Apple Inc. All rights reserved.
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
#include <corecrypto/cc_priv.h>
#include "cc_macros.h"
#include "cc_debug.h"
#include "ccwrap_internal.h"

/*

 1) Initialize variables.

 Set A = IV, an initial value (see 2.2.3)
 For i = 1 to n R[i] = P[i]

 2) Calculate intermediate values.

 For j = 0 to 5
 For i=1 to n
 B = AES(K, A | R[i])
 A = MSB(64, B) ^ t where t = (n x j)+i
 R[i] = LSB(64, B)

 3) Output the results.

 Set C[0] = A
 For i = 1 to n
 C[i] = R[i]

 */

int ccwrap_auth_encrypt_withiv(const struct ccmode_ecb *ecb_mode,
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
    uint8_t *out_bytes = out;
    uint64_t R[2];

    *obytes = ccwrap_wrapped_size(nbytes);
    cc_require_action(ccwrap_argsvalid(ecb_mode, nbytes, *obytes), out, ret = CCERR_PARAMETER);

    n = nbytes / CCWRAP_SEMIBLOCK;
    cc_memcpy(&R[0], iv, sizeof(R[0]));
    cc_memmove(out_bytes + CCWRAP_SEMIBLOCK, in, nbytes);

    for (j = 0; j <= 5; j += 1) {
        for (i = 1; i <= n; i += 1) {
            cc_memcpy(&R[1], (out_bytes + (i * CCWRAP_SEMIBLOCK)), sizeof(R[1]));
            ecb_mode->ecb(ecb_key, 1, R, R);
            R[0] ^= CC_H2BE64((n * (size_t)j) + i);
            cc_memcpy((out_bytes + (i * CCWRAP_SEMIBLOCK)), &R[1], sizeof(R[1]));
        }
    }

    cc_memcpy(out_bytes, &R[0], sizeof(R[0]));

    ret = CCERR_OK;

out:
    if (ret != CCERR_OK) {
        *obytes = 0;
    }
    return ret;
}

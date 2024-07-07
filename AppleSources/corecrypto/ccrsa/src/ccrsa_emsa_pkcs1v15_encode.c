/* Copyright (c) (2011-2013,2015-2019,2021) Apple Inc. All rights reserved.
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
#include <corecrypto/cc.h>
#include "cc_macros.h"
#include <corecrypto/ccrsa_priv.h>
#include <corecrypto/ccsha2.h>

/* this is the EMSA-PKCS1-v1_5 function specified in PKCS#1 v2.2 */
/* Null OID is a special case for interoperability purposes.
 Failing to do so results in weak signatures */
int ccrsa_emsa_pkcs1v15_encode(size_t emlen, uint8_t *em, size_t dgstlen, const uint8_t *dgst, const uint8_t *oid)
{
    CC_ENSURE_DIT_ENABLED

    int err = CCERR_PARAMETER;
    size_t tlen;
    uint8_t oidlen = 0;

    if (oid == NULL) {
        tlen = dgstlen;
    } else {
        assert(oid[0] == 0x06);
        oidlen = oid[1];
        /* oidlen + 4 must fit in uint8_t */
        cc_require(oidlen + 4 <= UINT8_MAX, out);
        /* dgstlen must fit in uint8_t  */
        cc_require(dgstlen <= UINT8_MAX, out);
        tlen = 2 + 2 + oidlen + 2 + 2 + dgstlen + 2;
        cc_require(tlen < 127, out);
    }

    /* the digest must fit in the message buffer in all code paths */
    cc_require(emlen >= 11, out);
    cc_require(tlen <= (emlen - 11), out);

    size_t pslen = emlen - 3 - tlen;

    *em++ = 0x00;
    *em++ = 0x01;
    cc_memset(em, 0xff, pslen);
    em += pslen;
    *em++ = 0x00;
    if (oid != NULL) {
        *em++ = 0x30;
        *em++ = (uint8_t)tlen - 2;
        *em++ = 0x30;
        *em++ = oidlen + 4;
        cc_memcpy(em, oid, oidlen + 2);
        em += oidlen + 2;
        *em++ = 0x05;
        *em++ = 0x00;
        *em++ = 0x04;
        *em++ = (uint8_t)dgstlen;
    }
    cc_memcpy(em, dgst, dgstlen);

    err = CCERR_OK;

out:
    return err;
}

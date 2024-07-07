/* Copyright (c) (2011,2012,2015,2016,2018-2022) Apple Inc. All rights reserved.
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
#include <corecrypto/ccrsa_priv.h>
#include "ccrsa_internal.h"
#include "cc_debug.h"
#include "cc_fault_canary_internal.h"

/* Null OID is a special case, required to support RFC 4346 where the padding
 is based on SHA1+MD5. The OID should not be NULL, except when strictly required
 for interoperability */
int ccrsa_emsa_pkcs1v15_verify_canary_out(size_t emlen,
                                          const uint8_t *em,
                                          size_t dgstlen,
                                          const uint8_t *dgst,
                                          const uint8_t *oid,
                                          cc_fault_canary_t fault_canary_out)
{
    CC_FAULT_CANARY_CLEAR(fault_canary_out);
    size_t tlen;

    size_t oidlen = 0;
    uint8_t r = 0;

#define bytecheck(v) r |= (*em++) ^ (v)
#define memcheck(s, len)              \
    r |= cc_cmp_safe((len), em, (s)); \
    em += (len)

    if (oid == NULL) {
        tlen = dgstlen;
    } else {
        assert(oid[0] == 0x06);
        oidlen = oid[1];
        tlen = 2 + 2 + oidlen + 2 + 2 + dgstlen + 2;
    }

    if (emlen < tlen + 11)
        return CCRSA_INVALID_INPUT;

    size_t pslen = emlen - 3 - tlen;

    bytecheck(0x00);
    bytecheck(0x01);
    while (pslen--) {
        bytecheck(0xff);
    }
    bytecheck(0x00);
    if (oid != NULL) {
        bytecheck(0x30);
        bytecheck(tlen - 2);
        bytecheck(0x30);
        bytecheck(oidlen + 4);
        memcheck(oid, oidlen + 2);
        bytecheck(0x05);
        bytecheck(0x00);
        bytecheck(0x04);
        bytecheck(dgstlen);
    }

    cc_assert(dgstlen > 0);
    
    cc_fault_canary_set(fault_canary_out, CCRSA_PKCS1_FAULT_CANARY, dgstlen, dgst, em);

    memcheck(dgst, dgstlen);
    return r;
}

int ccrsa_emsa_pkcs1v15_verify(size_t emlen, uint8_t *em, size_t dgstlen, const uint8_t *dgst, const uint8_t *oid)
{
    CC_ENSURE_DIT_ENABLED

    uint8_t unused_fault_canary[sizeof(CCRSA_PKCS1_FAULT_CANARY)];
    cc_memset(unused_fault_canary, 0xaa, sizeof(CCRSA_PKCS1_FAULT_CANARY));
    return ccrsa_emsa_pkcs1v15_verify_canary_out(emlen, em, dgstlen, dgst, oid, unused_fault_canary);
}

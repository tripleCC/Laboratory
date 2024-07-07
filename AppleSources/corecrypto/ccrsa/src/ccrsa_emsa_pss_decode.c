/* Copyright (c) (2015,2016,2019-2022) Apple Inc. All rights reserved.
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
#include "cc_fault_canary_internal.h"

int ccrsa_emsa_pss_decode_canary_out_ws(cc_ws_t ws,
                                        const struct ccdigest_info *di,
                                        const struct ccdigest_info *MgfDi,
                                        size_t sSize,
                                        size_t mSize,
                                        const uint8_t *mHash,
                                        size_t emBits,
                                        const uint8_t *EM,
                                        cc_fault_canary_t fault_canary_out)
{
    CC_FAULT_CANARY_CLEAR(fault_canary_out);
    const cc_size emSize = cc_ceiling(emBits, 8); // In theory, emLen can be one byte less than modBytes
    const size_t hSize = di->output_size;
    int rc = 0;

    // 1.
    if (mSize != hSize) {
        return CCRSA_DECODING_ERROR;
    }

    // 3.
    if (emSize < hSize + sSize + 2) {
        return CCRSA_DECODING_ERROR;
    }

    CC_DECL_BP_WS(ws, bp);

    cc_size n = ccn_nof(emBits);
    uint8_t *dbMask = (uint8_t *)CC_ALLOC_WS(ws, n);

    // 4.
    rc = EM[emSize - 1] ^ 0xbc; // EM[emLen-1] must be 0xbc

    // 5.
    const uint8_t *maskedDB = EM; // get directly from EM

    // 6.
    // standard: If the leftmost 8emLen – emBits bits of the leftmost octet in
    // maskedDB are not all equal to zero, output “inconsistent” and stop.
    const size_t n_zbits = -emBits & 0x7;

    // n == 0 generates mask == 0, that means no mask is required and sets rc to zero
    uint8_t mask = (uint8_t) ~(0xff >> n_zbits);
    rc |= maskedDB[0] & mask;

    // 7.
    const size_t len = emSize - hSize - 1;
    const uint8_t *H = EM + len;

    rc |= ccmgf(MgfDi, len, dbMask, hSize, H);

    // 8.
    // 9. knock off n number of bits
    dbMask[0] &= ~mask;

    // 10. "If the emSize - hSize - sSize -2 leftmost octets of DB are not zero"
    // output "inconsistent"
    size_t i = 0;
    cc_assert(emSize >= sSize + hSize + 2);
    for (i = 0; i < emSize - sSize - hSize - 2; i++) { // maskedDB and dbMask must be equal
        rc |= maskedDB[i] ^ dbMask[i];                 // let it continue, although there might be an error
    }

    // 10. "Or if the octet at position emSize - hSize - sSize - 1
    // (the leftmost position is "position 1") does not have hexadecimal value 0x01"
    // output "inconsistent"
    rc |= (maskedDB[i] ^ dbMask[i]) ^ 0x01;
    i++;

    // 11. Let salt be the last sSize octets of DB.
    uint8_t *salt = dbMask;
    for (size_t j = 0; j < sSize; i++, j++) {
        salt[j] = maskedDB[i] ^ dbMask[i];
    }

    // 12. 13.
    uint8_t H2[MAX_DIGEST_OUTPUT_SIZE];
    const uint64_t zero = 0;
    ccdigest_di_decl(di, dc);
    ccdigest_init(di, dc);
    ccdigest_update(di, dc, sizeof(uint64_t), &zero);
    ccdigest_update(di, dc, mSize, mHash);
    if (sSize > 0) {
        ccdigest_update(di, dc, sSize, salt);
    }
    ccdigest_final(di, dc, H2);
    ccdigest_di_clear(di, dc);

    // 14.
    rc |= cc_cmp_safe(hSize, H2, H);
    CC_HEAVISIDE_STEP(rc, rc);
    rc = CCRSA_DECODING_ERROR & (-rc);

    cc_assert(hSize > 16);
    cc_fault_canary_set(fault_canary_out, CCRSA_PSS_FAULT_CANARY, hSize, H, H2);

    CC_FREE_BP_WS(ws, bp);
    return rc;
}

int ccrsa_emsa_pss_decode_ws(cc_ws_t ws,
                             const struct ccdigest_info *di,
                             const struct ccdigest_info *MgfDi,
                             size_t sSize,
                             size_t mSize,
                             const uint8_t *mHash,
                             size_t emBits,
                             const uint8_t *EM)
{
    uint8_t unused_fault_canary[sizeof(CCRSA_PSS_FAULT_CANARY)];
    cc_memset(unused_fault_canary, 0xaa, sizeof(CCRSA_PSS_FAULT_CANARY));
    return ccrsa_emsa_pss_decode_canary_out_ws(ws, di, MgfDi, sSize, mSize, mHash, emBits, EM, unused_fault_canary);
}

/*!
 @function  ccrsa_emsa_pss_decode() PKCS calls it EMSA-PSS-Verify (M, EM, emBits)
 @param di	hash function (hLen denotes the length in octets of the hash function output)
 @param MgfDi	mask generation function
 @param sSize	intended length in octets of the salt
 @param mHash	message to be verified, an octet string
 @param EM	encoded message, an octet string of length emLen = ⎡emBits/8⎤
 @param emBits	maximal bit length of the integer OS2IP (EM) (see Section 4.2), at least 8hLen + 8sLen + 9
 @result	0=consistent or non zero= inconsistent
 */

int ccrsa_emsa_pss_decode(const struct ccdigest_info *di,
                          const struct ccdigest_info *MgfDi,
                          size_t sSize,
                          size_t mSize,
                          const uint8_t *mHash,
                          size_t emBits,
                          const uint8_t *EM)
{
    CC_ENSURE_DIT_ENABLED

    CC_DECL_WORKSPACE_OR_FAIL(ws, CCRSA_EMSA_PSS_DECODE_WORKSPACE_N(ccn_nof(emBits)));
    int rv = ccrsa_emsa_pss_decode_ws(ws, di, MgfDi, sSize, mSize, mHash, emBits, EM);
    CC_FREE_WORKSPACE(ws);
    return rv;
}

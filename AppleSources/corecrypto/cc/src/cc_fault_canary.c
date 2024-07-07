/* Copyright (c) (2019-2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/cc_fault_canary.h>
#include "cc_fault_canary_internal.h"

const cc_fault_canary_t CCEC_FAULT_CANARY = { 0xce, 0x3c, 0xed, 0x46, 0x6b, 0x11, 0xbf, 0x08, 0x13, 0xa0, 0xd4, 0xbf, 0x89, 0x60, 0xeb, 0x56 };
const cc_fault_canary_t CCRSA_PSS_FAULT_CANARY = { 0xef, 0x49, 0xba, 0x59, 0x22, 0xfe, 0x10, 0xdd, 0x84, 0x4f, 0x24,
    0xd6, 0xad, 0xc0, 0xa9, 0x93 };
const cc_fault_canary_t CCRSA_PKCS1_FAULT_CANARY = { 0xea, 0xc5, 0x4a, 0x7c, 0x9f, 0x28, 0xdf, 0x10, 0xb6, 0xe9, 0x3e, 0xb9, 0x1c, 0xd3, 0x3a, 0xc5 };

void cc_fault_canary_set(cc_fault_canary_t fault_canary_out, const cc_fault_canary_t fault_canary, size_t nbytes, const uint8_t *in1, const uint8_t *in2)
{    
    // We need to be careful with our xor's.
    // The first loop XORs the actual fault canary value
    for (size_t ci = 0; ci < CC_FAULT_CANARY_SIZE; ci++) {
        size_t bi = ci % nbytes;
        fault_canary_out[ci] = in1[bi] ^ in2[bi] ^ fault_canary[ci];
    }

    // The second loop XORs the existing value in the input fault canary buffer.
    for (size_t i = CC_FAULT_CANARY_SIZE; i < nbytes; i++) {
        size_t bi = i % nbytes;
        size_t ci = i % sizeof(CCEC_FAULT_CANARY);
        fault_canary_out[ci] = in1[bi] ^ in2[bi] ^ fault_canary_out[ci];
    }
}

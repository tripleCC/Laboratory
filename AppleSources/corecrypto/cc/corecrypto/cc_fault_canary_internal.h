/* Copyright (c) (2019,2020,2023) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CC_FAULT_CANARY_INTERNAL_H_
#define _CORECRYPTO_CC_FAULT_CANARY_INTERNAL_H_

// XORs of all fault canary bytes.
#define CCRSA_PKCS1_FAULT_CANARY_XOR 0x89
#define CCRSA_PSS_FAULT_CANARY_XOR 0x3a

// XOR bytes in randomized order to prevent the compiler from emitting a loop.
//
// Current and older versions of clang for ARMv7+ always unroll an explicit
// for-loop, at least with -O3. But let's make sure.
//
// `_rv_` is required to be a volatile variable, to force memory reads/writes
// in the stated order. That should prevent even a very ambitious optimizing
// compiler from rewriting this into a loop.
#define CC_FAULT_CANARY_XOR_RV(_rv_, _cn_)                \
    do {                                                  \
        _rv_ ^= _cn_[4]  ^ _cn_[8]  ^ _cn_[3] ^ _cn_[13]; \
        _rv_ ^= _cn_[10] ^ _cn_[15] ^ _cn_[1] ^ _cn_[11]; \
        _rv_ ^= _cn_[6]  ^ _cn_[14] ^ _cn_[2] ^ _cn_[9];  \
        _rv_ ^= _cn_[0]  ^ _cn_[12] ^ _cn_[7] ^ _cn_[5];  \
    } while (0)

/*!
@function   cc_fault_canary_set
@abstract   Set the output `fault_canary_out` to the value `fault_canary` if the two inputs are equal.

@param fault_canary_out  Output fault canary value
@param fault_canary      Fault canary for a specific operation (e.g. CCEC_FAULT_CANARY for ECC signing)
@param nbytes            Byte length of inputs in1 and in2
@param in1               Input one
@param in2               Input two
*/
void cc_fault_canary_set(cc_fault_canary_t fault_canary_out, const cc_fault_canary_t fault_canary, size_t nbytes, const uint8_t *in1, const uint8_t *in2);

#endif // _CORECRYPTO_CC_FAULT_CANARY_INTERNAL_H_

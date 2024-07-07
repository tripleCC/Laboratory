# Copyright (c) (2023) Apple Inc. All rights reserved.
#
# corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
# is contained in the License.txt file distributed with corecrypto) and only to
# people who accept that license. IMPORTANT:  Any license rights granted to you by
# Apple Inc. (if any) are limited to internal use within your organization only on
# devices and computers you own or control, for the sole purpose of verifying the
# security characteristics and correct functioning of the Apple Software.  You may
# not, directly or indirectly, redistribute the Apple Software or any portions thereof.

#include <corecrypto/cc_config.h>

#if defined(__x86_64__) && CCN_MULMOD_224_ASM

.text

#include "ccn_mul_256-x64.h"

.macro partial_redc
    movq $0, v
    negq v

    movq $$32, q
    shrx q, v, a
    shlx q, v, q

    addq v, $0
    adcq $$0, $1
    adcq $$0, $2
    adcq q, $3
    adcq a, $0

    subq q, $1
    sbbq a, $2
    sbbq $$0, $3
    sbbq $$0, $0
.endm

.align 4
.globl _ccn_mulmod_p224
_ccn_mulmod_p224: /* void ccn_mulmod_p224(cc_unit *r, const cc_unit *a, const cc_unit *b); */
    pushq %rbp
    movq %rsp, %rbp
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15
    pushq %rbx

    #include "ccn_mul_256-x64.s"

    partial_redc Z0, Z1, Z2, Z3
    partial_redc Z1, Z2, Z3, Z4
    partial_redc Z2, Z3, Z4, Z5
    partial_redc Z3, Z4, Z5, Z6

    addq Z4, Z0
    adcq Z5, Z1
    adcq Z6, Z2
    adcq Z7, Z3

    // Final subtraction.
    movq $0xffffffff00000000, a // m[1]
    movq $0xffffffffffffffff, q // m[2]
    movq $0x00000000ffffffff, v // m[3]

    // Subtract M.
    subq $1, Z0
    sbbq a, Z1
    sbbq q, Z2
    sbbq v, Z3

    // q = (Z < M) ? 0xffffffffffffffff : 0
    sbbq q, q

    // Clear a,v if (Z >= M).
    andq q, a
    andq q, v

    movq q, b
    negq b

    // Add M back, if needed.
    addq b, Z0
    adcq a, Z1
    adcq q, Z2
    adcq v, Z3

    // Write Z.
    movq Z0, (r)
    movq Z1, 8(r)
    movq Z2, 16(r)
    movq Z3, 24(r)

    popq %rbx
    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %rbp

    ret

#endif

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

#if defined(__x86_64__) && CCN_MULMOD_25519_ASM

.text

#include "ccn_mul_256-x64.h"

.align 4
.globl _ccn_addmod_p25519
_ccn_addmod_p25519: /* void ccn_addmod_p25519(cc_unit *r, const cc_unit *a, const cc_unit *b); */
    pushq %rbp
    movq %rsp, %rbp

    // Load A.
    movq (a), Z0
    movq 8(a), Z1
    movq 16(a), Z2
    movq 24(a), Z3

    addq (%rdx), Z0
    adcq 8(%rdx), Z1
    adcq 16(%rdx), Z2
    adcq 24(%rdx), Z3

    // Carry once.
    sbbq q, q
    andq $38, q

    addq q, Z0
    adcq $0, Z1
    adcq $0, Z2
    adcq $0, Z3

    // Carry twice.
    sbbq q, q
    andq $38, q

    addq q, Z0

    // Write Z.
    movq Z0, (r)
    movq Z1, 8(r)
    movq Z2, 16(r)
    movq Z3, 24(r)

    popq %rbp
    ret


.align 4
.globl _ccn_submod_p25519
_ccn_submod_p25519: /* void ccn_submod_p25519(cc_unit *r, const cc_unit *a, const cc_unit *b); */
    pushq %rbp
    movq %rsp, %rbp

    // Load A.
    movq (a), Z0
    movq 8(a), Z1
    movq 16(a), Z2
    movq 24(a), Z3

    subq (%rdx), Z0
    sbbq 8(%rdx), Z1
    sbbq 16(%rdx), Z2
    sbbq 24(%rdx), Z3

    // Carry once.
    sbbq q, q
    andq $38, q

    subq q, Z0
    sbbq $0, Z1
    sbbq $0, Z2
    sbbq $0, Z3

    // Carry twice.
    sbbq q, q
    andq $38, q

    subq q, Z0

    // Write Z.
    movq Z0, (r)
    movq Z1, 8(r)
    movq Z2, 16(r)
    movq Z3, 24(r)

    popq %rbp
    ret


.align 4
.globl _ccn_mulmod_p25519
_ccn_mulmod_p25519: /* void ccn_mulmod_p25519(cc_unit *r, const cc_unit *a, const cc_unit *b); */
    pushq %rbp
    movq %rsp, %rbp
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15
    pushq %rbx

    #include "ccn_mul_256-x64.s"

L_reduce:
    // Reduce mod 2^256-38.
    movq $38, %rdx

    // Clear CF.
    xorq q, q

    // Z4 * 38
    mulxq Z4, q, v

    adox q, Z0
    adcx v, Z1

    // Z5 * 38
    mulxq Z5, q, v

    adox q, Z1
    adcx v, Z2

    // Z6 * 38
    mulxq Z6, q, v

    adox q, Z2
    adcx v, Z3

    // Z7 * 38
    mulxq Z7, q, Z4

    adox q, Z3

    movq $0, v
    adox v, Z4
    adcx v, Z4

    // Carry once.
    imulq $38, Z4

    addq Z4, Z0
    adcq $0, Z1
    adcq $0, Z2
    adcq $0, Z3

    // Carry twice.
    sbbq q, q
    andq $38, q

    addq q, Z0

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


.align 4
.globl _ccn_sqrmod_p25519
_ccn_sqrmod_p25519: /* void ccn_sqrmod_p25519(cc_unit *r, const cc_unit *a); */
    pushq %rbp
    movq %rsp, %rbp
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15
    pushq %rbx

    // Free %rdx.
    movq %rdx, b

    // Load A0.
    movq (a), %rdx

    // Z1 = A0 * A1
    mulxq 8(a), Z1, Z2

    // Z2 += A0 * A2
    mulxq 16(a), q, Z3

    // Z3 += A0 * A3
    mulxq 24(a), v, Z4

    addq q, Z2
    adcq v, Z3

    // Load A3.
    movq 24(a), %rdx

    // Z4 += A1 * A3
    mulxq 8(a), q, Z5

    // Z5 += A2 * A3
    mulxq 16(a), v, Z6

    adcq q, Z4
    adcq v, Z5
    adcq $0, Z6

    movq $0, Z7
    adcq $0, Z7

    // Load A1.
    movq 8(a), %rdx

    // Z3 += A1 * A2
    mulxq 16(a), q, v

    addq q, Z3
    adcq v, Z4
    adcq $0, Z5
    adcq $0, Z6
    adcq $0, Z7

    // Double intermediate results.
    addq Z1, Z1
    adcq Z2, Z2
    adcq Z3, Z3
    adcq Z4, Z4
    adcq Z5, Z5
    adcq Z6, Z6
    adcq Z7, Z7

    // Load A0.
    movq (a), %rdx

    // Z0 = A0 * A0
    mulxq %rdx, Z0, v

    addq v, Z1

    // Load A1.
    movq 8(a), %rdx

    // Z2 = A1 * A1
    mulxq %rdx, q, v

    adcq q, Z2
    adcq v, Z3

    // Load A2.
    movq 16(a), %rdx

    // Z4 = A2 * A2
    mulxq %rdx, q, v

    adcq q, Z4
    adcq v, Z5

    // Load A3.
    movq 24(a), %rdx

    // Z6 = A3 * A3
    mulxq %rdx, q, v

    adcq q, Z6
    adcq v, Z7

    // Reduce mod 2^256-38.
    jmp L_reduce

#endif

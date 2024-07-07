# Copyright (c) (2022,2023) Apple Inc. All rights reserved.
#
# corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
# is contained in the License.txt file distributed with corecrypto) and only to
# people who accept that license. IMPORTANT:  Any license rights granted to you by
# Apple Inc. (if any) are limited to internal use within your organization only on
# devices and computers you own or control, for the sole purpose of verifying the
# security characteristics and correct functioning of the Apple Software.  You may
# not, directly or indirectly, redistribute the Apple Software or any portions thereof.

#if defined(__arm64__)

#include "ccarm_pac_bti_macros.h"

.section __TEXT,__text,regular,pure_instructions
.globl _AccelerateCrypto_SHA3_keccak
.p2align 2

_AccelerateCrypto_SHA3_keccak:

    SIGN_LR

    sub sp, sp, #176
    stp x28, x27, [sp, #80]             ; 16-byte Folded Spill
    stp x26, x25, [sp, #96]             ; 16-byte Folded Spill
    stp x24, x23, [sp, #112]            ; 16-byte Folded Spill
    stp x22, x21, [sp, #128]            ; 16-byte Folded Spill
    stp x20, x19, [sp, #144]            ; 16-byte Folded Spill
    stp x29, x30, [sp, #160]            ; 16-byte Folded Spill

    mov x30, x0                         // &state->lanes[0]

    ldp x0, x1, [x30, #0*8]             // s00 s01
    ldp x2, x3, [x30, #2*8]             // s02 s03
    ldp x4, x5, [x30, #4*8]             // s04 s05
    ldp x6, x7, [x30, #6*8]             // s06 s07
    ldp x8, x9, [x30, #8*8]             // s08 s09
    ldp x10, x11, [x30, #10*8]          // s10 s11
    ldp x12, x13, [x30, #12*8]          // s12 s13
    ldp x14, x15, [x30, #14*8]          // s14 s15
    ldp x16, x17, [x30, #16*8]          // s16 s17
    ldp x28, x19, [x30, #18*8]          // s18 s19
    ldp x20, x21, [x30, #20*8]          // s20 s21
    ldp x22, x23, [x30, #22*8]          // s22 s23
    ldr x24, [x30, #24*8]               // s24

    #define s00 x0
    #define s01 x1
    #define s02 x2
    #define s03 x3
    #define s04 x4
    #define s05 x5
    #define s06 x6
    #define s07 x7
    #define s08 x8
    #define s09 x9
    #define s10 x10
    #define s11 x11
    #define s12 x12
    #define s13 x13
    #define s14 x14
    #define s15 x15
    #define s16 x16
    #define s17 x17
    #define s18 x28
    #define s19 x19
    #define s20 x20
    #define s21 x21
    #define s22 x22
    #define s23 x23
    #define s24 x24

    #define t0  x25
    #define t1  x26
    #define t2  x27
    #define t3  x29
    #define t4  x30

    mov x25, #0
    adrp    x26, l___const.cckeccak_f1600_c.keccak_round_constants@PAGE
Lloh1:
    add     x26, x26, l___const.cckeccak_f1600_c.keccak_round_constants@PAGEOFF

    str x30, [sp, #0]                   // save &state->lanes[0]
    str x25, [sp, #8]                   // save counter i
    str x26, [sp, #7*8]                 // save to point to keccak_round_constants table

L_loop:                                 ; =>This Inner Loop Header: Depth=1

    str s00, [sp,#2*8]
    eor s00, s00, s05
    str s01, [sp,#3*8]
    eor s01, s01, s06
    str s02, [sp,#4*8]
    eor s02, s02, s07
    str s03, [sp,#5*8]
    eor s03, s03, s08
    str s04, [sp,#6*8]
    eor s04, s04, s09

    eor s00, s00, s10
    eor s01, s01, s11
    eor s02, s02, s12
    eor s03, s03, s13
    eor s04, s04, s14

    eor s00, s00, s15
    eor s01, s01, s16
    eor s02, s02, s17
    eor s03, s03, s18
    eor s04, s04, s19

    eor s00, s00, s20
    eor s01, s01, s21
    eor s02, s02, s22
    eor s03, s03, s23
    eor s04, s04, s24

    eor t0, s04, s01, ror #63
    eor t1, s00, s02, ror #63
    eor t2, s01, s03, ror #63
    ldr s01, [sp, #3*8]
    eor t3, s02, s04, ror #63
    ldr s02, [sp, #4*8]
    eor t4, s03, s00, ror #63
    ldr s04, [sp, #6*8]

    // tmp = CC_ROL64(s01, 1);
    eor s01, s01, t1
    ldr s03, [sp, #5*8]
    ror s01, s01, #64-1
    ldr s00, [sp, #2*8]
    str s01, [sp, #3*8]      // save for later to move to s10

    .macro  cc_rol  s0, s1, rot, t
    eor \s0, \s1, \t
    ror \s0, \s0, #64-\rot
    .endm

    eor     s00, s00, t0
    cc_rol  s01, s06, 44, t1
    cc_rol  s06, s09, 20, t4
    cc_rol  s09, s22, 61, t2
    cc_rol  s22, s14, 39, t4
    cc_rol  s14, s20, 18, t0
    cc_rol  s20, s02, 62, t2
    cc_rol  s02, s12, 43, t2
    cc_rol  s12, s13, 25, t3
    cc_rol  s13, s19, 8, t4
    cc_rol  s19, s23, 56, t3
    cc_rol  s23, s15, 41, t0
    cc_rol  s15, s04, 27, t4
    cc_rol  s04, s24, 14, t4
    cc_rol  s24, s21, 2, t1
    cc_rol  s21, s08, 55, t3
    cc_rol  s08, s16, 45, t1
    cc_rol  s16, s05, 36, t0
    cc_rol  s05, s03, 28, t3
    cc_rol  s03, s18, 21, t3
    cc_rol  s18, s17, 15, t2
    cc_rol  s17, s11, 10, t1
    cc_rol  s11, s07, 6, t2
    cc_rol  s07, s10, 3, t0
    ldr     s10, [sp, #3*8]

    bic t0, s02, s01
    bic t1, s03, s02
    bic t2, s04, s03
    bic t3, s00, s04
    bic t4, s01, s00
    eor s00, s00, t0
    ldr t0, [sp, #7*8]
    eor s01, s01, t1
    eor s02, s02, t2
    ldr t1, [t0], #8
    eor s03, s03, t3
    eor s04, s04, t4
    eor s00, s00, t1
    str t0, [sp, #7*8]

    .macro   chi s0, s1, s2, s3, s4
    bic     t0, \s2, \s1
    bic     t1, \s3, \s2
    bic     t2, \s4, \s3
    bic     t3, \s0, \s4
    bic     t4, \s1, \s0
    eor     \s0, \s0, t0
    eor     \s1, \s1, t1
    eor     \s2, \s2, t2
    eor     \s3, \s3, t3
    eor     \s4, \s4, t4
    .endm

    chi s05, s06, s07, s08, s09
    chi s10, s11, s12, s13, s14
    chi s15, s16, s17, s18, s19
    chi s20, s21, s22, s23, s24

    ldr t0, [sp, #8]
    add t0, t0, #8
    str t0, [sp, #8]
    cmp t0, #192
    b.ne L_loop

    ldr x30, [sp, #0]                   // save &state->lanes[0]
    stp x0, x1, [x30, #0*8]             // s00 s01
    stp x2, x3, [x30, #2*8]             // s02 s03
    stp x4, x5, [x30, #4*8]             // s04 s05
    stp x6, x7, [x30, #6*8]             // s06 s07
    stp x8, x9, [x30, #8*8]             // s08 s09
    stp x10, x11, [x30, #10*8]          // s10 s11
    stp x12, x13, [x30, #12*8]          // s12 s13
    stp x14, x15, [x30, #14*8]          // s14 s15
    stp x16, x17, [x30, #16*8]          // s16 s17
    stp x28, x19, [x30, #18*8]          // s18 s19
    stp x20, x21, [x30, #20*8]          // s20 s21
    stp x22, x23, [x30, #22*8]          // s22 s23
    str x24, [x30, #24*8]               // s24

    ldp x29, x30, [sp, #160]            ; 16-byte Folded Reload
    ldp x20, x19, [sp, #144]            ; 16-byte Folded Reload
    ldp x22, x21, [sp, #128]            ; 16-byte Folded Reload
    ldp x24, x23, [sp, #112]            ; 16-byte Folded Reload
    ldp x26, x25, [sp, #96]             ; 16-byte Folded Reload
    ldp x28, x27, [sp, #80]             ; 16-byte Folded Reload
    add sp, sp, #176

    AUTH_LR_AND_RET

    .section __TEXT,__const
    .p2align 3                            ; @__const.cckeccak_f1600_c.keccak_round_constants
l___const.cckeccak_f1600_c.keccak_round_constants:
    .quad 1                               ; 0x1
    .quad 32898                           ; 0x8082
    .quad -9223372036854742902            ; 0x800000000000808a
    .quad -9223372034707259392            ; 0x8000000080008000
    .quad 32907                           ; 0x808b
    .quad 2147483649                      ; 0x80000001
    .quad -9223372034707259263            ; 0x8000000080008081
    .quad -9223372036854743031            ; 0x8000000000008009
    .quad 138                             ; 0x8a
    .quad 136                             ; 0x88
    .quad 2147516425                      ; 0x80008009
    .quad 2147483658                      ; 0x8000000a
    .quad 2147516555                      ; 0x8000808b
    .quad -9223372036854775669            ; 0x800000000000008b
    .quad -9223372036854742903            ; 0x8000000000008089
    .quad -9223372036854743037            ; 0x8000000000008003
    .quad -9223372036854743038            ; 0x8000000000008002
    .quad -9223372036854775680            ; 0x8000000000000080
    .quad 32778                           ; 0x800a
    .quad -9223372034707292150            ; 0x800000008000000a
    .quad -9223372034707259263            ; 0x8000000080008081
    .quad -9223372036854742912            ; 0x8000000000008080
    .quad 2147483649                      ; 0x80000001
    .quad -9223372034707259384            ; 0x8000000080008008

#endif

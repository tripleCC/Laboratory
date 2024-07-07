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

	.section	__TEXT,__text,regular,pure_instructions
.arch  armv8.2-a+sha3
	.globl	_AccelerateCrypto_SHA3_keccak_hwassist
	.p2align	2
_AccelerateCrypto_SHA3_keccak_hwassist:

    str x29,[sp,#-80]!
    add x29,sp,#0
    stp d8,d9,[sp,#16]      // per ABI requirement
    stp d10,d11,[sp,#32]
    stp d12,d13,[sp,#48]
    stp d14,d15,[sp,#64]

    ldp d0,d1,[x0,#8*0]
    ldp d2,d3,[x0,#8*2]
    ldp d4,d5,[x0,#8*4]
    ldp d6,d7,[x0,#8*6]
    ldp d8,d9,[x0,#8*8]
    ldp d10,d11,[x0,#8*10]
    ldp d12,d13,[x0,#8*12]
    ldp d14,d15,[x0,#8*14]
    ldp d16,d17,[x0,#8*16]
    ldp d18,d19,[x0,#8*18]
    ldp d20,d21,[x0,#8*20]
    ldp d22,d23,[x0,#8*22]
    ldr d24,[x0,#8*24]

    #define s00 v0
    #define s01 v1
    #define s02 v2
    #define s03 v3
    #define s04 v4
    #define s05 v5
    #define s06 v6
    #define s07 v7
    #define s08 v8
    #define s09 v9
    #define s10 v10
    #define s11 v11
    #define s12 v12
    #define s13 v13
    #define s14 v14
    #define s15 v15
    #define s16 v16
    #define s17 v17
    #define s18 v18
    #define s19 v19
    #define s20 v20
    #define s21 v21
    #define s22 v22
    #define s23 v23
    #define s24 v24

	mov	x2, #0
    adrp    x3, l___const.cckeccak_f1600_c.keccak_round_constants@PAGE
Lloh1:
    add     x3, x3, l___const.cckeccak_f1600_c.keccak_round_constants@PAGEOFF

L_loop:                                 ; =>This Inner Loop Header: Depth=1

    // Function theta, as per FIPS-202 3.2.1.
    eor3.16b    v25, v0, v5, v10
    eor3.16b    v26, v1, v6, v11
    eor3.16b    v27, v2, v7, v12
    eor3.16b    v28, v3, v8, v13
    eor3.16b    v29, v4, v9, v14
    eor3.16b    v25, v25, v15, v20
    eor3.16b    v26, v26, v16, v21
    eor3.16b    v27, v27, v17, v22
    eor3.16b    v28, v28, v18, v23
    eor3.16b    v29, v29, v19, v24

    rax1.2d    v30, v25, v27            // D[1]
    rax1.2d    v31, v26, v28            // D[2]
    rax1.2d    v27, v27, v29            // D[3]
    rax1.2d    v28, v28, v25            // D[4]
    rax1.2d    v29, v29, v26            // D[0]

    #define t0  v29
    #define t1  v30
    #define t2  v31
    #define t3  v27
    #define t4  v28

    // Function rho & pi, as per FIPS-202 3.2.2 & 3.2.3
    .macro  cc_rol  s0, s1, rot, t
    xar.2d  \s0, \s1, \t, #64-\rot
    .endm

    cc_rol      v25, s01, 1, t1      // d25 = s10
    cc_rol      s01, s06, 44, t1
    cc_rol      s06, s09, 20, t4
    cc_rol      s09, s22, 61, t2
    cc_rol      s22, s14, 39, t4
    cc_rol		s14, s20, 18, t0
	cc_rol		s20, s02, 62, t2
	cc_rol		s02, s12, 43, t2
	cc_rol		s12, s13, 25, t3
	cc_rol		s13, s19, 8, t4
	cc_rol		s19, s23, 56, t3
	cc_rol		s23, s15, 41, t0
	cc_rol		s15, s04, 27, t4

	cc_rol		v26, s21, 2, t1     // v26 = s24
	cc_rol		s08, s08, 55, t3    // s08 = s21

    eor.16b     s00, s00, t0
    bcax.16b    s21, s08, s23, s22 
	cc_rol		t4, s24, 14, t4     // t4 = s04
    bcax.16b    s24, v26, s08, s20
	cc_rol		s18, s18, 21, t3     // s18 = s03
    bcax.16b    s23, s23, s20, v26
    cc_rol      s11, s11, 10, t1     // s11 = s17
    bcax.16b    s20, s20, s22, s08 
	cc_rol		t1, s16, 45, t1    // v26 = s08
    bcax.16b    s22, s22, v26, s23


	cc_rol		s16, s05, 36, t0
	cc_rol		t3, s03, 28, t3 


    bcax.16b    s03, s18, s00, t4
    cc_rol      t0, s10, 3, t0      // t0 = s07
    bcax.16b    s04, t4, s01, s00
	cc_rol		s10, s17, 15, t2     // s10 = s18
    bcax.16b    s00, s00, s02, s01 
    cc_rol      s07, s07, 6, t2      // t2 = s11
    bcax.16b    s01, s01, s18, s02 
    bcax.16b    s02, s02, t4, s18

    bcax.16b    s17, s11, s19, s10
    bcax.16b    s18, s10, s15, s19
    bcax.16b    s19, s19, s16, s15
    bcax.16b    s15, s15, s11, s16 
    bcax.16b    s16, s16, s10, s11 


    bcax.16b    s10, v25, s12, s07
    bcax.16b    s11, s07, s13, s12 
    bcax.16b    s12, s12, s14, s13
    bcax.16b    s13, s13, v25, s14
    bcax.16b    s14, s14, s07, v25

    ldr         d26, [x3]
    bcax.16b    s07, t0, s09, t1
    bcax.16b    s08, t1, t3, s09
    bcax.16b    s09, s09, s06, t3
    bcax.16b    s05, t3, t0, s06
    add         x3, x3, #8
    bcax.16b    s06, s06, t1, t0 

    add     x2, x2, #8
    eor.8b  s00, s00, v26

	cmp	    x2, #192
	b.ne	L_loop

    stp d0,d1,[x0,#8*0]
    stp d2,d3,[x0,#8*2]
    stp d4,d5,[x0,#8*4]
    stp d6,d7,[x0,#8*6]
    stp d8,d9,[x0,#8*8]
    stp d10,d11,[x0,#8*10]
    stp d12,d13,[x0,#8*12]
    stp d14,d15,[x0,#8*14]
    stp d16,d17,[x0,#8*16]
    stp d18,d19,[x0,#8*18]
    stp d20,d21,[x0,#8*20]
    stp d22,d23,[x0,#8*22]
    str d24,[x0,#8*24]

    ldp d8,d9,[sp,#16]
    ldp d10,d11,[sp,#32]
    ldp d12,d13,[sp,#48]
    ldp d14,d15,[sp,#64]
    ldr x29,[sp],#80


	ret

	.section	__TEXT,__const
	.p2align	3                               ; @__const.cckeccak_f1600_c.keccak_round_constants
l___const.cckeccak_f1600_c.keccak_round_constants:
	.quad	1                               ; 0x1
	.quad	32898                           ; 0x8082
	.quad	-9223372036854742902            ; 0x800000000000808a
	.quad	-9223372034707259392            ; 0x8000000080008000
	.quad	32907                           ; 0x808b
	.quad	2147483649                      ; 0x80000001
	.quad	-9223372034707259263            ; 0x8000000080008081
	.quad	-9223372036854743031            ; 0x8000000000008009
	.quad	138                             ; 0x8a
	.quad	136                             ; 0x88
	.quad	2147516425                      ; 0x80008009
	.quad	2147483658                      ; 0x8000000a
	.quad	2147516555                      ; 0x8000808b
	.quad	-9223372036854775669            ; 0x800000000000008b
	.quad	-9223372036854742903            ; 0x8000000000008089
	.quad	-9223372036854743037            ; 0x8000000000008003
	.quad	-9223372036854743038            ; 0x8000000000008002
	.quad	-9223372036854775680            ; 0x8000000000000080
	.quad	32778                           ; 0x800a
	.quad	-9223372034707292150            ; 0x800000008000000a
	.quad	-9223372034707259263            ; 0x8000000080008081
	.quad	-9223372036854742912            ; 0x8000000000008080
	.quad	2147483649                      ; 0x80000001
	.quad	-9223372034707259384            ; 0x8000000080008008

#endif

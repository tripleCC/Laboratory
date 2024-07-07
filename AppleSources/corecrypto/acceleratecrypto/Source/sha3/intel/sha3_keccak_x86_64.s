# Copyright (c) (2023) Apple Inc. All rights reserved.
#
# corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
# is contained in the License.txt file distributed with corecrypto) and only to
# people who accept that license. IMPORTANT:  Any license rights granted to you by
# Apple Inc. (if any) are limited to internal use within your organization only on
# devices and computers you own or control, for the sole purpose of verifying the
# security characteristics and correct functioning of the Apple Software.  You may
# not, directly or indirectly, redistribute the Apple Software or any portions thereof.

#if defined __x86_64__

	.text
	.globl	_AccelerateCrypto_SHA3_keccak
	.p2align	4, 0x90
_AccelerateCrypto_SHA3_keccak:
	pushq	%rbp
	movq	%rsp, %rbp
	pushq	%r15
	pushq	%r14
	pushq	%r13
	pushq	%r12
	pushq	%rbx
    sub     $16, %rsp

    movq    0*8(%rdi), %rax            // s00
    movq    1*8(%rdi), %rsi            // s01
    movq    2*8(%rdi), %rdx            // s02
    movq    3*8(%rdi), %rcx            // s03
    movq    4*8(%rdi), %r15            // s04

	xorq	%r9, %r9
	.p2align	4, 0x90
L_loop:                                 ## =>This Inner Loop Header: Depth=1
    movq    %rax, %r10                  // s00
    movq    %rsi, %r11                  // s01
    movq    %rdx, %r12                  // s02
    movq    %rcx, %r13                  // s03
    movq    %r15, %r14                  // s04

    // s0i ^ s0i+5
    xorq    5*8(%rdi), %r10
    xorq    6*8(%rdi), %r11
    xorq    7*8(%rdi), %r12
    xorq    8*8(%rdi), %r13
    xorq    9*8(%rdi), %r14

    // s0i ^ s0i+5 ^ s0i+10
    xorq    10*8(%rdi), %r10
    xorq    11*8(%rdi), %r11
    xorq    12*8(%rdi), %r12
    xorq    13*8(%rdi), %r13
    xorq    14*8(%rdi), %r14

    // s0i ^ s0i+5 ^ s0i+10 ^ s0i+15
    xorq    15*8(%rdi), %r10
    xorq    16*8(%rdi), %r11
    xorq    17*8(%rdi), %r12
    xorq    18*8(%rdi), %r13
    xorq    19*8(%rdi), %r14

    // s0i ^ s0i+5 ^ s0i+10 ^ s0i+15 ^ s0i+20
    xorq    20*8(%rdi), %r10
    xorq    21*8(%rdi), %r11
    xorq    22*8(%rdi), %r12
    xorq    23*8(%rdi), %r13
    xorq    24*8(%rdi), %r14


    // tmp = t4 ^ CC_ROL64(t1, 1);
    // tmp = t0 ^ CC_ROL64(t2, 1);
    // tmp = t2 ^ CC_ROL64(t4, 1);
    // tmp = t1 ^ CC_ROL64(t3, 1);
    // tmp = t3 ^ CC_ROL64(t0, 1);

    rorx    $63, %r11, %r8
    rorx    $63, %r12, %rbx
    xorq    %r14, %r8
    rolq    $1, %r14
    xorq    %r10, %rbx
    rolq    $1, %r10
    xorq    %r14, %r12
    rorx    $63, %r13, %r14
    xorq    %r10, %r13
    xorq    %r11, %r14


    // tmp = CC_ROL64(s01, 1);
    xorq    %rbx, %rsi
    rolq    $1, %rsi
    movq    %rsi, 0(%rsp)

    // s01 = CC_ROL64(s06, 44);
    movq    6*8(%rdi), %rsi
    xorq    %rbx, %rsi
    rolq    $44, %rsi

    // s06 = CC_ROL64(s09, 20);
    movq    %r13, %r11
    xorq    9*8(%rdi), %r11
    rolq    $20, %r11
    movq    %r11, 6*8(%rdi)

    // s09 = CC_ROL64(s22, 61);
    movq    %r14, %r11
    xorq    22*8(%rdi), %r11
    rolq    $61, %r11
    movq    %r11, 9*8(%rdi)

    // s22 = CC_ROL64(s14, 39);
    movq    %r13, %r11
    xorq    14*8(%rdi), %r11
    rolq    $39, %r11
    movq    %r11, 22*8(%rdi)

    // s14 = CC_ROL64(s20, 18);
    movq    %r8, %r11
    xorq    20*8(%rdi), %r11
    rolq    $18, %r11
    movq    %r11, 14*8(%rdi)

    // s20 = CC_ROL64(s02, 62);
    xorq    %r14, %rdx
    rolq    $62, %rdx
    movq    %rdx, 20*8(%rdi)

    // s02 = CC_ROL64(s12, 43);
    movq    12*8(%rdi), %rdx
    xorq    %r14, %rdx
    rolq    $43, %rdx

    // s12 = CC_ROL64(s13, 25);
    movq    %r12, %r11
    xorq    13*8(%rdi), %r11
    rolq    $25, %r11
    movq    %r11, 12*8(%rdi)

    // s13 = CC_ROL64(s19, 8);
    movq    %r13, %r11
    xorq    19*8(%rdi), %r11
    rolq    $8, %r11
    movq    %r11, 13*8(%rdi)

    // s19 = CC_ROL64(s23, 56);
    movq    %r12, %r11
    xorq    23*8(%rdi), %r11
    rolq    $56, %r11
    movq    %r11, 19*8(%rdi)

    // s23 = CC_ROL64(s15, 41);
    movq    %r8, %r11
    xorq    15*8(%rdi), %r11
    rolq    $41, %r11
    movq    %r11, 23*8(%rdi)

    // s15 = CC_ROL64(s04, 27);
    xorq    %r13, %r15
    rolq    $27, %r15
    movq    %r15, 15*8(%rdi)

    // s04 = CC_ROL64(s24, 14);
    movq    24*8(%rdi), %r15
    xorq    %r13, %r15
    rolq    $14, %r15

    // s24 = CC_ROL64(s21, 2);
    movq    %rbx, %r11
    xorq    21*8(%rdi), %r11
    rolq    $2, %r11
    movq    %r11, 24*8(%rdi)

    // s21 = CC_ROL64(s08, 55);
    movq    %r12, %r11
    xorq    8*8(%rdi), %r11
    rolq    $55, %r11
    movq    %r11, 21*8(%rdi)

    // s08 = CC_ROL64(s16, 45);
    movq    %rbx, %r11
    xorq    16*8(%rdi), %r11
    rolq    $45, %r11
    movq    %r11, 8*8(%rdi)

    // s16 = CC_ROL64(s05, 36);
    movq    %r8, %r11
    xorq    5*8(%rdi), %r11
    rolq    $36, %r11
    movq    %r11, 16*8(%rdi)

    // s05 = CC_ROL64(s03, 28);
    xorq    %r12, %rcx
    rolq    $28, %rcx
    movq    %rcx, 5*8(%rdi)

    // s03 = CC_ROL64(s18, 21);
    movq    18*8(%rdi), %rcx
    xorq    %r12, %rcx
    rolq    $21, %rcx

    // s18 = CC_ROL64(s17, 15);
    movq    %r14, %r11
    xorq    17*8(%rdi), %r11
    rolq    $15, %r11
    movq    %r11, 18*8(%rdi)

    // s17 = CC_ROL64(s11, 10);
    xorq    11*8(%rdi), %rbx
    rolq    $10, %rbx
    movq    %rbx, 17*8(%rdi)

    // s11 = CC_ROL64(s07, 6);
    xorq    7*8(%rdi), %r14
    rolq    $6, %r14
    movq    %r14, 11*8(%rdi)

    xorq    %r8, %rax

    // s07 = CC_ROL64(s10, 3);
    xorq    10*8(%rdi), %r8
    rolq    $3, %r8
    movq    %r8, 7*8(%rdi)

    // s10 = tmp;
    movq    0(%rsp), %r12
    movq    %r12, 10*8(%rdi)

    andnq   %rsi, %rax, %r10
    andnq   %rdx, %rsi, %r8
    leaq    _keccak_round_constants(%rip), %r11
    andnq   %rcx, %rdx, %r12
    andnq   %r15, %rcx, %r13
    andnq   %rax, %r15, %r14

    xorq    (%r9,%r11), %r8

    xorq    %r10, %r15
    xorq    %r8, %rax
    xorq    %r12, %rsi
    xorq    %r13, %rdx
    xorq    %r14, %rcx

    movq    5*8(%rdi), %r8
    movq    6*8(%rdi), %r11
    movq    7*8(%rdi), %r12
    movq    8*8(%rdi), %r13
    movq    9*8(%rdi), %r14
    andnq   %r11, %r8, %r10
    andnq   %r12, %r11, %r11
    andnq   %r13, %r12, %r12
    andnq   %r14, %r13, %r13
    andnq   %r8, %r14, %r14
    xorq    %r10, 9*8(%rdi)
    xorq    %r11, 5*8(%rdi)
    xorq    %r12, 6*8(%rdi)
    xorq    %r13, 7*8(%rdi)
    xorq    %r14, 8*8(%rdi)

    movq    10*8(%rdi), %r8
    movq    11*8(%rdi), %r11
    movq    12*8(%rdi), %r12
    movq    13*8(%rdi), %r13
    movq    14*8(%rdi), %r14
    andnq   %r11, %r8, %r10
    andnq   %r12, %r11, %r11
    andnq   %r13, %r12, %r12
    andnq   %r14, %r13, %r13
    andnq   %r8, %r14, %r14
    xorq    %r10, 14*8(%rdi)
    xorq    %r11, 10*8(%rdi)
    xorq    %r12, 11*8(%rdi)
    xorq    %r13, 12*8(%rdi)
    xorq    %r14, 13*8(%rdi)

    movq    15*8(%rdi), %r8
    movq    16*8(%rdi), %r11
    movq    17*8(%rdi), %r12
    movq    18*8(%rdi), %r13
    movq    19*8(%rdi), %r14
    andnq   %r11, %r8, %r10
    andnq   %r12, %r11, %r11
    andnq   %r13, %r12, %r12
    andnq   %r14, %r13, %r13
    andnq   %r8, %r14, %r14
    xorq    %r10, 19*8(%rdi)
    xorq    %r11, 15*8(%rdi)
    xorq    %r12, 16*8(%rdi)
    xorq    %r13, 17*8(%rdi)
    xorq    %r14, 18*8(%rdi)

    movq    20*8(%rdi), %r8
    movq    21*8(%rdi), %r11
    movq    22*8(%rdi), %r12
    movq    23*8(%rdi), %r13
    movq    24*8(%rdi), %r14
    andnq   %r11, %r8, %r10
    andnq   %r12, %r11, %r11
    andnq   %r13, %r12, %r12
    andnq   %r14, %r13, %r13
    andnq   %r8, %r14, %r14
    xorq    %r10, 24*8(%rdi)
    xorq    %r11, 20*8(%rdi)
    xorq    %r12, 21*8(%rdi)
    xorq    %r13, 22*8(%rdi)
    xorq    %r14, 23*8(%rdi)

	addq	$8, %r9
	cmpq	$192, %r9
	jne	L_loop

    movq    %rax, 0*8(%rdi)
    movq    %rsi, 1*8(%rdi)
    movq    %rdx, 2*8(%rdi)
    movq    %rcx, 3*8(%rdi)
    movq    %r15, 4*8(%rdi)

    add     $16, %rsp
	popq	%rbx
	popq	%r12
	popq	%r13
	popq	%r14
	popq	%r15
	popq	%rbp
	retq

	.text
	.globl	_keccak_round_constants         ## @keccak_round_constants
	.p2align	4
_keccak_round_constants:
	.quad	1                               ## 0x1
	.quad	32898                           ## 0x8082
	.quad	-9223372036854742902            ## 0x800000000000808a
	.quad	-9223372034707259392            ## 0x8000000080008000
	.quad	32907                           ## 0x808b
	.quad	2147483649                      ## 0x80000001
	.quad	-9223372034707259263            ## 0x8000000080008081
	.quad	-9223372036854743031            ## 0x8000000000008009
	.quad	138                             ## 0x8a
	.quad	136                             ## 0x88
	.quad	2147516425                      ## 0x80008009
	.quad	2147483658                      ## 0x8000000a
	.quad	2147516555                      ## 0x8000808b
	.quad	-9223372036854775669            ## 0x800000000000008b
	.quad	-9223372036854742903            ## 0x8000000000008089
	.quad	-9223372036854743037            ## 0x8000000000008003
	.quad	-9223372036854743038            ## 0x8000000000008002
	.quad	-9223372036854775680            ## 0x8000000000000080
	.quad	32778                           ## 0x800a
	.quad	-9223372034707292150            ## 0x800000008000000a
	.quad	-9223372034707259263            ## 0x8000000080008081
	.quad	-9223372036854742912            ## 0x8000000000008080
	.quad	2147483649                      ## 0x80000001
	.quad	-9223372034707259384            ## 0x8000000080008008

#endif

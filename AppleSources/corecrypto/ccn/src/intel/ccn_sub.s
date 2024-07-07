# Copyright (c) (2011,2015,2016,2018,2019,2021) Apple Inc. All rights reserved.
#
# corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
# is contained in the License.txt file distributed with corecrypto) and only to
# people who accept that license. IMPORTANT:  Any license rights granted to you by
# Apple Inc. (if any) are limited to internal use within your organization only on
# devices and computers you own or control, for the sole purpose of verifying the
# security characteristics and correct functioning of the Apple Software.  You may
# not, directly or indirectly, redistribute the Apple Software or any portions thereof.

#include <corecrypto/cc_config.h>


#if (defined(__x86_64__) || defined(__i386__)) && CCN_SUB_ASM

	        .globl  _ccn_sub_asm
        .p2align  4, 0x90
_ccn_sub_asm:

#ifdef	__x86_64__

		// push rbp and set up frame base
        pushq   %rbp
        movq    %rsp, %rbp

		// symbolicate used registers

		#define	size	%rdi			// size in cc_unit (8-bytes)
		#define	r		%rsi			// destination
		#define	s		%rdx			// source 1
		#define	t		%rcx			// source 2

		#define	o		%rax
		#define	i		%r8

		xor		o, o					// used as a potential output (carry = 0 for size=0), and also sahf for an initial carry = 0

		// macro for adding 2 quad-words
		.macro	mysbb arg0
        movq    \arg0(s, i, 8), o			// 2nd source
        sbbq	\arg0(t, i, 8), o			// add with carry 1st source
		movq	o, \arg0(r, i, 8)			// save to destination
		.endm

		xor		i, i					// address offset and also loop counter

		subq	$4, size
		jl		2f						// if size < 4, skip the following code that processes 4 blocks/iteration

0:

		sahf							// load Carry from ah
		mysbb	0
		mysbb	8
		mysbb	16
		mysbb	24
		lahf							// save Carry in ah
		add		$4, i					// i+=4;
		subq	$4, size					// size vs i
		jge		0b						// repeat if size > i

2:		
		testq	$2, size
		je		1f						// if size < 2, skip the following code that process 2 blocks
		sahf							// load Carry from ah
		mysbb	0
		mysbb	8
		lahf							// save Carry in ah
		add		$2, i					// i+=4;

1:		testq	$1, size
		je		3f
		sahf							// load Carry from ah
		mysbb	0
		lahf							// save Carry in ah
3:
		xor     i, i
		sahf
		adc		$0, i // to return the final carry signal
		mov     i, o


9:
        popq    %rbp
        ret

#else		// i386

		// set up frame and push save/restore registers
		push	%ebp
		mov		%esp, %ebp
		push    %ebx
	    push    %esi
		push    %edi

		// symbolicate registers
		#define	size	%edi
		#define	r		%esi
		#define	s		%edx
		#define	t		%ecx
		#define	o		%eax
		#define i		%ebx

		movl	8(%ebp), size
		movl	12(%ebp), r
		movl	16(%ebp), s
		movl	20(%ebp), t

		xor		o, o				// used as a potential output (carry = 0 for size=0), and also sahf for an initial carry = 0

		cmp		$0, size
		jle		9f					// early exit should size <= 0

		// macro for add with carry for 2 4-byte words
		.macro mysbb arg0
		movl	\arg0(s, i, 4), o
		sbbl	\arg0(t, i, 4), o
		movl	o, \arg0(r, i, 4)
		.endm

		xor		i, i				// 4-byte index

		subl	$8, size
		jl		4f					// if size < 8, skip the code that processes 8 blocks/iteration
0:
		sahf
		mysbb	0
		mysbb	4
		mysbb	8
		mysbb	12
		mysbb	16
		mysbb	20
		mysbb	24
		mysbb	28
		lahf
		addl	$8, i
		subl	$8, size
		jge		0b

4:
		testl	$4, size
		je		2f					// if size < 4, skip the code that processes the remaining 4 blocks
		sahf
		mysbb	0
		mysbb	4
		mysbb	8
		mysbb	12
		lahf
		addl	$4, i

2:
		testl	$2, size
		je		1f					// if size < 2, skip the code that processes the remaining 2 blocks
		sahf
		mysbb	0
		mysbb	4
		lahf
		addl	$2, i

1:
		testl	$1, size
		je		3f					// if size < 1, skip the code that processes the remaining 1 block
		sahf
		mysbb	0
		lahf
3:
		xor     i, i
		sahf
		adc		$0, i // to return the final carry signal
		mov     i, o
9:
		pop		%edi
		pop		%esi
		pop		%ebx
		pop		%ebp
		ret

#endif
#endif


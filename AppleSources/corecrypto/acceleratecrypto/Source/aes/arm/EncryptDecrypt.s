# Copyright (c) (2011-2016,2019,2022) Apple Inc. All rights reserved.
#
# corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
# is contained in the License.txt file distributed with corecrypto) and only to
# people who accept that license. IMPORTANT:  Any license rights granted to you by
# Apple Inc. (if any) are limited to internal use within your organization only on
# devices and computers you own or control, for the sole purpose of verifying the
# security characteristics and correct functioning of the Apple Software.  You may
# not, directly or indirectly, redistribute the Apple Software or any portions thereof.

#include <corecrypto/cc_config.h>

#if CCAES_ARM_ASM && CC_ARM_ARCH_7

#define	S0	r0
#define	S1	r1
#define	S2	r2
#define	S3	r3

#if Select == 0
	#define	Name		_AccelerateCrypto_AES_encrypt   // Routine name.
	#define	MTable		_AESEncryptTable			    // Main table.
	#define	FTable		_AESSubBytesWordTable		    // Final table.
	#define	P0			S0							    // State permutation.
	#define	P1			S1
	#define	P2			S2
	#define	P3			S3
	#define	Increment	+16							    // ExpandedKey increment.
#elif Select == 1
	#define	Name		_AccelerateCrypto_AES_decrypt   // Routine name.
	#define	MTable		_AESDecryptTable			    // Main table.
	#define	FTable		_AESInvSubBytesWordTable	    // Final table.
	#define	P0			S2							    // State permutation.
	#define	P1			S3
	#define	P2			S0
	#define	P3			S1
	#define	Increment	-16							// ExpandedKey increment.
#endif	// Select

#if defined(__ARM_NEON__)   // vpaes uses NEON instructions
    .extern _AccelerateCrypto_vpaes_encrypt
    .extern _AccelerateCrypto_vpaes_decrypt
#endif

#define	ExpandedKey			r11
#define	ExpandedKeyEnd		lr
#define	ContextKeyLength	240	
#define	t					r12

.subsections_via_symbols
	.text
    .syntax unified
    .p2align  2
    .code   16
    .thumb_func Name
	.globl Name
Name:
#if defined(__ARM_NEON__)   // if neon is available, use cache-attack resilient vector permute AES

#if Select == 0
    b   _AccelerateCrypto_vpaes_encrypt
#else
    b   _AccelerateCrypto_vpaes_decrypt
#endif

#else   // __ARM_NEON__

	// set up debug trace frame pointer
	push	{r7,lr}
	mov		r7, sp

	// now setup the stack for the current function
	push	{r1,r4-r6,r8-r11}
	sub		sp, #(16+8)         // make sp 16-byte aligned

	// copy r0,r2 to r4,r11 to release r0,r2 (r1 is saved in stack) for use as S0-S3
	mov		r4, r0
	mov		ExpandedKey, r2

	// Get and check "key length".
	ldr		t, [ExpandedKey, #ContextKeyLength]
	cmp		t, #160
	beq		2f
	cmp		t, #192
	beq		2f
	cmp		t, #224
	beq		2f
	mov		r0, #-1		// Return error.
	b		9f
2:

	#if (Select == 0)
		// For encryption, prepare to iterate forward through expanded key.
		add		ExpandedKeyEnd, ExpandedKey, t
	#else
		// For decryption, prepare to iterate backward through expanded key.
		mov		ExpandedKeyEnd, ExpandedKey
		add		ExpandedKey, t
	#endif

    /*
        we need to do this for otherwise ldmia $0, {$1-$4} will hit memory access error when $0 is not word-aligned in thumb state
    */
    .macro  thumb2_ldmia
    ldr     $1, [$0, #0]
    ldr     $2, [$0, #4]
    ldr     $3, [$0, #8]
    ldr     $4, [$0, #12]
    .endm

    .macro  thumb2_stmia
    str     $1, [$0, #0]
    str     $2, [$0, #4]
    str     $3, [$0, #8]
    str     $4, [$0, #12]
    .endm

	// Initialize State from input text.
    // we need to do this otherwise ldmia will crash when input (pointed by r4) is not word aligned
    thumb2_ldmia    r4, S0, S1, S2, S3

	// Add round key and save results.
    thumb2_ldmia    ExpandedKey, r4, r5, r8, r10 
	add		ExpandedKey, #Increment

	eor		S0, r4
	eor		S1, r5
	eor		S2, r8
	eor		S3, r10
	
	// Set up r6 = _AESEncryptTable or _AESDecryptTable
    ldr		r6, L_table1
L_table0:	
    mov     r12, pc
    ldr     r6, [r12, r6]

	// save S0-S3 in the stack memory
	stmia	sp, {S0-S3}

	// use this to extract byte from a shifted word, tried use uxtb, same complexity, but then limit to armv6 or above
	mov		r9, #0xff

	// Get round key.
	thumb2_ldmia	ExpandedKey, S0, S1, S2, S3
	add		ExpandedKey, #Increment 

	// per round operation

	/*
        the following macro defines the per round operation for aes
        the state computed from the previous round is now saved in sp[0:15]
        and r0-r3 has been initialized with the next expanded round key
        the macro reads those 16 bytes in sp[0:15] and for each byte does a table look up
        the result (4-byte) word is xor-ed to one of r0-r3
        the final r0-r3 is the aes state
        r6 : points to Main or Final table
        r9 : 0xff is used as a byte mask
    */

	.macro	aes_per_round

#if defined (__ARM_ARCH_7S__)
    // better for swift and (old cortex-a8) 

	// S0 process
	ldr		t, [sp, #0]					// load 4 bytes for S0 process
	and		r4, r9, t					// byte 0
	and		r5, r9, t, lsr #8			// byte 1
	ldr		r4, [r6, r4, lsl #2]		// 1st table lookup
	and		r8, r9, t, lsr #16			// byte 2
	ldr		r5, [r6, r5, lsl #2]		// 2nd table lookup
	and		r10, r9, t, lsr #24			// byte 3
	ldr		r8, [r6, r8, lsl #2]		// 3rd table lookup
	eor		S0, r4						// S0 ^= 1st table lookup
	ldr		r10, [r6, r10, lsl #2]		// 4th table lookup
	eor		P3, r5, ror #24				// P3 ^= 2nd table lookup
	ldr		t, [sp, #4]					//   read Word for next S1 process
	eor		S2, r8, ror #16				// S2 ^= 3rd table lookup
	eor		P1, r10, ror #8				// P1 ^= 4th table lookup

	// S1 process
	and		r4, r9, t
	and		r5, r9, t, lsr #8
	ldr		r4, [r6, r4, lsl #2]
	and		r8, r9, t, lsr #16
	ldr		r5, [r6, r5, lsl #2]
	and		r10, r9, t, lsr #24
	ldr		r8, [r6, r8, lsl #2]
	eor		S1, r4
	ldr		r10, [r6, r10, lsl #2]
	eor		P0, r5, ror #24
	ldr		t, [sp, #8]
	eor		S3, r8, ror #16
	eor		P2, r10, ror #8

	// S2 process
	and		r4, r9, t
	and		r5, r9, t, lsr #8
	ldr		r4, [r6, r4, lsl #2]
	and		r8, r9, t, lsr #16
	ldr		r5, [r6, r5, lsl #2]
	and		r10, r9, t, lsr #24
	ldr		r8, [r6, r8, lsl #2]
	eor		S2, r4
	ldr		r10, [r6, r10, lsl #2]
	eor		P1, r5, ror #24
	ldr		t, [sp, #12]
	eor		S0, r8, ror #16
	eor		P3, r10, ror #8

	// S3 process
	and		r4, r9, t
	and		r5, r9, t, lsr #8
	ldr		r4, [r6, r4, lsl #2]
	and		r8, r9, t, lsr #16
	ldr		r5, [r6, r5, lsl #2]
	and		r10, r9, t, lsr #24
	ldr		r8, [r6, r8, lsl #2]
	eor		S3, r4
	ldr		r10, [r6, r10, lsl #2]
	eor		P2, r5, ror #24
	eor		S1, r8, ror #16
	eor		P0, r10, ror #8

#else

    // better for cortex-a7 and cortex-a9

    // S0 process
	ldrb	r4, [sp, #0]					// byte 0
	ldrb	r5, [sp, #1]					// byte 1 
	ldrb	r8, [sp, #2]					// byte 2
	ldrb	r10, [sp, #3]					// byte 3 
	ldr		r4, [r6, r4, lsl #2]		// 1st table lookup
	ldr		r5, [r6, r5, lsl #2]		// 2nd table lookup
	ldr		r8, [r6, r8, lsl #2]		// 1st table lookup
	eor		S0, r4						// S0 ^= 1st table lookup
	ldr		r10, [r6, r10, lsl #2]		// 2nd table lookup
	eor		P3, r5, ror #24				// P3 ^= 2nd table lookup
	eor		S2, r8, ror #16				// S2 ^= 3rd table lookup
	eor		P1, r10, ror #8				// P1 ^= 4th table lookup

    // S1 process
	ldrb	r4, [sp, #4]					// byte 0
	ldrb	r5, [sp, #5]					// byte 1 
	ldrb	r8, [sp, #6]					// byte 2
	ldrb	r10, [sp, #7]					// byte 3 
	ldr		r4, [r6, r4, lsl #2]
	ldr		r5, [r6, r5, lsl #2]
	ldr		r8, [r6, r8, lsl #2]
	eor		S1, r4
	ldr		r10, [r6, r10, lsl #2]
	eor		P0, r5, ror #24
	eor		S3, r8, ror #16
	eor		P2, r10, ror #8

    // S2 process
	ldrb	r4, [sp, #8]					// byte 0
	ldrb	r5, [sp, #9]					// byte 1 
	ldrb	r8, [sp, #10]					// byte 2
	ldrb	r10, [sp, #11]					// byte 3 
	ldr		r4, [r6, r4, lsl #2]
	ldr		r5, [r6, r5, lsl #2]
	ldr		r8, [r6, r8, lsl #2]
	eor		S2, r4
	ldr		r10, [r6, r10, lsl #2]
	eor		P1, r5, ror #24
	eor		S0, r8, ror #16
	eor		P3, r10, ror #8

    // S3 process
	ldrb	r4, [sp, #12]					// byte 0
	ldrb	r5, [sp, #13]					// byte 1 
	ldrb	r8, [sp, #14]					// byte 2
	ldrb	r10, [sp, #15]					// byte 3 
	ldr		r4, [r6, r4, lsl #2]
	ldr		r5, [r6, r5, lsl #2]
	ldr		r8, [r6, r8, lsl #2]
	eor		S3, r4
	ldr		r10, [r6, r10, lsl #2]
	eor		P2, r5, ror #24
	eor		S1, r8, ror #16
	eor		P0, r10, ror #8

#endif

	.endm

	.macro	aes_last_round
#if defined (__ARM_ARCH_7S__)
    // better for swift (and old cortex-a8)

	// S0 process
	ldr		t, [sp, #0]					// load 4 bytes for S0 process
	and		r4, r9, t					// byte 0
	and		r5, r9, t, lsr #8			// byte 1
	ldrb	r4, [r6, r4]				// 1st table lookup
	and		r8, r9, t, lsr #16			// byte 2
	ldrb	r5, [r6, r5]				// 2nd table lookup
	and		r10, r9, t, lsr #24			// byte 3
	ldrb	r8, [r6, r8]				// 3rd table lookup
	eor		S0, r4						// S0 ^= 1st table lookup
	ldrb	r10, [r6, r10]				// 4th table lookup
	eor		P3, r5, ror #24				// P3 ^= 2nd table lookup
	ldr		t, [sp, #4]					//   read Word for next S1 process
	eor		S2, r8, ror #16				// S2 ^= 3rd table lookup
	eor		P1, r10, ror #8				// P1 ^= 4th table lookup

	// S1 process
	and		r4, r9, t
	and		r5, r9, t, lsr #8
	ldrb	r4, [r6, r4]
	and		r8, r9, t, lsr #16
	ldrb	r5, [r6, r5]
	and		r10, r9, t, lsr #24
	ldrb	r8, [r6, r8]
	eor		S1, r4
	ldrb	r10, [r6, r10]
	eor		P0, r5, ror #24
	ldr		t, [sp, #8]
	eor		S3, r8, ror #16
	eor		P2, r10, ror #8

	// S2 process
	and		r4, r9, t
	and		r5, r9, t, lsr #8
	ldrb	r4, [r6, r4]
	and		r8, r9, t, lsr #16
	ldrb	r5, [r6, r5]
	and		r10, r9, t, lsr #24
	ldrb	r8, [r6, r8]
	eor		S2, r4
	ldrb	r10, [r6, r10]
	eor		P1, r5, ror #24
	ldr		t, [sp, #12]
	eor		S0, r8, ror #16
	eor		P3, r10, ror #8

	// S3 process
	and		r4, r9, t
	and		r5, r9, t, lsr #8
	ldrb	r4, [r6, r4]
	and		r8, r9, t, lsr #16
	ldrb	r5, [r6, r5]
	and		r10, r9, t, lsr #24
	ldrb	r8, [r6, r8]
	eor		S3, r4
	ldrb	r10, [r6, r10]
	eor		P2, r5, ror #24
	eor		S1, r8, ror #16
	eor		P0, r10, ror #8

#else
    // better for cortex-a7 and cortex-a9

	// S0 process
	ldrb	r4, [sp, #0]					// byte 0
	ldrb	r5, [sp, #1]					// byte 1 
	ldrb	r8, [sp, #2]					// byte 2
	ldrb	r10, [sp, #3]					// byte 3 
	ldrb	r4, [r6, r4]				// 1st table lookup
	ldrb	r5, [r6, r5]				// 2nd table lookup
	ldrb	r8, [r6, r8]				// 3rd table lookup
	eor		S0, r4						// S0 ^= 1st table lookup
	ldrb	r10, [r6, r10]				// 4th table lookup
	eor		P3, r5, ror #24				// P3 ^= 2nd table lookup
	eor		S2, r8, ror #16				// S2 ^= 3rd table lookup
	eor		P1, r10, ror #8				// P1 ^= 4th table lookup

	// S1 process
	ldrb	r4, [sp, #4]					// byte 0
	ldrb	r5, [sp, #5]					// byte 1 
	ldrb	r8, [sp, #6]					// byte 2
	ldrb	r10, [sp, #7]					// byte 3 
	ldrb	r4, [r6, r4]
	ldrb	r5, [r6, r5]
	ldrb	r8, [r6, r8]
	eor		S1, r4
	ldrb	r10, [r6, r10]
	eor		P0, r5, ror #24
	eor		S3, r8, ror #16
	eor		P2, r10, ror #8

	// S2 process
	ldrb	r4, [sp, #8]					// byte 0
	ldrb	r5, [sp, #9]					// byte 1 
	ldrb	r8, [sp, #10]					// byte 2
	ldrb	r10, [sp, #11]					// byte 3 
	ldrb	r4, [r6, r4]
	ldrb	r5, [r6, r5]
	ldrb	r8, [r6, r8]
	eor		S2, r4
	ldrb	r10, [r6, r10]
	eor		P1, r5, ror #24
	eor		S0, r8, ror #16
	eor		P3, r10, ror #8

	// S3 process
	ldrb	r4, [sp, #12]					// byte 0
	ldrb	r5, [sp, #13]					// byte 1 
	ldrb	r8, [sp, #14]					// byte 2
	ldrb	r10, [sp, #15]					// byte 3 
	ldrb	r4, [r6, r4]
	ldrb	r5, [r6, r5]
	ldrb	r8, [r6, r8]
	eor		S3, r4
	ldrb	r10, [r6, r10]
	eor		P2, r5, ror #24
	eor		S1, r8, ror #16
	eor		P0, r10, ror #8
#endif

	.endm

1:
	aes_per_round

	// Save state for next iteration and load next round key.
	stmia	sp,{S0-S3}
	thumb2_ldmia	ExpandedKey, S0, S1, S2, S3

	cmp		ExpandedKeyEnd, ExpandedKey
	add		ExpandedKey, #Increment 
	bne		1b

	// setup r6 = _AESSubBytesWordTable or _AESInvSubBytesWordTable 
    ldr		r6, L_table3
L_table2:	
    mov     r12, pc
    ldr     r6, [r12, r6]

	aes_last_round

	ldr		r4, [sp, #(16+8)]		// restore OutputText
	thumb2_stmia	r4, S0, S1, S2, S3
	eor		r0, r0				// Return success.

9:

	add		sp, #(4+16+8)       // skip r1 restore 
	pop		{r4-r6,r8-r11}
	pop		{r7, pc}


	.p2align 	2
L_table1:
    .long   L_Tab$non_lazy_ptr-(L_table0+4)

	.p2align 	2
L_table3:
    .long   L_Tab$non_lazy_ptr2-(L_table2+4)

    .section    __DATA,__nl_symbol_ptr,non_lazy_symbol_pointers
    .p2align  2
L_Tab$non_lazy_ptr:
    .indirect_symbol    MTable
    .long   0

    .p2align  2
L_Tab$non_lazy_ptr2:
    .indirect_symbol    FTable
    .long   0

#endif  // __ARM_NEON__

#undef	S0
#undef	S1
#undef	S2
#undef	S3
#undef	Name
#undef	MTable
#undef	FTable
#undef	P0
#undef	P1
#undef	P2
#undef	P3
#undef	Increment

#endif // CCAES_ARM_ASM && CC_ARM_ARCH_7

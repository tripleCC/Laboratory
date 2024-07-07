# Copyright (c) (2011-2017,2019-2021) Apple Inc. All rights reserved.
#
# corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
# is contained in the License.txt file distributed with corecrypto) and only to
# people who accept that license. IMPORTANT:  Any license rights granted to you by
# Apple Inc. (if any) are limited to internal use within your organization only on
# devices and computers you own or control, for the sole purpose of verifying the
# security characteristics and correct functioning of the Apple Software.  You may
# not, directly or indirectly, redistribute the Apple Software or any portions thereof.

#include <corecrypto/cc_config.h>
#include "ccarm_pac_bti_macros.h"

/*
	This files defines 2 aes key expansion functions : _aes_encrypt_key and _aes_decrypt_key
	that replaces the C implementations defined in gen/aeskey.c and gen/aestab.c

*/

/* 
	The following is the pseudo code for encrypt key expansion from FIPS-197

uint32_t SubWord(uint32_t x)
{
	uint32_t a = 0x0ff & x;
	uint32_t b = 0x0ff & (x >> 8);
	uint32_t c = 0x0ff & (x >> 16);
	uint32_t d = 0x0ff & (x >> 24);

	a = AESSubByteTable[a];
	b = AESSubByteTable[b];
	c = AESSubByteTable[c];
	d = AESSubByteTable[d];

	return ((d << 24) | (c << 16) | (b << 8) | a); 

}

aes_rval aes_key_expansion(const uint8_t *in_key, aes_encrypt_ctx *ctx, uint32_t Nk, uint32_t Nr) 
{
	uint32_t	tmp, i=0;
	uint32_t	*w = (uint32_t*) ctx, *key = (uint32_t*) in_key;
	ctx->rn = Nr;
	while (i<Nk) {
		w[i] = key[i];
		i++;	
	}
	while (i<(Nb*(Nr+1))) {
		tmp = w[i-1];
		if ((i%Nk)==0)
			tmp = SubWord(RotWord(tmp)) ^ RCON[i/Nk-1];
		else {
			if (Nk == 8) tmp = SubWord(tmp);
		}
		w[i] = w[i-Nk] ^ tmp;
		i++;
	}
}

*/

#if CCAES_ARM_ASM

#if defined(__arm64__)
	#define	w	x1
	#define	ctx	x1
	#define	key	x0
	#define	Nk	w2
	#define	Nr	w3
	#define	tmp	w6
	#define	RCON x4
	#define	subbyte	x5
#else
	#define	w	r1
	#define	ctx	r1
	#define	key	r0
	#define	Nk	r2
	#define	Nr	r3
	#define	tmp	r12
	#define	RCON r4
	#define	subbyte	r5
#endif

	// SubWord : input/output on r12, r5 : points to AESSubByteTable[], used r0/r2/r6 as temp registers  

	.macro SubWord

#if defined(__arm64__)
	lsr		w0, w12, #24
	lsr 	w2, w12, #16
	lsr		w6, w12, #8
	and		w12, w12, #0x0ff
	and		w2, w2, #0x0ff
	and		w6, w6, #0x0ff
	ldrb	w0, [subbyte, x0]				// the table for arm64 is byte table, so no LSL #2 is needed
	ldrb	w12, [subbyte, x12]
	ldrb	w2, [subbyte, x2]
	ldrb	w6, [subbyte, x6]
	orr		w12, w12, w0, lsl #24
	orr		w12, w12, w2, lsl #16
	orr		w12, w12, w6, lsl #8
#else
	mov 	r0, r12, lsr #24
	mov 	r2, r12, lsr #16
	mov		r6, r12, lsr #8
	and		r12, #0x0ff
	and		r2, #0x0ff
	and		r6, #0x0ff
	ldrb	r0, [subbyte, r0]	
	ldrb	r12, [subbyte, r12]	
	ldrb	r2, [subbyte, r2]	
	ldrb	r6, [subbyte, r6]	
	orr		r12, r0, lsl #24
	orr		r12, r2, lsl #16
	orr		r12, r6, lsl #8
#endif

	.endm

#if defined(__arm64__)
	#define	beq		b.eq
	#define	ble		b.le
	#define	bgt		b.gt
#endif

    .text
#if defined(__arm64__)
    .align  4
#else
    .align  2
    .syntax unified
    .code 16    
    .thumb_func aes_key_expansion
#endif
	
aes_key_expansion:			// this is an internal private function

#if defined(__arm64__)
#include "ccarm_intrinsic_compatability.h"
	adrp    RCON, _Rcon@GOTPAGE
    ldr     RCON, [RCON, _Rcon@GOTPAGEOFF]
    adrp    subbyte, _AESSubBytesWordTable@GOTPAGE
    ldr     subbyte, [subbyte, _AESSubBytesWordTable@GOTPAGEOFF]

#else
	push	{r4-r7,lr}
	add		r7, sp, #12		// set up trace frame pointer
	push	{r8-r11}
    sub     sp, sp, #12     // make sp 16-byte aligned
#ifdef CC_STATIC
	adr		RCON, L_Rcon_table
	adr		subbyte, L_SubByteTable
	ldr		RCON, [RCON]
	ldr		subbyte, [subbyte]
#else       // CC_STATIC
    ldr     RCON, L_Rcon_table
L_Rcon_table0:
    mov     tmp, pc
    ldr     RCON, [tmp, RCON]
    ldr     subbyte, L_SubByteTable
L_SubByteTable0:
    mov     tmp, pc
    ldr     subbyte, [tmp, subbyte]
#endif      // CC_STATIC
#endif      // __arm64__

    lsl     tmp, Nr, #4 
	str	    tmp, [ctx, #240]		// ctx->rn = Nr*16

	cmp		Nk, #6
	beq		6f
	cmp		Nk, #8
	beq		8f

4:		// Nk = 4, Nr = 10

#if defined(__arm64__)
	// 1st 4 w = key
	ldp		x8, x9, [key]
	stp		x8, x9, [w], #16
	lsl		Nr, Nr, #2
0:
	lsr		x12, x9, #32
	ror		w12, w12, #8
	SubWord
	ldrb	w0, [RCON], #1
	eor		w12, w12, w0
	eor		x8, x8, x12
	eor		x8, x8, x8, lsl #32
	eor		x9, x9, x8, lsr #32
	eor		x9, x9, x9, lsl #32
	stp		x8, x9, [w], #16
#else
	// 1st 4 w = key
	ldmia	key, {r8-r11}
	stmia	w!, {r8-r11}	
	lsl		Nr, #2
0:
	mov		tmp, r11
	ror		tmp, #8
	SubWord	
	ldrb	r0, [RCON], #1
	eor		tmp, r0 		
	eor		r8, tmp
	eor		r9, r8
	eor		r10, r9
	eor		r11, r10
	stmia	w!, {r8-r11}
#endif

	subs	Nr, Nr, #4
	bgt		0b
	b		9f	

6:		// Nk = 6, Nr = 12

#if defined(__arm64__)
	ldp		x8, x9, [key], #16
	stp		x8, x9, [w], #16
	ldr		x10, [key]
	str		x10, [w], #8
	lsl		Nr, Nr, #2
	sub		Nr, Nr, #2
0:
	lsr		x12, x10, #32
	ror		w12, w12, #8
	SubWord
	ldrb	w0, [RCON], #1
	eor		w12, w12, w0
	eor		x8, x8, x12
	eor		x8, x8, x8, lsl #32
	eor		x9, x9, x8, lsr #32
	eor		x9, x9, x9, lsl #32
	eor		x10, x10, x9, lsr #32
	eor		x10, x10, x10, lsl #32
	stp		x8, x9, [w], #16
	str		x10, [w], #8
#else
	ldmia	key, {r2,r8-r11,lr}
	stmia	w!, {r2,r8-r11,lr}
	lsl	Nr, #2
	sub	Nr, #2
0:
	mov		tmp, lr
	ror		tmp, #8
	SubWord	
	ldr		r2, [w, #-24]	// r2 was used in SubWord
	ldrb	r0, [RCON], #1
	eor		tmp, r0 		
	eor		r2, tmp
	eor		r8, r2
	eor		r9, r8
	eor		r10, r9
	eor		r11, r10
	eor		lr, r11
	stmia	w!, {r2,r8-r11,lr}
#endif

	subs	Nr, Nr, #6
	bgt		0b
	b		9f	

8:		// Nk = 8, Nr = 14

#if defined(__arm64__)
	ldp		x8, x9, [key], #16
	stp		x8, x9, [w], #16
	ldp		x10, x11, [key], #16
	stp		x10, x11, [w], #16
	lsl		Nr, Nr, #2
	sub		Nr, Nr, #4
0:
	lsr		x12, x11, #32
	ror		w12, w12, #8
	SubWord
	ldrb	w0, [RCON], #1
	eor		w12, w12, w0
	eor		x8, x8, x12
	eor		x8, x8, x8, lsl #32
	eor		x9, x9, x8, lsr #32
	eor		x9, x9, x9, lsl #32
	stp		x8, x9, [w], #16
	subs	Nr, Nr, #4
	beq		9f

	lsr		x12, x9, #32
	SubWord
	eor		x10, x10, x12
	eor		x10, x10, x10, lsl #32
	eor		x11, x11, x10, lsr #32
	eor		x11, x11, x11, lsl #32
	stp		x10, x11, [w], #16
	subs	Nr, Nr, #4
	bgt		0b

#else
	ldmia	key!, {r8-r11}
	stmia	w!, {r8-r11}	
	ldmia	key!, {r8-r11}
	stmia	w!, {r8-r11}	
	lsl		Nr, #2
	sub		Nr, #4
	mov		tmp, r11
0:
	ror		tmp, #8
	SubWord	
	ldrb	r0, [RCON], #1
	ldr		r8, [w, #-32]
	eor		tmp, r0 		
	eor		tmp, r8
	str		tmp, [w], #4

	ldr		r8, [w,#-32]
	eor		tmp, r8
	str		tmp, [w],#4
	ldr		r8, [w,#-32]
	eor		tmp, r8
	str		tmp, [w],#4
	ldr		r8, [w,#-32]
	eor		tmp, r8
	str		tmp, [w],#4

	subs	Nr, #4
	beq		9f

	ldr		r8, [w, #-32]
	SubWord
	eor		tmp, r8
	str		tmp, [w], #4

	ldr		r8, [w,#-32]
	eor		tmp, r8
	str		tmp, [w],#4
	ldr		r8, [w,#-32]
	eor		tmp, r8
	str		tmp, [w],#4
	ldr		r8, [w,#-32]
	eor		tmp, r8
	str		tmp, [w],#4
	subs	Nr, #4
	bgt		0b
#endif

9:

#if defined(__arm64__)
	ret		lr
#else
    add     sp, sp, #12
	pop		{r8-r11}
	pop		{r4-r7,pc}	

#ifdef CC_STATIC
	.align 2
L_Rcon_table:
	.long	_Rcon
L_SubByteTable:
	.long	_AESSubBytesWordTable

#else
	.align 2
L_Rcon_table:
	.long   L_Tab$non_lazy_ptr-(L_Rcon_table0+4)
L_SubByteTable:
	.long	L_Tab$non_lazy_ptr2-(L_SubByteTable0+4)

	.section    __DATA,__nl_symbol_ptr,non_lazy_symbol_pointers
    .align  2
L_Tab$non_lazy_ptr:
    .indirect_symbol    _Rcon
    .long   0
L_Tab$non_lazy_ptr2:
    .indirect_symbol    _AESSubBytesWordTable
    .long   0

#endif

#endif

/*
aes_rval aes_encrypt_key128(const uint8_t *key, aes_encrypt_ctx ctx[1])
{
	return aes_key_expansion(key, ctx, 4, 10);	
}

aes_rval aes_encrypt_key192(const uint8_t *key, aes_encrypt_ctx ctx[1])
{
	return aes_key_expansion(key, ctx, 6, 12);	
}

aes_rval aes_encrypt_key256(const uint8_t *key, aes_encrypt_ctx ctx[1])
{
	return aes_key_expansion(key, ctx, 8, 14);	
}
*/

#if defined(__arm64__)
	#define	r2	w2
	#define	r3	w3
#endif

    .macro  thumb2_func
    .align  2
    .code 16
    .thumb_func $0
    .globl  $0
    .endm

	.text
#if CC_ARM_ARCH_7 && defined(__ARM_NEON__)
    .extern _vpaes_set_encrypt_key
    .text
    thumb2_func _ccaes_arm_encrypt_key128
_ccaes_arm_encrypt_key128:
    mov     r2, r1
    mov     r1, #128
    b       _vpaes_set_encrypt_key

    thumb2_func _ccaes_arm_encrypt_key192
_ccaes_arm_encrypt_key192:
    mov     r2, r1
    mov     r1, #192
    b       _vpaes_set_encrypt_key

    thumb2_func  _ccaes_arm_encrypt_key256
_ccaes_arm_encrypt_key256:
    mov     r2, r1
    mov     r1, #256
    b       _vpaes_set_encrypt_key
#else   // CC_ARM_ARCH_7 && defined(__ARM_NEON__)

#if defined(__arm64__)
	.align	4
#else
	.align	2
    .code   16
    .thumb_func _ccaes_arm_encrypt_key128
#endif
	.globl	_ccaes_arm_encrypt_key128
_ccaes_arm_encrypt_key128:
	BRANCH_TARGET_CALL
	mov		r2, #4
	mov		r3, #10
	b		aes_key_expansion	

#if defined(__arm64__)
	.align	4
#else
	.align	2
    .code   16
    .thumb_func _ccaes_arm_encrypt_key192
#endif
	.globl	_ccaes_arm_encrypt_key192
_ccaes_arm_encrypt_key192:
	BRANCH_TARGET_CALL
	mov		r2, #6
	mov		r3, #12
	b		aes_key_expansion	

#if defined(__arm64__)
	.align	4
#else
	.align	2
    .code   16
    .thumb_func _ccaes_arm_encrypt_key256
#endif
	.globl	_ccaes_arm_encrypt_key256
_ccaes_arm_encrypt_key256:
	BRANCH_TARGET_CALL
	mov		r2, #8
	mov		r3, #14
	b		aes_key_expansion	

#endif  // CC_ARM_ARCH_7 && defined(__ARM_NEON__)

#if defined(__arm64__)
	#undef	r2
	#undef	r3
#endif

/* 
// this produces [ 9*a 13*a 11*a 14*a ] per byte in regular decrypt round
uint32_t invmix(uint8_t a) 
{
	uint8_t	a2, a4, a8, a9, a11, a13, a14;
	a2 = (a<<1);
	if (a&0x080) a2^=0x1b;			// a2 = 2*a;
	a4 = (a2<<1);
	if (a2&0x080) a4^=0x1b;			// a4 = 4*a;
	a8 = (a4<<1);
	if (a4&0x080) a8^=0x1b;			// a8 = 8*a;

	a9 = a8^a;
	a13 = a9^a4;
	a11 = a9^a2;
	a14 = a2^a4^a8;

	return ((a11<<24) | (a13<<16) | (a9<<8) | a14);
}

uint32_t invmixcolumn(uint32_t abcd)
{
	uint32_t a = (abcd>>0)&0x0ff;
	uint32_t b = (abcd>>8)&0x0ff;
	uint32_t c = (abcd>>16)&0x0ff;
	uint32_t d = (abcd>>24)&0x0ff;

	a = invmix(a);
	b = ror(invmix(b),24);
	c = ror(invmix(c),16);
	d = ror(invmix(d),8);

	return (a ^ b ^ c ^ d);
}

// the following function is implemented using table look up
void	InvMixColumns(uint32_t *state) {
	state[0] = invmixcolumn(state[0]);
	state[1] = invmixcolumn(state[1]);
	state[2] = invmixcolumn(state[2]);
	state[3] = invmixcolumn(state[3]);
}

aes_rval aes_dkey_expansion(const uint8_t *in_key, aes_decrypt_ctx *ctx, uint32_t Nk, uint32_t Nr) 
{
	uint32_t	tmp, i=0;
	uint32_t	*w = (uint32_t*) ctx, *key = (uint32_t*) in_key;
	ctx->rn = Nr;
	while (i<Nk) {
		w[i] = key[i];
		i++;	
	}
	while (i<(Nb*(Nr+1))) {
		tmp = w[i-1];
		if ((i%Nk)==0)
			tmp = SubWord(RotWord(tmp)) ^ RCON[i/Nk-1];
		else {
			if (Nk == 8)
				tmp = SubWord(tmp);
		}
		w[i] = w[i-Nk] ^ tmp;
		i++;
	}

	// compute decryption round keys
	for (i=1;i<Nr;i++) 
			InvMixColumns(&w[4*i]);

}
*/

	.text
#if defined(__arm64__)
    .align  4
#else
    .align  2
    .code   16
    .thumb_func aes_dkey_expansion
#endif

aes_dkey_expansion:
#if defined(__arm64__)
    SIGN_LR
    sub     sp, sp, #32
    str     lr,[sp, #16]
    stp     x1,x3,[sp]
    bl      aes_key_expansion
    ldp     x1,x3,[sp],#16
#if CC_KERNEL
	sub		sp, sp, #16
	str		q0, [sp]
#endif
    add     x1,x1,#16           // skip the 1st word
    sub     x3, x3, #1
0:
    subs    x3, x3, #1
    ldr     q0, [x1]
    AESIMC  0, 0
    str     q0, [x1], #16
    bgt     0b
#if CC_KERNEL
	ldr		q0, [sp], #16
#endif
    ldr     lr, [sp], #16
    AUTH_LR_AND_RET

#else
	push	{r0-r3,r8-r11,lr}		// keep a copy of ctx, Nr, and return address

	bl		aes_key_expansion

	pop		{r0-r3}		// restore ctx, Nr
	add		w,#16

#ifdef CC_STATIC
	adr		r2, L_invmixTable 
	ldr		r2, [r2]
#else
	ldr		r2, L_invmixTable 
L_invmixTable0:
    mov     r12, pc
    ldr     r2, [r12, r2]
#endif

	mov		lr, #0x0ff
	sub		Nr, #1
	lsl		Nr, #2
0:
	ldr		r12, [w]

    and     r8, lr, r12					// byte 0
    and     r9, lr, r12, lsr #8         // byte 1
    and     r10, lr, r12, lsr #16       // byte 2
    and     r11, lr, r12, lsr #24       // byte 3
    ldr     r8, [r2, r8, lsl #2]        //
    ldr     r9, [r2, r9, lsl #2]        //
    ldr     r10, [r2, r10, lsl #2]        //
    ldr     r12, [r2, r11, lsl #2]        //
	eor		r8, r9, ror #24
	eor		r8, r10, ror #16
	eor		r8, r12, ror #8
	str		r8, [w], #4
	subs	Nr, #1
	bgt		0b
	pop		{r8-r11,pc}

#ifdef CC_STATIC
	.align 2
L_invmixTable:
	.long	_AESInvMixColumnTable

#else
	.align 2
L_invmixTable:
	.long	L_Tab$non_lazy_ptr3-(L_invmixTable0+4)

	.section    __DATA,__nl_symbol_ptr,non_lazy_symbol_pointers
L_Tab$non_lazy_ptr3:
    .indirect_symbol    _AESInvMixColumnTable
    .long   0

#endif

#endif	// architecture

/*
aes_rval aes_decrypt_key128(const uint8_t *key, aes_decrypt_ctx ctx[1])
{
	return aes_dkey_expansion(key, ctx, 4, 10);	
}

aes_rval aes_decrypt_key192(const uint8_t *key, aes_decrypt_ctx ctx[1])
{
	return aes_dkey_expansion(key, ctx, 6, 12);	
}

aes_rval aes_decrypt_key256(const uint8_t *key, aes_decrypt_ctx ctx[1])
{
	return aes_dkey_expansion(key, ctx, 8, 14);	
}
*/

	.text

#if CC_ARM_ARCH_7 && defined(__ARM_NEON__)
   .extern _vpaes_set_decrypt_key
    thumb2_func _ccaes_arm_decrypt_key128
_ccaes_arm_decrypt_key128:
    mov     r2, r1
    mov     r1, #128
    b       _vpaes_set_decrypt_key

    thumb2_func  _ccaes_arm_decrypt_key192
_ccaes_arm_decrypt_key192:
    mov     r2, r1
    mov     r1, #192
    b       _vpaes_set_decrypt_key
    thumb2_func _ccaes_arm_decrypt_key256
_ccaes_arm_decrypt_key256:
    mov     r2, r1
    mov     r1, #256
    b       _vpaes_set_decrypt_key

#else   // CC_ARM_ARCH_7 && defined(__ARM_NEON__)


	.globl	_ccaes_arm_decrypt_key128
#if defined(__arm64__)
	.align	4
#else
	.align	2
    .code 16
    .thumb_func _ccaes_arm_decrypt_key128
#endif
_ccaes_arm_decrypt_key128:
#if defined(__arm64__)
    SIGN_LR
	sub		sp, sp, #16
	str		lr, [sp]
	mov		x2, #4
	mov		x3, #10
	bl		aes_dkey_expansion
	ldr		lr, [sp], #16
    AUTH_LR_AND_RET
#else
	push	{r7,lr}
	mov		r7, sp
    sub     sp, sp, #8      // make sp 16-byte aligned
	mov		r2, #4
	mov		r3, #10
	bl		aes_dkey_expansion
    add     sp, sp, #8
	pop		{r7,pc}
#endif
	
	.globl	_ccaes_arm_decrypt_key192
#if defined(__arm64__)
	.align	4
#else
	.align	2
    .code 16
    .thumb_func _ccaes_arm_decrypt_key192
#endif
_ccaes_arm_decrypt_key192:
#if defined(__arm64__)
    SIGN_LR
	sub		sp, sp, #16
	str		lr, [sp]
	mov		x2, #6
	mov		x3, #12
	bl		aes_dkey_expansion
	ldr		lr, [sp], #16
    AUTH_LR_AND_RET
#else
	push	{r7,lr}
	mov		r7, sp
    sub     sp, sp, #8      // make sp 16-byte aligned
	mov		r2, #6
	mov		r3, #12
	bl		aes_dkey_expansion
    add     sp, sp, #8
	pop		{r7,pc}
#endif

	.globl	_ccaes_arm_decrypt_key256
#if defined(__arm64__)
	.align	4
#else
	.align  2	
    .code 16
    .thumb_func _ccaes_arm_decrypt_key256
#endif
_ccaes_arm_decrypt_key256:
#if defined(__arm64__)
    SIGN_LR
	sub		sp, sp, #16
	str		lr, [sp]
	mov		x2, #8
	mov		x3, #14
	bl		aes_dkey_expansion
	ldr		lr, [sp], #16
    AUTH_LR_AND_RET
#else
	push	{r7,lr}
	mov		r7, sp
    sub     sp, sp, #8      // make sp 16-byte aligned
	mov		r2, #8
	mov		r3, #14
	bl		aes_dkey_expansion
    add     sp, sp, #8
	pop		{r7,pc}
#endif

#endif      // CC_ARM_ARCH_7 && defined(__ARM_NEON__)

	.globl	_ccaes_arm_encrypt_key
#if defined(__arm64__)
	.align	4
#else
	.align	2
    .code 16
    .thumb_func _ccaes_arm_encrypt_key 
#endif
_ccaes_arm_encrypt_key:
#if defined(__arm64__)
    SIGN_LR

	// convert interface to save wrapper
	mov		x0, x1				// x0 = ctx
	mov		x1, x2				// x1 = len
	mov		x2, x0				// x2 = ctx	
	mov		x0, x3				// x0 = rawkey

	sub		sp, sp, #16
	str		lr, [sp]
	mov	x3, x1		// key_len
	mov	x1, x2		// cx
	cmp	x3, #32		//
	ble	1f
	lsr	x3, x3, #3		// change 128/192/256 to 16/24/32
1:	cmp	x3, #16
	beq	2f
	cmp	x3, #24
	beq	3f
	cmp	x3, #32
	beq	4f
	mov	x0, #-1
	b	9f
2:	bl	_ccaes_arm_encrypt_key128
	b	8f
3:	bl	_ccaes_arm_encrypt_key192
	b	8f
4:	bl	_ccaes_arm_encrypt_key256
8:	mov	x0, #0
9:	ldr		lr, [sp], #16
    AUTH_LR_AND_RET
#else
	push	{r7,lr}
	mov		r7, sp
    sub     sp, sp, #8          // sp 16-byte aligned for armv7k
	mov	r3, r1		// key_len
	mov	r1, r2		// cx
	cmp	r3, #32		//
	ble	1f
	lsr	r3, #3		// change 128/192/256 to 16/24/32
1:	cmp	r3, #16
	beq	2f
	cmp	r3, #24
	beq	3f
	cmp	r3, #32
	beq	4f
	mov	r0, #-1
	b	9f
2:	bl	_ccaes_arm_encrypt_key128
	b	8f
3:	bl	_ccaes_arm_encrypt_key192
	b	8f
4:	bl	_ccaes_arm_encrypt_key256
8:	eor	r0, r0
9:  add sp, sp, #8	
    pop		{r7,pc}
#endif

	.globl	_ccaes_arm_decrypt_key
#if defined(__arm64__)
	.align	4
#else
	.align	2
    .code 16
    .thumb_func _ccaes_arm_decrypt_key 
#endif
_ccaes_arm_decrypt_key:
#if defined(__arm64__)
    SIGN_LR
	// convert interface to save wrapper
	mov		x0, x1				// x0 = ctx
	mov		x1, x2				// x1 = len
	mov		x2, x0				// x2 = ctx	
	mov		x0, x3				// x0 = rawkey

	sub		sp, sp, #16
	str		lr, [sp]
	mov	x3, x1		// key_len
	mov	x1, x2		// cx
	cmp	x3, #32		//
	ble	1f
	lsr	x3, x3, #3	// change 128/192/256 to 16/24/32
1:	cmp	x3, #16
	beq	2f
	cmp	x3, #24
	beq	3f
	cmp	x3, #32
	beq	4f
	mov	x0, #-1
	b	9f
2:	bl	_ccaes_arm_decrypt_key128
	b	8f
3:	bl	_ccaes_arm_decrypt_key192
	b	8f
4:	bl	_ccaes_arm_decrypt_key256
8:	mov		x0, #0
9:	ldr		lr, [sp], #16
    AUTH_LR_AND_RET
#else
	push	{r7,lr}
	mov		r7, sp
    sub     sp, sp, #8          // make sp 16-byte aligned for armv7k
	mov	r3, r1		// key_len
	mov	r1, r2		// cx
	cmp	r3, #32		//
	ble	1f
	lsr	r3, #3		// change 128/192/256 to 16/24/32
1:	cmp	r3, #16
	beq	2f
	cmp	r3, #24
	beq	3f
	cmp	r3, #32
	beq	4f
	mov	r0, #-1
	b	9f
2:	bl	_ccaes_arm_decrypt_key128
	b	8f
3:	bl	_ccaes_arm_decrypt_key192
	b	8f
4:	bl	_ccaes_arm_decrypt_key256
8:	eor	r0, r0
9:	add sp, sp, #8
    pop		{r7,pc}
#endif

#endif /* CCAES_ARM_ASM */


# Copyright (c) (2011-2016,2018,2019,2021) Apple Inc. All rights reserved.
#
# corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
# is contained in the License.txt file distributed with corecrypto) and only to
# people who accept that license. IMPORTANT:  Any license rights granted to you by
# Apple Inc. (if any) are limited to internal use within your organization only on
# devices and computers you own or control, for the sole purpose of verifying the
# security characteristics and correct functioning of the Apple Software.  You may
# not, directly or indirectly, redistribute the Apple Software or any portions thereof.

// This is an include file, not a standalone file
// It is a common code template for aes_encrypt_cbc and aes_decrypt_cbc

/*
	This (armv5 isa) assembly file was derived by porting from the i386/x86_64 EncryptDecrypt.s, plus 
	adding the cbc mode function wrapper.
	
    This file is a code template to define the CBC mode AES functions
		_aes_encrypt_cbc
		_aes_decrypt_cbc
	depending on the value of the Select preprocessor symbol. 
	It can be used to define _aes_encrypt_cbc with Select=0.
    Otherwise, it defines _aes_decrypt_cbc. 

	The atomic functions aes_encrypt/aes_decrypt can be similarly defined from EncryptDecrypt.s

	By calling directly these cbc mode functions, instead of writing C functions and calling the
	atomic functions aes_encrypt/aes_decrypt per 16-byte block, significant amount of overhead is saved.
	This improves the cost from ~ 36 cycles/byte to ~ 29 cycles/byte in cbc mode applications on cortex-a8.

    One important change from i386/x86_64 is that the fact that the 2nd operand for arm architecture
    comes from the rotated/shifted output of the barrel shifter is exploited to save usage of GPU
    and to save the size of the lookup tables. For all the 4 used lookup tables, here we only
    need the 1st quarter of the original tables in the original i386/Data.s

*/

#if CCAES_ARM_ASM

#if Select == 0
	#define	Name		_ccaes_arm_encrypt_cbc		// Routine name.
#else
	#define	Name		_ccaes_arm_decrypt_cbc		// Routine name.
#endif	// Select

/*

	our cbc-mode level implementation of aes_encrypt_cbc(*ibuf,*iv_in,nb,*obuf,*ctx) is as follows:

	// all variables represent 16-byte blocks.
	*iv = *iv_in;         // *iv_in is declared const, so we should not change its value
	while (nb--) {
		*iv ^= *ibuf;
		aes_encrypt(iv,iv,ctx);
		memcpy(obuf,iv,AES_BLOCK_SIZE);
		ibuf += AES_BLOCK_SIZE;
		obuf += AES_BLOCK_SIZE;
	}

	our cbc-mode level implementation of aes_decrypt_cbc(*ibuf,*in_iv,nb,*obuf,*ctx) is as follows:

	memcpy(iv,in_iv,AES_BLOCK_SIZE);
	while (nb--) {
		memcpy(tmp,ibuf,AES_BLOCK_SIZE);
		aes_decrypt(ibuf,obuf,ctx);
		*obuf ^= *iv;
		memcpy(iv,tmp,AES_BLOCK_SIZE);
		ibuf += AES_BLOCK_SIZE;
		obuf += AES_BLOCK_SIZE;
	}
	
*/

#define	t					r12

	.text
    .syntax unified
    .align  2
    .code   16
    .thumb_func Name

	.globl Name
Name:

	ldr		t, [sp, #0]			// load the 5th calling argument (ctx) before we move the stack pointer

	// set up debug trace frame pointer
	push	{r7,lr}				// set up frame pointer for debug tracing
	mov		r7, sp

	// now setup the stack for the current function
	push	{r4-r6,r8-r11}			// saved ibuf,nb,obuf in the stack, need to use r0-r3 for the 16-byte state
	sub		sp, #48                 // local iv and tmp

    mov     r4, r0                  // ibuf
    mov     r5, r3                  // obuf
    mov     r11, r2                 // nb
    mov     r10, t                  // ctx

    #define ibuf    r4
    #define obuf    r5
    #define nb      r11
    #define ctx     r10

    // copy iv to local iv
    ldr     r0, [r1, #0]
    ldr     r2, [r1, #4]
    ldr     r3, [r1, #8]
    ldr     r6, [r1, #12]
    stmia   sp, {r0,r2,r3,r6}

    subs    nb, nb, #1
    blt     9f
L_loop:
#if (Select == 0)       // encrypt
    /*
		*iv ^= *ibuf;
		aes_encrypt(iv,iv,ctx);
		memcpy(obuf,iv,AES_BLOCK_SIZE);
		ibuf += AES_BLOCK_SIZE;
		obuf += AES_BLOCK_SIZE;
    */
    ldr     r0, [ibuf], #4
    ldr     r1, [ibuf], #4
    ldr     r2, [ibuf], #4
    ldr     r3, [ibuf], #4
    ldmia   sp, {r6,r9,r12,lr}

    eor     r0, r0, r6
    eor     r1, r1, r9
    eor     r2, r2, r12
    eor     r3, r3, lr

    stmia   sp, {r0, r1, r2, r3}

    mov     r0, sp
    mov     r1, sp
    mov     r2, ctx
    bl      _AccelerateCrypto_AES_encrypt

    ldmia   sp, {r0, r1, r2, r3}
    str     r0, [obuf], #4
    str     r1, [obuf], #4
    str     r2, [obuf], #4
    str     r3, [obuf], #4

#else                   // decrypt
    /*
		memcpy(tmp,ibuf,AES_BLOCK_SIZE);
		aes_decrypt(ibuf,obuf,ctx);
		*obuf ^= *iv;
		memcpy(iv,tmp,AES_BLOCK_SIZE);
		ibuf += AES_BLOCK_SIZE;
		obuf += AES_BLOCK_SIZE;
    */
    add     r6, sp, #16                 // tmp
    ldr     r0, [ibuf], #4
    ldr     r1, [ibuf], #4
    ldr     r2, [ibuf], #4
    ldr     r3, [ibuf], #4
    stmia   r6, {r0, r1, r2, r3}
    sub     r0, ibuf, #16
    add     r1, sp, #32
    mov     r2, ctx
    bl      _AccelerateCrypto_AES_decrypt

    add     r6, sp, #32
    ldmia   r6, {r0, r1, r2, r3}    // decrypt out
    ldmia   sp, {r6, r9, r12, lr}   // iv
    eor     r0, r0, r6
    eor     r1, r1, r9
    eor     r2, r2, r12
    eor     r3, r3, lr

    str     r0, [obuf], #4
    str     r1, [obuf], #4
    str     r2, [obuf], #4
    str     r3, [obuf], #4

    add     r6, sp, #16
    ldmia   r6, {r0, r1, r2, r3}
    stmia   sp, {r0, r1, r2, r3}
    
#endif



    subs    nb, nb, #1
    bge     L_loop

9:
    add     sp, #48
    pop     {r4-r6,r8-r11}
    pop     {r7, pc}
    

#undef	Name

#endif /* CCAES_ARM_ASM */

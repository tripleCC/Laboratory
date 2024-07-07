# Copyright (c) (2011-2016,2018-2020,2022) Apple Inc. All rights reserved.
#
# corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
# is contained in the License.txt file distributed with corecrypto) and only to
# people who accept that license. IMPORTANT:  Any license rights granted to you by
# Apple Inc. (if any) are limited to internal use within your organization only on
# devices and computers you own or control, for the sole purpose of verifying the
# security characteristics and correct functioning of the Apple Software.  You may
# not, directly or indirectly, redistribute the Apple Software or any portions thereof.

#if defined(__arm64__) && defined(__ARM_FEATURE_AES)
#include "arm64_isa_compatibility.h"
#include "ccarm_pac_bti_macros.h"
	// ecb mode

    #define key     x0
	#define	nblocks	w1
	#define in      x2
    #define out     x3
    #define keylen  x4
    #define t       x5

.subsections_via_symbols
    .text

	.globl _AccelerateCrypto_ecb_AES_decrypt
	.p2align	4
_AccelerateCrypto_ecb_AES_decrypt:
    BRANCH_TARGET_CALL
#if BUILDKERNEL
    // save used vector registers
    sub     x4, sp, #6*16
    sub     sp, sp, #6*16
    st1.4s      {v0,v1,v2,v3}, [x4], #4*16
    st1.4s      {v4,v5}, [x4], #2*16
#endif

    ldr     w4, [key, #240]             // keylength = 32-bit
    ldr     q5, [key]               // expanded key
	subs	nblocks, nblocks, #4
	b.lt	L_lessthan4

L_4blocks:
    mov     t, keylen
	ld1.4s	{v0,v1,v2,v3}, [in], #4*16
    ldr     q4, [key, t]	        // expanded key
    sub     t, t, #16
0:
    AESD     0, 4
    AESIMC   0, 0
    AESD     1, 4
    AESIMC   1, 1
    AESD     2, 4
    AESIMC   2, 2
    AESD     3, 4
    AESIMC   3, 3
    ldr         q4, [key, t]				// expanded key
    subs        t, t, #16
    b.gt        0b
    AESD     0, 4
    eor.16b v0, v0, v5
    AESD     1, 4
    eor.16b v1, v1, v5
    AESD     2, 4
    eor.16b v2, v2, v5
    AESD     3, 4
    eor.16b v3, v3, v5

	st1.4s		{v0,v1,v2,v3}, [out], #4*16

	subs	nblocks, nblocks, #4
	b.ge	L_4blocks

L_lessthan4:
	ands	nblocks, nblocks, #3
	b.eq	9f

L_1block:
    mov     t, keylen
    ldr     q0, [in], #16          // plain data
    ldr     q4, [key, t]	        // expanded key
    sub     t, t, #16
0:
    AESD    0, 4
    AESIMC   0, 0
    ldr     q4, [key, t]			// expanded key
    subs        t, t, #16
    b.gt        0b

    AESD    0, 4
    eor.16b v0, v0, v5

    str     q0, [out], #16
	subs	nblocks, nblocks, #1
	b.gt	L_1block

9:
#if BUILDKERNEL
	// restore used vector registers
	ld1.4s		{v0,v1,v2,v3}, [sp], #4*16
	ld1.4s		{v4,v5}, [sp], #2*16
#endif

    mov     x0, #0
    ret     lr

	#undef in
    #undef out
    #undef key
	#undef nblocks
    #undef keylen

#endif


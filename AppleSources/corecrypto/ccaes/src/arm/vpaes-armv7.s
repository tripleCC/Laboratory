# Copyright (c) (2015,2016,2019,2021) Apple Inc. All rights reserved.
#
# corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
# is contained in the License.txt file distributed with corecrypto) and only to
# people who accept that license. IMPORTANT:  Any license rights granted to you by
# Apple Inc. (if any) are limited to internal use within your organization only on
# devices and computers you own or control, for the sole purpose of verifying the
# security characteristics and correct functioning of the Apple Software.  You may
# not, directly or indirectly, redistribute the Apple Software or any portions thereof.

#include <corecrypto/cc_config.h>

#if CCAES_ARM_ASM && !defined(__arm64__) && defined(__ARM_NEON__)

    .macro EnableVFP
#if CC_KERNEL
        push    {r0, r1, r2, r3}
        bl      _enable_kernel_vfp_context
        pop     {r0, r1, r2, r3}
#endif
    .endm

    #define ekey    r2
    #define eax     r4

    .macro  save_all_neon
#if CC_KERNEL
    vstmdb  sp!, {q12-q15}
    vstmdb  sp!, {q8-q11}
    vstmdb  sp!, {q0-q3}
#endif
    vstmdb  sp!, {q4-q7}
    .endm

    .macro  restore_all_neon
    vldmia  sp!, {q4-q7}
#if CC_KERNEL
    vldmia  sp!, {q0-q3}
    vldmia  sp!, {q8-q11}
    vldmia  sp!, {q12-q15}
#endif
    .endm

    .macro  vpaes_push
    push    {r4-r7,lr}
    add     r7, sp, #12
    push    {r8,r10,r11}
    .endm

    .macro  vpaes_pop
    pop    {r8,r10,r11}
    pop    {r4-r7,pc}
    .endm

    .text	

    .align  6
.Lk_ipt2:
.quad	0xC2B2E8985A2A7000, 0xCABAE09052227808
.quad	0x4C01307D317C4D00, 0xCD80B1FCB0FDCC81
.Lk_rcon:
.quad	0x1F8391B9AF9DEEB6, 0x702A98084D7C7D81
.Lk_sr:
.quad   0x0706050403020100, 0x0F0E0D0C0B0A0908
.quad   0x030E09040F0A0500, 0x0B06010C07020D08
.quad   0x0F060D040B020900, 0x070E050C030A0108
.quad   0x0B0E0104070A0D00, 0x0306090C0F020508


    .align	4
vpaes_schedule_core:
    bl      vpaes_preheat
    adr     r10, .Lk_rcon
    vld1.8  {q0}, [r0]
    vld1.64 {q8}, [r10 :128]!
    vmov    q3, q0
    adr     r11, .Lk_ipt2
	bl      vpaes_schedule_transform
    vmov    q7, q0

    cmp     r3, #0
    bne     .Lschedule_am_decrypting

    vst1.8 {q0}, [r2]

	b       .Lschedule_go

.Lschedule_am_decrypting:

    add     r12, r10, r8
    vmov    q1, q3
    vld1.8 {q3}, [r12]
    vtbl.8  d6, {q1}, d6
    vtbl.8  d7, {q1}, d7
    eor     r8, r8, #48
    vst1.8 {q3}, [r2]


.Lschedule_go:
	cmp     r1, #192
	bgt	    .Lschedule_256
	beq     .Lschedule_192

.Lschedule_128:
    mov     r1, #10

.Loop_schedule_128:
	bl  	vpaes_schedule_round
    subs    r1, r1, #1
    beq     .Lschedule_mangle_last
	bl  	vpaes_schedule_mangle
	b   	.Loop_schedule_128

    .align	4
.Lschedule_192:
    add     r12, r0, #8
    vld1.8 {q0}, [r12]
	bl      vpaes_schedule_transform
    vmov    d13, d1
    veor    d12, d12, d12
    mov     r1, #4
    
.Loop_schedule_192:
	bl	vpaes_schedule_round
    vext.8  q0, q6, q0, #8
    
	bl	vpaes_schedule_mangle
	bl	vpaes_schedule_192_smear
	bl	vpaes_schedule_mangle
	bl	vpaes_schedule_round
    subs    r1, r1, #1
	beq	.Lschedule_mangle_last
	bl	vpaes_schedule_mangle
	bl	vpaes_schedule_192_smear
	b	.Loop_schedule_192

.align	4
.Lschedule_256:
    add     r12, r0, #16
    vld1.8 {q0}, [r12]
	bl	vpaes_schedule_transform
    mov r1, #7

.Loop_schedule_256:
	bl	vpaes_schedule_mangle
    vmov    q6, q0

	bl	vpaes_schedule_round
    subs    r1, r1, #1
	beq	.Lschedule_mangle_last
	bl	vpaes_schedule_mangle

    vdup.32 q0, d1[1]
    vmov    q5, q7
    vmov    q7, q6
	bl  	vpaes_schedule_low_round
    vmov    q7, q5

	b	.Loop_schedule_256

    .align  4
.Lk_opt:
.quad   0xFF9F4929D6B66000, 0xF7974121DEBE6808
.quad   0x01EDBD5150BCEC00, 0xE10D5DB1B05C0CE0

.Lk_deskew:
.quad   0x07E4A34047A4E300, 0x1DFEB95A5DBEF91A
.quad   0x5F36B5DC83EA6900, 0x2841C2ABF49D1E77

    .align	4
.Lschedule_mangle_last:

	adr     r11, .Lk_deskew
    cmp     r3, #0
    bne 	.Lschedule_mangle_last_dec

    add     r12, r8, r10
    vld1.8  {q1}, [r12]
	adr	    r11, .Lk_opt
    vtbl.8  d2, {q0}, d2
    vtbl.8  d3, {q0}, d3
    vmov    q0, q1
    add     r2, r2, #32

.Lschedule_mangle_last_dec:
    adr     r12, .Lk_s63
	sub     r2, r2, #16
    vld1.8  {q1}, [r12]
    veor    q0, q0, q1
	bl  	vpaes_schedule_transform
    vst1.8  {q0}, [r2]

    restore_all_neon

    eor     r0, r0, r0
    vpaes_pop


    .align	4
vpaes_schedule_192_smear:
    vdup.32 q1, d12[0]
    vdup.32 q0, d15[1]
    vmov    s7, s26
    vmov    s0, s30
    veor    q6, q6, q1
    veor    q6, q6, q0
    vmov    q0, q6
    veor    d12, d12, d12
    bx      lr


    .align	4
vpaes_schedule_round:

    veor    q1, q1, q1
    vext.8  q1, q8, q1, #15
    vext.8  q8, q8, q8, #15
    veor    q7, q7, q1
    vdup.32 q0, d1[1]
    vext.8  q0, q0, q0, #1

vpaes_schedule_low_round:

    veor    q1, q1, q1
    adr     r12, .Lk_s63
    vext.8  q1, q1, q7, #12
    veor    q2, q2, q2
    veor    q7, q7, q1
    vld1.8  {q1}, [r12]
    vext.8  q2, q2, q7, #8
    veor    q7, q7, q1
    veor    q7, q7, q2


    vbic    q1, q0, q9
    vshr.u32    q1, q1, #4
    vand    q0, q0, q9

    vtbl.8  d4, {q11}, d0
    vtbl.8  d5, {q11}, d1

    veor    q0, q0, q1

    vtbl.8  d6, {q10}, d2
    vtbl.8  d7, {q10}, d3

    veor    q3, q3, q2

    vtbl.8  d8, {q10}, d0
    vtbl.8  d9, {q10}, d1

    veor    q4, q4, q2

    vtbl.8  d4, {q10}, d6
    vtbl.8  d5, {q10}, d7

    veor    q2, q2, q0


    vtbl.8  d6, {q10}, d8
    vtbl.8  d7, {q10}, d9

    veor    q3, q3, q1

    vtbl.8  d8, {q13}, d4
    vtbl.8  d9, {q13}, d5

    vtbl.8  d0, {q12}, d6
    vtbl.8  d1, {q12}, d7

    veor    q0, q0, q4
    veor    q0, q0, q7
    vmov    q7, q0

    bx      lr

    .align	4
vpaes_schedule_transform:
    vbic        q1, q0, q9
    vldmia      r11, {q4-q5}
    vand        q0, q0, q9
    vshr.u32    q1, q1, #4
    vtbl.8      d0, {q4}, d0
    vtbl.8      d1, {q4}, d1
    vtbl.8      d2, {q5}, d2
    vtbl.8      d3, {q5}, d3
    veor        q0, q0, q1
    bx          lr


    .align  4
.Lk_mc_forward2:
    .quad   0x0407060500030201, 0x0C0F0E0D080B0A09
.Lk_s63:
    .quad   0x5B5B5B5B5B5B5B5B, 0x5B5B5B5B5B5B5B5B

.Lk_dksd:
.quad	0xFEB91A5DA3E44700, 0x0740E3A45A1DBEF9
.quad	0x41C277F4B5368300, 0x5FDC69EAAB289D1E
.Lk_dksb:
.quad	0x9A4FCA1F8550D500, 0x03D653861CC94C99
.quad	0x115BEDA7B6FC4A00, 0xD993256F7E3482C8
.Lk_dkse:
.quad	0xD5031CCA1FC9D600, 0x53859A4C994F5086
.quad	0xA23196054FDC7BE8, 0xCD5EF96A20B31487
.Lk_dks9:
.quad	0xB6116FC87ED9A700, 0x4AED933482255BFC
.quad	0x4576516227143300, 0x8BB89FACE9DAFDCE

    .align	4
vpaes_schedule_mangle:
    vstmdb  sp!, {q6-q7}
    adr     r12, .Lk_mc_forward2
    vmov    q4, q0
    cmp     r3, #0
    vldmia  r12!, {q5-q6}        // q5 = Lk_mc_forward2, q6 = Lk_s63
    bne     .Lschedule_mangle_dec
    add     r2, r2, #16
    veor    q4, q4, q6

    vtbl.8  d6, {q4}, d10
    vtbl.8  d7, {q4}, d11
    vtbl.8  d8, {q3}, d10
    vtbl.8  d9, {q3}, d11
    vtbl.8  d2, {q4}, d10
    vtbl.8  d3, {q4}, d11
    veor    q3, q3, q4
    veor    q3, q3, q1
	b       .Lschedule_mangle_both

    .align	4
.Lschedule_mangle_dec:

    vbic    q1, q4, q9
    vldmia  r12!, {q6-q7}
    vshr.u32    q1, q1, #4
    vand    q4, q4, q9

    vtbl.8  d4, {q6}, d8
    vtbl.8  d5, {q6}, d9
    vtbl.8  d6, {q7}, d2
    vtbl.8  d7, {q7}, d3
    vldmia  r12!, {q6-q7}
    veor    q2, q3, q2
    vtbl.8  d6, {q2}, d10
    vtbl.8  d7, {q2}, d11


    vtbl.8  d4, {q6}, d8
    vtbl.8  d5, {q6}, d9
    veor    q2, q2, q3
    vtbl.8  d6, {q7}, d2
    vtbl.8  d7, {q7}, d3
    vldmia  r12!, {q6-q7}
    veor    q2, q3, q2
    vtbl.8  d6, {q2}, d10
    vtbl.8  d7, {q2}, d11

    vtbl.8  d4, {q6}, d8
    vtbl.8  d5, {q6}, d9
    veor    q2, q2, q3
    vtbl.8  d6, {q7}, d2
    vtbl.8  d7, {q7}, d3
    vldmia  r12!, {q6-q7}
    veor    q2, q3, q2
    vtbl.8  d6, {q2}, d10
    vtbl.8  d7, {q2}, d11

    vtbl.8  d4, {q6}, d8
    vtbl.8  d5, {q6}, d9
    veor    q2, q2, q3
    vtbl.8  d6, {q7}, d2
    vtbl.8  d7, {q7}, d3
    veor    q3, q3, q2

    sub     r2, r2, #16

.Lschedule_mangle_both:
    add     r12, r10, r8
    vld1.8  {q1}, [r12]
    sub     r8, r8, #16
    vtbl.8  d4, {q3}, d2
    vtbl.8  d5, {q3}, d3
    and     r8, r8, #48
    vst1.8  {q2}, [r2]
    vldmia  sp!, {q6-q7}
    bx      lr




/*
    int vpaes_set_encrypt_key(const uint8_t *userKey, int bits, void *key);
*/

    #define userKey     r0
    #define AES_bits    r1
    #define key         r2 
    #define t           r12
    .globl	_vpaes_set_encrypt_key
    .align	4
_vpaes_set_encrypt_key:


    // 128/192/256 divide by 32 = 4/6/8 + 5 - 9/11/13
    lsr     t, AES_bits, #5  
    vpaes_push
    mov     r11, t
    EnableVFP
    save_all_neon
    add     t, r11, #5
    mov     r3, #0
    str     t, [key, #240] 
    mov     r8, #48 
    b       vpaes_schedule_core

    .globl	_vpaes_set_decrypt_key
    .align	4
_vpaes_set_decrypt_key:
    lsr     t, AES_bits, #5  
    vpaes_push
    mov     r11, t
    EnableVFP
    save_all_neon
    mov     r8, #32
    add     t, r11, #5
    and     r8, r8, AES_bits, lsr #1
    mov     r3, #1
    str     t, [key, #240] 
    add     key, key, #16
    eor     r8, r8, #32
    add     key, key, t, lsl #4
    b       vpaes_schedule_core

    .align	4
vpaes_preheat:
    adr     r12, .Lk_s0F
    vldmia  r12, {q9-q15}
    bx      lr

    .align  6
// the following 7 16-bytes words are loaded into 
.Lk_s0F:
.quad	0x0F0F0F0F0F0F0F0F, 0x0F0F0F0F0F0F0F0F
.Lk_inv:
.quad	0x0E05060F0D080180, 0x040703090A0B0C02
.quad	0x01040A060F0B0780, 0x030D0E0C02050809
.Lk_sb1:
.quad	0x3618D415FAE22300, 0x3BF7CCC10D2ED9EF
.quad	0xB19BE18FCB503E00, 0xA5DF7A6E142AF544
.Lk_sb2:
.quad	0x69EB88400AE12900, 0xC2A163C8AB82234A
.quad	0xE27A93C60B712400, 0x5EB7E955BC982FCD

#endif // CCAES_ARM_ASM && !defined(__arm64__) && defined(__ARM_NEON__)

# Copyright (c) (2015,2016,2019,2021) Apple Inc. All rights reserved.
#
# corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
# is contained in the License.txt file distributed with corecrypto) and only to
# people who accept that license. IMPORTANT:  Any license rights granted to you by
# Apple Inc. (if any) are limited to internal use within your organization only on
# devices and computers you own or control, for the sole purpose of verifying the
# security characteristics and correct functioning of the Apple Software.  You may
# not, directly or indirectly, redistribute the Apple Software or any portions thereof.


#if !defined(__arm64__) && defined(__ARM_NEON__)

    #define ekey    r2
    #define eax     r4

    .macro  save_all_neon
#if BUILDKERNEL
    vstmdb  sp!, {q12-q15}
    vstmdb  sp!, {q8-q11}
    vstmdb  sp!, {q0-q3}
#endif
    vstmdb  sp!, {q4-q7}
    .endm

    .macro  restore_all_neon
    vldmia  sp!, {q4-q7}
#if BUILDKERNEL
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

    .p2align  6
.Lk_ipt:
.quad   0xC2B2E8985A2A7000, 0xCABAE09052227808
.quad   0x4C01307D317C4D00, 0xCD80B1FCB0FDCC81

.Lk_sbo:
.quad   0xD0D26D176FBDC700, 0x15AABF7AC502A878
.quad   0xCFE474A55FBB6A00, 0x8E1E90D1412B35FA

.Lk_mc_forward:
.quad	0x0407060500030201, 0x0C0F0E0D080B0A09
.quad	0x080B0A0904070605, 0x000302010C0F0E0D
.quad	0x0C0F0E0D080B0A09, 0x0407060500030201
.quad	0x000302010C0F0E0D, 0x080B0A0904070605

.Lk_mc_backward:
.quad	0x0605040702010003, 0x0E0D0C0F0A09080B
.quad	0x020100030E0D0C0F, 0x0A09080B06050407
.quad	0x0E0D0C0F0A09080B, 0x0605040702010003
.quad	0x0A09080B06050407, 0x020100030E0D0C0F

.quad   0x0706050403020100, 0x0F0E0D0C0B0A0908
.quad   0x030E09040F0A0500, 0x0B06010C07020D08
.quad   0x0F060D040B020900, 0x070E050C030A0108
.quad   0x0B0E0104070A0D00, 0x0306090C0F020508


    .p2align	4
vpaes_encrypt_core:
	mov     r9, ekey
	mov	    r11, #16
    adr     r10, .Lk_ipt
    ldr     eax, [ekey, #240]
    vldmia  r10!,{q3-q4}
    vbic    q1, q0, q9
    vld1.8 {q5}, [r9]!
    vshr.u32    q1, q1, #4
    vand    q0, q0, q9

    vtbl.8  d4, {q3}, d0
    vtbl.8  d5, {q3}, d1

    adr     r10, .Lk_mc_backward

    vtbl.8  d0, {q4}, d2
    vtbl.8  d1, {q4}, d3
    veor    q2, q2, q5
    veor    q0, q0, q2
    cmp     eax, #0
	b       .Lenc_entry

    .p2align	4
.Lenc_loop:

    vtbl.8  d8, {q13}, d4
    vtbl.8  d9, {q13}, d5
    vtbl.8  d0, {q12}, d6
    vtbl.8  d1, {q12}, d7
    veor    q4, q4, q5
    add     r12, r10, r11
    veor    q5, q0, q4
    vld1.8 {q4}, [r12 :128]
    sub     r12, r12, #64
    vtbl.8  d12, {q15}, d4
    vtbl.8  d13, {q15}, d5
    vld1.8 {q1}, [r12 :128]

    vtbl.8  d4, {q14}, d6
    vtbl.8  d5, {q14}, d7

    veor    q2, q2, q6

    vtbl.8  d6, {q5}, d8
    vtbl.8  d7, {q5}, d9
    vtbl.8  d0, {q5}, d2
    vtbl.8  d1, {q5}, d3
    veor    q5, q0, q2

    add     r11, r11, #16
    veor    q3, q3, q5
    vtbl.8  d0, {q5}, d2
    vtbl.8  d1, {q5}, d3
    and     r11, r11, #48
    subs    eax, eax, #1
    veor    q0, q0, q3

.Lenc_entry:


    vbic    q1, q0, q9
    vand    q0, q0, q9
    vshr.u32    q1, q1, #4

    vtbl.8  d10, {q11}, d0
    vtbl.8  d11, {q11}, d1

    veor    q0, q0, q1

    vtbl.8  d6, {q10}, d2
    vtbl.8  d7, {q10}, d3
    vtbl.8  d8, {q10}, d0
    vtbl.8  d9, {q10}, d1

    veor    q3, q3, q5
    veor    q4, q4, q5

    vtbl.8  d4, {q10}, d6
    vtbl.8  d5, {q10}, d7
    vtbl.8  d6, {q10}, d8
    vtbl.8  d7, {q10}, d9

    veor    q2, q2, q0
    veor    q3, q3, q1

    vld1.8 {q5}, [r9]!
    bgt 	.Lenc_loop

    adr     r12, .Lk_sbo

    vld1.8 {q1}, [r12]!
    vtbl.8  d8, {q1}, d4
    vtbl.8  d9, {q1}, d5
    vld1.8 {q2}, [r12]
    add     r12, r10, r11
    veor    q4, q4, q5
    add     r12, r12, #64
    vtbl.8  d0, {q2}, d6
    vtbl.8  d1, {q2}, d7
    vld1.8 {q1}, [r12]
    veor    q2, q0, q4
    vtbl.8  d0, {q2}, d2
    vtbl.8  d1, {q2}, d3
    bx      lr


    .p2align  4
.Lk_dipt:
.quad	0x0F505B040B545F00, 0x154A411E114E451A
.quad	0x86E383E660056500, 0x12771772F491F194
.quad	0x000302010C0F0E0D, 0x080B0A0904070605      // .Lk_mc_forward+48

.Lk_dsb9:
.quad   0x851C03539A86D600, 0xCAD51F504F994CC9
.quad   0xC03B1789ECD74900, 0x725E2C9EB2FBA565
.Lk_dsbd:
.quad   0x7D57CCDFE6B1A200, 0xF56E9B13882A4439
.quad   0x3CE2FAF724C6CB00, 0x2931180D15DEEFD3
.Lk_dsbb:
.quad   0xD022649296B44200, 0x602646F6B0F2D404
.quad   0xC19498A6CD596700, 0xF3FF0C3E3255AA6B
.Lk_dsbe:
.quad   0x46F2929626D4D000, 0x2242600464B4F6B0
.quad   0x0C55A6CDFFAAC100, 0x9467F36B98593E32
.Lk_dsbo:
.quad   0x1387EA537EF94000, 0xC7AA6DB9D4943E2D
.quad   0x12D7560F93441D00, 0xCA4B8159D8C58E9C

.quad   0x0706050403020100, 0x0F0E0D0C0B0A0908
.quad   0x0F060D040B020900, 0x070E050C030A0108


    .p2align	4
vpaes_decrypt_core:
    mov     r9, r2              // dkey
    ldr     eax, [r2, #240]     // Nr
    adr     r12, .Lk_dipt
    vbic    q1, q0, q9
    vld1.64 {q3}, [r12 :128]!
    vshr.u32    q1, q1, #4
    vld1.8  {q5}, [r9]!
	lsl     r11, eax, #4
    vand    q2, q0, q9
    vtbl.8  d4, {q3}, d4
    vtbl.8  d5, {q3}, d5
    vld1.64 {q4}, [r12 :128]!
    eor     r11, r11, #48
    adr     r10, .Lk_dsbd
    vtbl.8  d0, {q4}, d2
    vtbl.8  d1, {q4}, d3
    and     r11, r11, #48
    veor    q2, q2, q5
    vld1.64 {q5}, [r12 :128]!
    veor    q0, q0, q2
    cmp     eax, #0
	b       .Ldec_entry

    .p2align	4
.Ldec_loop:

    sub     r12, r10, 32
    vld1.64 {q6-q7}, [r12 :128]!
    vtbl.8  d8, {q6}, d4
    vtbl.8  d9, {q6}, d5
    vtbl.8  d2, {q7}, d6
    vtbl.8  d3, {q7}, d7
    vld1.64 {q6-q7}, [r12 :128]!
    veor    q0, q0, q4
    vtbl.8  d8, {q6}, d4
    vtbl.8  d9, {q6}, d5
    veor    q6, q0, q1
    vtbl.8  d2, {q7}, d6
    vtbl.8  d3, {q7}, d7
    vtbl.8  d0, {q6}, d10
    vtbl.8  d1, {q6}, d11
    vld1.64 {q6-q7}, [r12 :128]!

    veor    q0, q0, q4
    vtbl.8  d8, {q6}, d4
    vtbl.8  d9, {q6}, d5
    veor    q6, q0, q1
    vtbl.8  d2, {q7}, d6
    vtbl.8  d3, {q7}, d7
    vtbl.8  d0, {q6}, d10
    vtbl.8  d1, {q6}, d11
    vld1.64 {q6-q7}, [r12 :128]!

    veor    q0, q0, q4
    vtbl.8  d8, {q6}, d4
    vtbl.8  d9, {q6}, d5
    veor    q6, q0, q1
    vtbl.8  d2, {q7}, d6
    vtbl.8  d3, {q7}, d7
    vtbl.8  d0, {q6}, d10
    vtbl.8  d1, {q6}, d11

    veor    q0, q0, q4

    vext.8  q5, q5, q5, #12
    veor    q0, q0, q1
    subs    eax, eax, #1

.Ldec_entry:

    vbic    q1, q0, q9
    vand    q0, q0, q9
    vshr.u32    q1, q1, #4
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

    vld1.8 {q0}, [r9]!
    veor    q3, q3, q1
    bne     .Ldec_loop

    vld1.64 {q6-q7}, [r12 :128]!

    vtbl.8  d8, {q6}, d4
    vtbl.8  d9, {q6}, d5
    add     r12, r12, r11, lsr #1
    vtbl.8  d6, {q7}, d6
    vtbl.8  d7, {q7}, d7
    vld1.64 {q2}, [r12]
    veor    q0, q0, q4
    veor    q1, q0, q3

    vtbl.8  d0, {q1}, d4
    vtbl.8  d1, {q1}, d5
    bx      lr


/*
    void vpaes_encrypt(const unsigned char *in, unsigned char *out, const AES_KEY *key);
*/
    #define in      r0
    #define out     r1
    #define key     r2

    .globl	_AccelerateCrypto_vpaes_encrypt
    .p2align	4
_AccelerateCrypto_vpaes_encrypt:
    vpaes_push
    save_all_neon
    vld1.8  {q0}, [in]
    bl      vpaes_preheat
	bl	    vpaes_encrypt_core
    vst1.8  {q0}, [out]
    restore_all_neon
    eor     r0, r0      // return 0 for SUCCESS
    vpaes_pop

    .globl	_AccelerateCrypto_vpaes_decrypt
    .p2align	4
_AccelerateCrypto_vpaes_decrypt:
    vpaes_push
    save_all_neon
    vld1.8  {q0}, [in]
	bl  	vpaes_preheat
	bl      vpaes_decrypt_core
    vst1.8  {q0}, [out]
    restore_all_neon
    eor     r0, r0      // return 0 for SUCCESS
    vpaes_pop

    .p2align	4
vpaes_preheat:
    adr     r12, .Lk_s0F
    vldmia  r12, {q9-q15}
    bx      lr

    .p2align  6
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

#endif // !defined(__arm64__) && defined(__ARM_NEON__)

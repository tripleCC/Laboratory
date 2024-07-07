# Copyright (c) (2016,2019,2022) Apple Inc. All rights reserved.
#
# corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
# is contained in the License.txt file distributed with corecrypto) and only to
# people who accept that license. IMPORTANT:  Any license rights granted to you by
# Apple Inc. (if any) are limited to internal use within your organization only on
# devices and computers you own or control, for the sole purpose of verifying the
# security characteristics and correct functioning of the Apple Software.  You may
# not, directly or indirectly, redistribute the Apple Software or any portions thereof.

#include <corecrypto/cc_config.h>

#if CCSHA256_ARMV6M_ASM

.text
.syntax unified
.code 16

#define W          0
#define W_LEN      (4*80)
#define STACK_SIZE (W_LEN+(8*4))

#define STATE       (4+W_LEN)
#define NBLOCKS     (8+W_LEN)
#define INPUT_DATA (12+W_LEN)
#define SHA256TBL  (16+W_LEN)
#define BLOCK_SIZE 64

#define A r0
#define B r1
#define C r2
#define D r3
#define E r4
#define F r5
#define G r6
#define H r7
#define HH r8
#define DD r9
#define TT r10
#define Sha256Table r11
#define Idx r12


//r = Gamma0(x)  x>>>18 ^ x >>3 ^ x>>>7
.macro Gamma rv x n1 n2 n3
    mov r7, \x
    movs \rv, \n1
    rors r7, \rv
    lsrs r6, \x, \n2
    eors r6, r7

    movs r7, \n3
    mov \rv, \x
    rors \rv, r7
    eors \rv, r6
.endm

//-- Maj(x,y,z)  ((x|y)&z) | (x& y)
.macro Maj tmp rv x y z
    mov  \rv, \x
    orrs \rv, \y
    ands \rv, \z

    mov  \tmp, \x
    ands \tmp, \y
    orrs \rv, \tmp
.endm

//-- Sigma(x)  x>>>n1 ^ x>>>n2 ^ x>>>n3
.macro Sigma tmp rv x n1 n2 n3
    mov TT, \x

    movs \tmp, \n1
    mov  \rv, TT
    rors \rv, \tmp

    movs \tmp, \n2
    rors \x, \tmp

    eors \rv, \x

    movs \tmp, \n3
    mov  \x, TT
    rors \x, \tmp

    eors \rv, \x

    mov \x, TT
.endm

//-- Ch(x,y,z)  z^(x&(y^z))
.macro Ch rv x y z
    mov  \rv, \z
    eors \rv, \y
    ands \rv, \x
    eors \rv, \z
.endm

.macro Add_Ki_Wi tmp rv io ii
    mov \tmp, \ii

    mov \rv, Sha256Table
    ldr \rv, [\rv, \tmp]
    add \io, \rv

    add \rv, sp, #W
    ldr \rv, [\rv, \tmp]
    add \io, \rv
.endm

.macro Load_Ki tmp rv ii
    mov \tmp, \ii
    mov \rv, Sha256Table
    ldr \rv, [\rv, \tmp]
.endm

.macro Load_Wi tmp rv ii
    mov \tmp, \ii
    add \rv, sp, #W
    ldr \rv, [\rv, \tmp]
.endm

//---------------------------------------------------------------------
//h =  h + Sigma1(e) + Ch(e, f, g) + K[i] + W[i];
//d += h;
//h  = h + Sigma0(a) + Maj(a, b, c);

.macro Round A B C tmp E F G rv ii
    mov HH, \rv
    mov DD, \tmp

    Sigma   \tmp, \rv, \E, #11, #6, #25
    add HH, \rv

    Ch      \rv, \E, \F, \G
    add HH, \rv

    Add_Ki_Wi \tmp, \rv, HH, \ii

    add DD, HH

    Sigma   \tmp, \rv, \A, #13, #2, #22
    add HH, \rv

    Maj \tmp, \rv, \A, \B, \C
    add HH, \rv

    movs \tmp, #4
    add \ii, \tmp

    mov \rv, HH
    mov \tmp, DD
.endm

.macro Update_State tmp V in ofs
    ldr \tmp, [\V, \ofs]
    add \tmp, \in
    str \tmp, [\V, \ofs]
.endm


.align 2
.globl _ccsha256_v6m_compress
.thumb_func
_ccsha256_v6m_compress: /* void ccsha256_v6m_compress(ccdigest_state_t c, size_t nblocks, const void *data); */
    push {r4, r5, r6, r7, lr}

    mov r3, r8
    push {r3}
    mov r3, r9
    push {r3}
    mov r3, r10
    push {r3}
    mov r3, r11
    push {r3}
    mov r3, r12
    push {r3}

    sub sp, #STACK_SIZE
    cmp r1, #0
    bne L_Start
    b   L_Return

L_Start:
    str r0, [sp, #STATE]
    str r1, [sp, #NBLOCKS]
    str r2, [sp, #INPUT_DATA]

    bl L_Set_Sha256_Table_Address

L_NBlocks_Loop:

//-- schedule W[0] tp W[15] -------------------------------------------------

    .macro Set_W_0_15 input_data ofs
      ldr r0, [\input_data, #(4*\ofs)]
      rev r0, r0
      str r0, [sp, #(W + 4*\ofs)]
    .endm

    ldr r1, [sp, #INPUT_DATA]
    Set_W_0_15 r1, 15
    Set_W_0_15 r1, 14
    Set_W_0_15 r1, 13
    Set_W_0_15 r1, 12
    Set_W_0_15 r1, 11
    Set_W_0_15 r1, 10
    Set_W_0_15 r1, 9
    Set_W_0_15 r1, 8
    Set_W_0_15 r1, 7
    Set_W_0_15 r1, 6
    Set_W_0_15 r1, 5
    Set_W_0_15 r1, 4
    Set_W_0_15 r1, 3
    Set_W_0_15 r1, 2
    Set_W_0_15 r1, 1
    Set_W_0_15 r1, 0

//-- schedule W[16] tp W[63] -------------------------------------------------

//W[i] = Gamma1(W[i - 2]) + W[i - 7] + Gamma0(W[i - 15]) + W[i - 16];
    movs r1, #0
    add  r2, sp, #W

L_Set_W_16_63:
    adds r3, r2, r1

    ldr  r4, [r3, #36]
    adds r0, r4

    ldr   r4, [r3, #56]
    Gamma r5, r4, #19, #10, #17
    adds  r0, r5

    ldr   r4, [r3, #4]
    Gamma r5, r4, #18, #3, #7
    adds  r0, r5

    str r0, [r3, #64]
    mov r0, r4

    adds r1, #4
    cmp  r1, #(64-16)*4
    bne  L_Set_W_16_63

//---------------------------------------------------------------------

    movs r0, #0
    mov Idx, r0

    ldr H, [sp, #STATE]
    ldr A, [H, #0]
    ldr B, [H, #4]
    ldr C, [H, #8]
    ldr D, [H, #12]
    ldr E, [H, #16]
    ldr F, [H, #20]
    ldr G, [H, #24]
    ldr H, [H, #28]

L_Round_Loop:
    Round  A, B, C, D, E, F, G, H, Idx
    Round  H, A, B, C, D, E, F, G, Idx
    Round  G, H, A, B, C, D, E, F, Idx
    Round  F, G, H, A, B, C, D, E, Idx
    Round  E, F, G, H, A, B, C, D, Idx
    Round  D, E, F, G, H, A, B, C, Idx
    Round  C, D, E, F, G, H, A, B, Idx
    Round  B, C, D, E, F, G, H, A, Idx

    mov TT, r0
    mov r0, Idx
    cmp r0, #255
    mov r0, TT
    bge L_Out_Of_Loop
    b L_Round_Loop

L_Out_Of_Loop:
    mov HH, H
    mov DD, D
    ldr H, [sp, #STATE]
    Update_State D, H, A, #0
    Update_State D, H, B, #4
    Update_State D, H, C, #8
    Update_State D, H, DD, #12
    Update_State D, H, E, #16
    Update_State D, H, F, #20
    Update_State D, H, G, #24
    Update_State D, H, HH, #28

    ldr r0, [sp, #INPUT_DATA]
    movs r1, #BLOCK_SIZE
    adds r0, r1
    str r0, [sp, #INPUT_DATA]

    ldr r0, [sp, #NBLOCKS]
    subs r0, #1
    str r0, [sp, #NBLOCKS]
    beq L_Return
    b   L_NBlocks_Loop

L_Return:
    add sp, #STACK_SIZE

    pop {r3}
    pop {r2}
    pop {r1}
    pop {r0}
    mov r12, r3
    pop {r3}
    mov r11, r2
    mov r10, r1
    mov r9, r0
    mov r8, r3

    pop {r4, r5, r6, r7, pc}

//---------------------------------------------------------------------

L_Set_Sha256_Table_Address:
    adr r0, L_Sha256Table_Indicator
    ldr r0, [r0]

L_Sha256Table_Save:
    add r0, pc
    str r0, [sp, #SHA256TBL]
    mov Sha256Table, r0
    mov pc, lr

//---------------------------------------------------------------------

.align 4
L_Sha256Table_Indicator:
    .long L_ccsha256_K-(L_Sha256Table_Save+4)

L_ccsha256_K:
    .long 0x428a2f98
    .long 0x71374491
    .long 0xb5c0fbcf
    .long 0xe9b5dba5
    .long 0x3956c25b
    .long 0x59f111f1
    .long 0x923f82a4
    .long 0xab1c5ed5
    .long 0xd807aa98
    .long 0x12835b01
    .long 0x243185be
    .long 0x550c7dc3
    .long 0x72be5d74
    .long 0x80deb1fe
    .long 0x9bdc06a7
    .long 0xc19bf174
    .long 0xe49b69c1
    .long 0xefbe4786
    .long 0x0fc19dc6
    .long 0x240ca1cc
    .long 0x2de92c6f
    .long 0x4a7484aa
    .long 0x5cb0a9dc
    .long 0x76f988da
    .long 0x983e5152
    .long 0xa831c66d
    .long 0xb00327c8
    .long 0xbf597fc7
    .long 0xc6e00bf3
    .long 0xd5a79147
    .long 0x06ca6351
    .long 0x14292967
    .long 0x27b70a85
    .long 0x2e1b2138
    .long 0x4d2c6dfc
    .long 0x53380d13
    .long 0x650a7354
    .long 0x766a0abb
    .long 0x81c2c92e
    .long 0x92722c85
    .long 0xa2bfe8a1
    .long 0xa81a664b
    .long 0xc24b8b70
    .long 0xc76c51a3
    .long 0xd192e819
    .long 0xd6990624
    .long 0xf40e3585
    .long 0x106aa070
    .long 0x19a4c116
    .long 0x1e376c08
    .long 0x2748774c
    .long 0x34b0bcb5
    .long 0x391c0cb3
    .long 0x4ed8aa4a
    .long 0x5b9cca4f
    .long 0x682e6ff3
    .long 0x748f82ee
    .long 0x78a5636f
    .long 0x84c87814
    .long 0x8cc70208
    .long 0x90befffa
    .long 0xa4506ceb
    .long 0xbef9a3f7
    .long 0xc67178f2

#endif

/* Copyright (c) (2023) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

// This file is auto-generated. Please don't modify it.

// Store the 512-bit product on the stack.
sub sp, #(16*4)

ldr r3, [r1, #(6*4)]
ldr r4, [r2, #(0*4)]

// A6 * B0
umull r9, r10, r3, r4

str r9, [sp, #(6*4)]

mov r11, #0
mov r12, #0

ldr r5, [r1, #(7*4)]
ldr r6, [r2, #(1*4)]

// A7 * B0
umaal r10, r11, r5, r4

// A6 * B1
umaal r10, r12, r3, r6

str r10, [sp, #(7*4)]

// A7 * B1
umaal r11, r12, r5, r6

str r11, [sp, #(8*4)]
str r12, [sp, #(9*4)]

ldr r7, [r1, #(0*4)]

// A0 * B0
umull r12, r9, r7, r4

str r12, [sp, #(0*4)]

mov r10, #0
mov r11, #0

ldr r8, [r1, #(1*4)]

// A1 * B0
umaal r9, r10, r8, r4

// A0 * B1
umaal r9, r11, r7, r6

str r9, [sp, #(1*4)]

mov r12, #0
mov r9, #0

ldr r3, [r1, #(2*4)]
ldr r5, [r2, #(2*4)]

// A2 * B0
umaal r10, r11, r3, r4

// A1 * B1
umaal r10, r12, r8, r6

// A0 * B2
umaal r10, r9, r7, r5

str r10, [sp, #(2*4)]

mov r10, #0

ldr r4, [r2, #(3*4)]

// A2 * B1
umaal r11, r12, r3, r6

// A1 * B2
umaal r11, r9, r8, r5

// A0 * B3
umaal r11, r10, r7, r4

str r11, [sp, #(3*4)]

mov r11, #0

ldr r6, [r2, #(4*4)]

// A2 * B2
umaal r12, r9, r3, r5

// A1 * B3
umaal r12, r10, r8, r4

// A0 * B4
umaal r12, r11, r7, r6

str r12, [sp, #(4*4)]

mov r12, #0

ldr r5, [r2, #(5*4)]

// A2 * B3
umaal r9, r10, r3, r4

// A1 * B4
umaal r9, r11, r8, r6

// A0 * B5
umaal r9, r12, r7, r5

str r9, [sp, #(5*4)]

ldr r9, [sp, #(6*4)]
ldr r4, [r2, #(6*4)]

// A2 * B4
umaal r10, r11, r3, r6

// A1 * B5
umaal r10, r12, r8, r5

// A0 * B6
umaal r10, r9, r7, r4

str r10, [sp, #(6*4)]

ldr r10, [sp, #(7*4)]
ldr r6, [r2, #(7*4)]

// A2 * B5
umaal r11, r12, r3, r5

// A1 * B6
umaal r11, r9, r8, r4

// A0 * B7
umaal r11, r10, r7, r6

str r11, [sp, #(7*4)]

ldr r11, [sp, #(8*4)]
ldr r7, [r1, #(3*4)]

// A3 * B5
umaal r12, r9, r7, r5

// A2 * B6
umaal r12, r10, r3, r4

// A1 * B7
umaal r12, r11, r8, r6

str r12, [sp, #(8*4)]

ldr r12, [sp, #(9*4)]
ldr r8, [r1, #(4*4)]

// A4 * B5
umaal r9, r10, r8, r5

// A3 * B6
umaal r9, r11, r7, r4

// A2 * B7
umaal r9, r12, r3, r6

str r9, [sp, #(9*4)]

// A4 * B6
umaal r10, r11, r8, r4

// A3 * B7
umaal r10, r12, r7, r6

str r10, [sp, #(10*4)]

// A4 * B7
umaal r11, r12, r8, r6

str r11, [sp, #(11*4)]
str r12, [sp, #(12*4)]

mov r12, #0

ldr r9, [sp, #(3*4)]
ldr r3, [r2, #(0*4)]

// A3 * B0
umaal r12, r9, r7, r3

str r12, [sp, #(3*4)]

mov r10, #0

ldr r11, [sp, #(4*4)]
ldr r5, [r2, #(1*4)]

// A4 * B0
umaal r9, r10, r8, r3

// A3 * B1
umaal r9, r11, r7, r5

str r9, [sp, #(4*4)]

mov r12, #0

ldr r9, [sp, #(5*4)]
ldr r4, [r1, #(5*4)]
ldr r6, [r2, #(2*4)]

// A5 * B0
umaal r10, r11, r4, r3

// A4 * B1
umaal r10, r12, r8, r5

// A3 * B2
umaal r10, r9, r7, r6

str r10, [sp, #(5*4)]

ldr r10, [sp, #(6*4)]
ldr r3, [r2, #(3*4)]

// A5 * B1
umaal r11, r12, r4, r5

// A4 * B2
umaal r11, r9, r8, r6

// A3 * B3
umaal r11, r10, r7, r3

str r11, [sp, #(6*4)]

ldr r11, [sp, #(7*4)]
ldr r5, [r2, #(4*4)]

// A5 * B2
umaal r12, r9, r4, r6

// A4 * B3
umaal r12, r10, r8, r3

// A3 * B4
umaal r12, r11, r7, r5

str r12, [sp, #(7*4)]

ldr r12, [sp, #(8*4)]
ldr r7, [r1, #(6*4)]

// A6 * B2
umaal r9, r10, r7, r6

// A5 * B3
umaal r9, r11, r4, r3

// A4 * B4
umaal r9, r12, r8, r5

str r9, [sp, #(8*4)]

ldr r9, [sp, #(9*4)]
ldr r8, [r1, #(7*4)]

// A7 * B2
umaal r10, r11, r8, r6

// A6 * B3
umaal r10, r12, r7, r3

// A5 * B4
umaal r10, r9, r4, r5

str r10, [sp, #(9*4)]

ldr r10, [sp, #(10*4)]
ldr r6, [r2, #(5*4)]

// A7 * B3
umaal r11, r12, r8, r3

// A6 * B4
umaal r11, r9, r7, r5

// A5 * B5
umaal r11, r10, r4, r6

str r11, [sp, #(10*4)]

ldr r11, [sp, #(11*4)]
ldr r3, [r2, #(6*4)]

// A7 * B4
umaal r12, r9, r8, r5

// A6 * B5
umaal r12, r10, r7, r6

// A5 * B6
umaal r12, r11, r4, r3

str r12, [sp, #(11*4)]

ldr r12, [sp, #(12*4)]
ldr r5, [r2, #(7*4)]

// A7 * B5
umaal r9, r10, r8, r6

// A6 * B6
umaal r9, r11, r7, r3

// A5 * B7
umaal r9, r12, r4, r5

str r9, [sp, #(12*4)]

// A7 * B6
umaal r10, r11, r8, r3

// A6 * B7
umaal r10, r12, r7, r5

str r10, [sp, #(13*4)]

// A7 * B7
umaal r11, r12, r8, r5

str r11, [sp, #(14*4)]
str r12, [sp, #(15*4)]

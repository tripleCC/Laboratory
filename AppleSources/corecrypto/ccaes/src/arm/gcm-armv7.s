# Copyright (c) (2015,2016,2017,2019,2021) Apple Inc. All rights reserved.
#
# corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
# is contained in the License.txt file distributed with corecrypto) and only to
# people who accept that license. IMPORTANT:  Any license rights granted to you by
# Apple Inc. (if any) are limited to internal use within your organization only on
# devices and computers you own or control, for the sole purpose of verifying the
# security characteristics and correct functioning of the Apple Software.  You may
# not, directly or indirectly, redistribute the Apple Software or any portions thereof.

#include <corecrypto/cc_config.h>

#if CCAES_ARM_ASM
#if !defined(__arm64__) && defined(__ARM_NEON__)
/*
    gcm_encrypt((void*) pt, (void*) ct, (void*)  _CCMODE_GCM_KEY(key), j, (void*) HTable, (void*) CCMODE_GCM_KEY_ECB_KEY(key));

        CT = PT ^ AES_Encrypt_output;
        key->X ^= CT;
        key->X = key->X * key->H (ccmode_gcm_mult_h);
        key->Y++;
        AES_Encrypt_output = AES_Encrypt(key->Y);
        
*/

    #define     in  r4
    #define     out r5
    #define     gcm_key r6
    #define     nsize   r8
    #define     HTable  r10
    #define     ecb_key r11

    #define     key_pad     q1
    #define     X           q2
    #define     Y           q3

    .align      6
L_bswap:
    .byte   15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0
    .word   1, 0, 0, 0

    .extern     _gcm_gmult              // r0 -> X r1 -> HTable
    .extern     _AccelerateCrypto_AES_encrypt

    .text   
    .align  4
    .globl  _gcmEncrypt

_gcmEncrypt:

    mov     r12, sp
    push    {r4-r6,r8-r11,lr}
    vstmdb  sp!, {q4-q7}
#if CC_KERNEL
    vstmdb  sp!, {q8-q10}
    vstmdb  sp!, {q0-q3}
#endif

    mov     in, r0
    mov     out, r1
    mov     gcm_key, r2
    mov     nsize, r3
    ldr     HTable, [r12, #0]
    ldr     ecb_key, [r12, #4]
    adr     r9, L_bswap
    add     r12, gcm_key, #16
    vldmia  r9, {q2-q3}
    vldmia  r12, {q4-q5}           // q4 = X, q5 = Y
    vmov    q7, q3                // one  

    vtbl.8  d12, {q5}, d4         // q6 is byte reversed Y
    vtbl.8  d13, {q5}, d5
    vmov    q5, q2
    
0:
    // Q0 = PT
    vld1.8      {q0}, [in]!

    // Q1 = AES_Encrypt_output
    vldr        d2, [gcm_key, #64]
    vldr        d3, [gcm_key, #72]

    veor    q0, q0, q1          // CT =  PT ^ AES_Encrypt_output;
    veor    q4, q4, q0          // key->X ^= CT

    add     r0, gcm_key, #16    // r0 -> key->X;
    mov     r1, HTable          // r1 -> HTable;
    mov     r2, r0              // r2 -> key->X;

    vst1.8  {q4}, [r0]          // update key->X;
    vst1.8  {q0}, [out]!        // write output ciphertext;

#if defined(__ARM_ARCH_7EM__)
    bl  _gcm_gmult // call gcm_gmult to update key->X;
#else
    blx _gcm_gmult // call gcm_gmult to update key->X;
#endif

    add     r12, gcm_key, #16

    vadd.i32    q6, q6, q7      // Y++;
    add         r0, gcm_key, #32
    vld1.8      {q4}, [r12]     // load updated key->X
    vtbl.8      d2, {q6}, d10   // byte swapped back to little-endian (to call _AccelerateCrypto_AES_encrypt)
    add         r1, r12, #48    // output in gcm ctx KEY_PAD
    vtbl.8      d3, {q6}, d11
    mov         r2, ecb_key     // expanded AES Key

    // update Y in the gcm ctx
    vstr        d2, [r12, #16] 
    vstr        d3, [r12, #24] 

#if defined(__ARM_ARCH_7EM__)
    bl          _AccelerateCrypto_AES_encrypt
#else
    blx         _AccelerateCrypto_AES_encrypt
#endif

    subs        nsize, nsize, #16
    bne         0b // nsize is guaranteed to be a multiple of 16: loop until zero

#if CC_KERNEL
    vldmia  sp!, {q0-q3}
    vldmia  sp!, {q8-q10}
#endif
    vldmia  sp!, {q4-q7}

    pop     {r4-r6,r8-r11,pc}

/*
    gcm_decrypt((void*) ct, (void*) pt, (void*)  _CCMODE_GCM_KEY(key), j, (void*) HTable, (void*) CCMODE_GCM_KEY_ECB_KEY(key));

        key->X ^= CT;
        PT = CT ^ AES_Encrypt_output;
        key->X = key->X * key->H (ccmode_gcm_mult_h);
        key->Y++;
        AES_Encrypt_output = AES_Encrypt(key->Y);
        
*/
    .align  4
    .globl  _gcmDecrypt

_gcmDecrypt:

    mov     r12, sp
    push    {r4-r6,r8-r11,lr}
    vstmdb  sp!, {q4-q7}
#if CC_KERNEL
    vstmdb  sp!, {q8-q10}
    vstmdb  sp!, {q0-q3}
#endif

    mov     in, r0
    mov     out, r1
    mov     gcm_key, r2
    mov     nsize, r3
    ldr     HTable, [r12, #0]
    ldr     ecb_key, [r12, #4]
    adr     r9, L_bswap
    add     r12, gcm_key, #16
    vldmia  r9, {q2-q3}
    vldmia  r12, {q4-q5}           // q4 = X, q5 = Y
    vmov    q7, q3                // one  

    vtbl.8  d12, {q5}, d4         // q6 is byte reversed Y
    vtbl.8  d13, {q5}, d5
    vmov    q5, q2
    
0:
    // Q0 = CT;
    vld1.8  {q0}, [in]!

    // Q1 = AES_Encrypt_output;
    vldr        d2, [gcm_key, #64]
    vldr        d3, [gcm_key, #72]

    veor    q4, q4, q0          // key->X ^= CT;
    veor    q0, q0, q1          // PT = CT ^ AES_Encrypt_output;

    add     r0, gcm_key, #16    // r0 -> key->X;
    mov     r1, HTable          // r1 -> HTable;
    mov     r2, r0              // r2 -> key->X;

    vst1.8  {q4}, [r0]          // write to key->X (input to _gcm_gmult)
    vst1.8  {q0}, [out]!        // write output vector

#if defined(__ARM_ARCH_7EM__)
    bl  _gcm_gmult  // call gcm_gmult to update key->X;
#else
    blx _gcm_gmult // call gcm_gmult to update key->X;
#endif

    add         r12, gcm_key, #16   // r12 -> key->X
    vadd.i32    q6, q6, q7          // Y++;
    add         r0, gcm_key, #32    // r0 -> key->Y
    vld1.8      {q4}, [r12]         // reload Q4 = key->X
    vtbl.8      d2, {q6}, d10       // byte swap Y and save to key->Y, to call _AccelerateCrypto_AES_encrypt to compute AES_Encrypt(key->Y);
    add         r1, r12, #48        // r1 -> key->KEY_PAD (AES_Encrypt_output);
    vtbl.8      d3, {q6}, d11
    mov         r2, ecb_key         // r2 -> expanded AES Key

    // update Y in the gcm ctx
    vstr        d2, [r12, #16] 
    vstr        d3, [r12, #24] 

#if defined(__ARM_ARCH_7EM__)
    bl  _AccelerateCrypto_AES_encrypt
#else
    blx _AccelerateCrypto_AES_encrypt
#endif

    subs        nsize, nsize, #16
    bne         0b // nsize is guaranteed to be a multiple of 16: loop until zero

#if CC_KERNEL
    vldmia  sp!, {q0-q3}
    vldmia  sp!, {q8-q10}
#endif
    vldmia  sp!, {q4-q7}

    pop     {r4-r6,r8-r11,pc}


#endif

#endif  // CCAES_ARM_ASM


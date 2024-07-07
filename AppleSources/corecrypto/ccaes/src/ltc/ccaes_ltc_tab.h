/* Copyright (c) (2017,2019,2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 *
 * Tom St Denis, tomstdenis@gmail.com, http://libtom.org
 */

/* The precomputed tables for AES */
/*
Te0[x] = S [x].[02, 01, 01, 03];
Te1[x] = S [x].[03, 02, 01, 01];
Te2[x] = S [x].[01, 03, 02, 01];
Te3[x] = S [x].[01, 01, 03, 02];
Te4[x] = S [x].[01, 01, 01, 01];

Td0[x] = Si[x].[0e, 09, 0d, 0b];
Td1[x] = Si[x].[0b, 0e, 09, 0d];
Td2[x] = Si[x].[0d, 0b, 0e, 09];
Td3[x] = Si[x].[09, 0d, 0b, 0e];
Td4[x] = Si[x].[01, 01, 01, 01];
*/

#ifndef _CORECRYPTO_CCAES_LTC_TAB_H_
#define _CORECRYPTO_CCAES_LTC_TAB_H_

#include <corecrypto/cc.h>

/*!
  @file aes_tab.c
  AES tables
*/
extern const uint32_t TE0[256];
extern const uint32_t Te4[256];

#ifndef ENCRYPT_ONLY
extern const uint32_t TD0[256];
extern const uint32_t Td4[256];
#endif /* ENCRYPT_ONLY */

#define Te0(x) TE0[x]
#define Te1(x) TE1[x]
#define Te2(x) TE2[x]
#define Te3(x) TE3[x]

#define Td0(x) TD0[x]
#define Td1(x) TD1[x]
#define Td2(x) TD2[x]
#define Td3(x) TD3[x]

extern const uint32_t TE1[256];
extern const uint32_t TE2[256];
extern const uint32_t TE3[256];
extern const uint32_t TE0[];
extern const uint32_t Te4_0[];
extern const uint32_t Te4_1[];
extern const uint32_t Te4_2[];
extern const uint32_t Te4_3[];

#ifndef ENCRYPT_ONLY
extern const uint32_t TD1[256];
extern const uint32_t TD2[256];
extern const uint32_t TD3[256];
extern const uint32_t Tks0[];
extern const uint32_t Tks1[];
extern const uint32_t Tks2[];
extern const uint32_t Tks3[];
#endif /* ENCRYPT_ONLY */

extern const uint32_t rcon[];

#endif // _CORECRYPTO_CCAES_LTC_TAB_H_

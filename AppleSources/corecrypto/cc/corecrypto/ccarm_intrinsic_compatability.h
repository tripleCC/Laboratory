/* Copyright (c) (2013,2015,2016,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */


#ifndef corecrypto_arm_aes_compatability_h
#define corecrypto_arm_aes_compatability_h

// #include <Availability.h>
#include <sys/cdefs.h>

#if defined(__clang__) && ((defined(__apple_build_version__) && __apple_build_version__ > 5010000))
#define __USES_V_CRYPTO_INTRINSICS 1
#else
#define __USES_V_CRYPTO_INTRINSICS 0
#endif


//  AES INSTRUCTIONS
// aese.16b	v0, v1
// aesd.16b	v0, v1
// aesmc.16b	v0, v1
// aesimc.16b	v0, v1

// SHA1 INTRINSICS
// sha1su0.4s	v0, v1, v2
// sha1su1.4s	v0, v1
// sha1c.4s	v0, v1, v2		// or q0, s1, v2.4s
// sha1m.4s	v0, v1, v2		// or q0, s1, v2.4s
// sha1p.4s	v0, v1, v2		// or q0, s1, v2.4s
// sha1h.4s	v0, v1		// or s0, s1

// SHA256 INTRINSICS
// sha256su0.4s	v0, v1
// sha256su1.4s	v0, v1, v2
// sha256h.4s		v0, v1, v2		// or q0, q1, v2.4s
// sha256h2.4s	v0, v1, v2		// or q0, q1, v2.4s


#if __USES_V_CRYPTO_INTRINSICS == 1
.macro	AESE
aese.16b v$0, v$1
.endm

.macro	AESD
aesd.16b v$0, v$1
.endm

.macro	AESMC
aesmc.16b v$0, v$1
.endm

.macro	AESIMC
aesimc.16b v$0, v$1
.endm


#else

.macro	AESE
aese q$0, q$1
.endm

.macro	AESD
aesd q$0, q$1
.endm

.macro	AESMC
aesmc q$0, q$1
.endm

.macro	AESIMC
aesimc q$0, q$1
.endm

#endif

#if __USES_V_CRYPTO_INTRINSICS == 1

.macro SHA1SU0
sha1su0	v$0.4s, v$1.4s, v$2.4s
.endm

.macro SHA1SU1
sha1su1	v$0.4s, v$1.4s
.endm

.macro SHA1C
sha1c	q$0, s$1, v$2.4s
.endm

.macro SHA1M
sha1m	q$0, s$1, v$2.4s
.endm

.macro SHA1P
sha1p	q$0, s$1, v$2.4s
.endm

.macro SHA1H
sha1h	s$0, s$1
.endm

.macro SHA256SU0
sha256su0    v$0.4s, v$1.4s
.endm

.macro SHA256SU1
sha256su1    v$0.4s, v$1.4s, v$2.4s
.endm

.macro SHA256H
sha256h    q$0, q$1, v$2.4s
.endm

.macro SHA256H2
sha256h2    q$0, q$1, v$2.4s
.endm

#else

.macro SHA1SU0
sha1su0	q$0, q$1, q$2
.endm

.macro SHA1SU1
sha1su1	q$0, q$1
.endm

.macro SHA1C
sha1c	q$0, q$1, q$2
.endm

.macro SHA1M
sha1m	q$0, q$1, q$2
.endm

.macro SHA1P
sha1p	q$0, q$1, q$2
.endm

.macro SHA1H
sha1h	q$0, q$1
.endm

.macro SHA256SU0
sha256su0    q$0, q$1
.endm

.macro SHA256SU1
sha256su1    q$0, q$1, q$2
.endm

.macro SHA256H
sha256h    q$0, q$1, q$2
.endm

.macro SHA256H2
sha256h2    q$0, q$1, q$2
.endm

#endif
#endif /*corecrypto_arm_aes_compatability_h*/





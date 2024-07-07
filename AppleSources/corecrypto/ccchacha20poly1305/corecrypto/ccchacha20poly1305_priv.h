/* Copyright (c) (2017-2019,2021,2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CCCHACHA20POLY1305_PRIV_H_
#define _CORECRYPTO_CCCHACHA20POLY1305_PRIV_H_

#include <corecrypto/ccchacha20poly1305.h>

CC_PTRCHECK_CAPABLE_HEADER()

/*!	@group		ccchacha20
	@abstract	Encrypts/decrypts N bytes of data with a 32-byte key and 12-byte nonce starting from a 4-byte counter.
	@discussion	See RFC 8439 <https://tools.ietf.org/html/rfc8439>
 */

int	ccchacha20_init(ccchacha20_ctx *ctx, const uint8_t *cc_counted_by(CCCHACHA20_KEY_NBYTES) key);
int	ccchacha20_reset(ccchacha20_ctx *ctx);
int ccchacha20_setnonce(ccchacha20_ctx *ctx, const uint8_t *cc_counted_by(CCCHACHA20_NONCE_NBYTES) nonce);
int ccchacha20_setcounter(ccchacha20_ctx *ctx, uint32_t counter);
int	ccchacha20_update(ccchacha20_ctx *ctx, size_t nbytes, const void *cc_sized_by(nbytes) in, void *cc_sized_by(nbytes) out);
int	ccchacha20_final(ccchacha20_ctx *ctx);
int ccchacha20(const uint8_t *key, const uint8_t *nonce, uint32_t counter, size_t nbytes, const void *cc_sized_by(nbytes) in, void *cc_sized_by(nbytes) out);

/*!	@group		poly1305
	@abstract	Generates a 16-byte Poly1305 Message Authentication Code from N bytes of data and a 32-byte key.
	@discussion	See RFC 8439 <https://tools.ietf.org/html/rfc8439>
 */

int	ccpoly1305_init(ccpoly1305_ctx *ctx, const uint8_t *cc_counted_by(CCPOLY1305_KEY_NBYTES) key);
int	ccpoly1305_update(ccpoly1305_ctx *ctx, size_t nbytes, const uint8_t *cc_counted_by(nbytes) data);
int	ccpoly1305_final(ccpoly1305_ctx *ctx, uint8_t *cc_counted_by(CCPOLY1305_TAG_NBYTES) tag);
int	ccpoly1305(const uint8_t *key, size_t nbytes, const uint8_t *cc_counted_by(nbytes) data, uint8_t *cc_counted_by(CCPOLY1305_TAG_NBYTES) tag);

#endif /* _CORECRYPTO_CCCHACHA20POLY1305_PRIV_H_ */

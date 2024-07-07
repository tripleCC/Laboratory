/* Copyright (c) (2010-2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CCRC4_H_
#define _CORECRYPTO_CCRC4_H_

#include <corecrypto/ccmode.h>

cc_aligned_struct(16) ccrc4_ctx;

struct ccrc4_info {
    size_t size;        /* first argument to ccrc4_ctx_decl(). */
    void (* CC_SPTR(ccrc4_info, init))(ccrc4_ctx *ctx, size_t key_len, const void *key);
    void (* CC_SPTR(ccrc4_info, crypt))(ccrc4_ctx *ctx, size_t nbytes, const void *in, void *out);
};

const struct ccrc4_info *ccrc4(void);

extern const struct ccrc4_info ccrc4_eay;

#endif /* _CORECRYPTO_CCRC4_H_ */

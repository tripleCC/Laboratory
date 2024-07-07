/* Copyright (c) (2010-2012,2015,2016,2019,2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CRYPTO_TEST_RC4_H_
#define _CORECRYPTO_CRYPTO_TEST_RC4_H_

#include <corecrypto/ccrc4.h>
#include "cc_internal.h"

#define ccrc4_ctx_decl(_size_, _name_) cc_ctx_decl(ccrc4_ctx, _size_, _name_)
#define ccrc4_ctx_clear(_size_, _name_) cc_clear(_size_, _name_)

#endif /* _CORECRYPTO_CRYPTO_TEST_RC4_H_ */

/* Copyright (c) (2014,2015,2019,2020) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef corecrypto_ccsymmetric_pad_h
#define corecrypto_ccsymmetric_pad_h

#include "ccsymmetric.h"
#include <corecrypto/ccpad.h>


// Padding format
enum {
    ccpad_cts1          = 0,
    ccpad_cts2          = 1,
    ccpad_cts3          = 2,
    ccpad_pkcs7         = 3,
    ccpad_xts           = 4,
    ccpad_cnt           = 5
};
typedef uint32_t ccpad_select;

typedef size_t (*ecb_pad_crypt_f)(const struct ccmode_ecb *ecb, ccecb_ctx *ecb_key,
                                  size_t nbytes, const void *in, void *out);

typedef size_t (*cbc_pad_crypt_f)(const struct ccmode_cbc *cbc, cccbc_ctx *cbc_key,
                                  cccbc_iv *iv, size_t nbytes, const void *in, void *out);

extern cbc_pad_crypt_f cbc_pad_crypt_funcs[ccpad_cnt][cc_NDirections];
extern ecb_pad_crypt_f ecb_pad_crypt_funcs[ccpad_cnt][cc_NDirections];

size_t
cc_symmetric_crypt_pad(cc_symmetric_context_p ctx, ccpad_select pad, const void *iv, const void *in, void *out, size_t len);


#endif

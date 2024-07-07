/* Copyright (c) (2012,2014-2016,2018-2020) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef corecrypto_ccsymmetric_h
#define corecrypto_ccsymmetric_h

#include <corecrypto/ccmode.h>
#include <corecrypto/ccmode_impl.h>
#include <corecrypto/ccaes.h>
#include <corecrypto/ccdes.h>
#include <corecrypto/cccast.h>
#include <corecrypto/ccrc2.h>
#include <corecrypto/ccblowfish.h>


#define CC_SUCCESS 0
#define CC_FAILURE -1
#define CC_UNIMPLEMENTED -2
typedef int cc_status;

// Ciphers
enum {
    cc_cipherAES        = 0,
    cc_cipherDES        = 1,
    cc_cipher3DES       = 2,
    cc_cipherCAST       = 3,
    cc_cipherRC2        = 4,
    cc_cipherBlowfish   = 5,
    cc_NCiphers         = 6,
};
typedef uint32_t cc_cipher_select;

enum {
  cc_digestSHA256       = 0,
  cc_NDigest            = 1,
};
typedef uint32_t cc_digest_select;

// Modes
enum {
	cc_ModeECB		= 0,
	cc_ModeCBC		= 1,
	cc_ModeCFB		= 2,
	cc_ModeCTR		= 3,
	cc_ModeOFB		= 4,
	cc_ModeXTS		= 5,
	cc_ModeCFB8		= 6,
	cc_ModeGCM		= 7,
    cc_ModeCCM		= 8,
    cc_ModeSIV		= 9,
    cc_ModeSIV_HMAC = 10,
    cc_NModes       = 11,
};
typedef uint32_t cc_mode_select;

// Directions
enum {
	cc_Encrypt		= 0,
	cc_Decrypt		= 1,
    cc_NDirections = 2,
};
typedef uint32_t cc_direction;

typedef union  {
    const void *data;
    const struct ccmode_ecb *ecb;
    const struct ccmode_cbc *cbc;
    const struct ccmode_cfb *cfb;
    const struct ccmode_cfb8 *cfb8;
    const struct ccmode_ctr *ctr;
    const struct ccmode_ofb *ofb;
    const struct ccmode_xts *xts;
    const struct ccmode_gcm *gcm;
    const struct ccmode_ccm *ccm;
    const struct ccmode_siv *siv;
    const struct ccmode_siv_hmac *siv_hmac;
} ciphermode_t;

typedef struct cc_ciphermode_descriptor_t {
    cc_cipher_select cipher;
    cc_mode_select mode;
    cc_direction direction;
    ciphermode_t ciphermode;
} cc_ciphermode_descriptor_s, *cc_ciphermode_descriptor;

cc_aligned_struct(16) cc_aligned_ctx;

typedef union {
    cc_aligned_ctx *data;
    ccecb_ctx *ecb;
    cccbc_ctx *cbc;
    cccfb_ctx *cfb;
    cccfb8_ctx *cfb8;
    ccctr_ctx *ctr;
    ccofb_ctx *ofb;
    ccxts_ctx *xts;
    ccgcm_ctx *gcm;
    ccccm_ctx *ccm;
    ccsiv_ctx *siv;
    ccsiv_hmac_ctx *siv_hmac;
} mode_ctx;

typedef union {
    cc_aligned_ctx *data;
    ccccm_nonce *ccm_nonce;
} extra_ctx;

typedef struct cc_symmetric_context_t {
    cc_ciphermode_descriptor mode_desc;
    mode_ctx  ctx;
    extra_ctx xtra_ctx;
} cc_symmetric_context, *cc_symmetric_context_p;

int
cc_get_ciphermode(cc_cipher_select cipher, cc_mode_select mode, cc_direction direction, cc_ciphermode_descriptor desc);

int
cc_get_C_ciphermode(cc_cipher_select cipher, cc_mode_select mode, cc_direction direction, cc_ciphermode_descriptor desc);

int
cc_symmetric_setup(cc_ciphermode_descriptor cm, const void *key, size_t keylen, const void *iv, cc_symmetric_context_p ctx);

int
cc_symmetric_setup_tweaked(cc_ciphermode_descriptor cm, const void *key, size_t keylen, const void *tweak, const void *iv, cc_symmetric_context_p ctx);

int
cc_symmetric_setup_authenticated(cc_ciphermode_descriptor cm, const void *key, size_t keylen,
                                 const void *iv, size_t iv_len,
                                 const void *adata,  size_t adata_len,
                                 const void *adata2, size_t adata2_len,
                                 size_t data_len,
                                 size_t tag_len,
                                 cc_symmetric_context_p ctx);

int
cc_symmetric_crypt(cc_symmetric_context_p ctx, const void *iv, const void *in, void *out, size_t len);

void
cc_symmetric_final(cc_symmetric_context_p ctx);

int
cc_symmetric_authenticated_finalize(cc_symmetric_context_p ctx, char *tag, size_t tag_len);

int
cc_symmetric_reset(cc_symmetric_context_p ctx);

int
cc_symmetric_oneshot(cc_ciphermode_descriptor cm, const void *key, size_t keylen,
                     const void *iv, const void *in, void *out, size_t len);

static inline size_t get_context_size_in_bytes(cc_ciphermode_descriptor cm) {
    return (cm->ciphermode.ecb->size);
                                    // This assumes the compiler always puts the size field first
                                    // if not we're going to have to build a switch statement and
                                    // go through all the modes.
}

static inline size_t get_extra_context_size_in_bytes(cc_ciphermode_descriptor cm) {
    // Allocate an extra context (ex: nonce in CCM)
    if (cm->mode==cc_ModeCCM) {
        return cm->ciphermode.ccm->nonce_size;
    }
    return 1; // To prevent warning about declaring a zero length variable
}

// Generic mode context (cc_symmetric_ctx) aligned on 16bytes.
#define MAKE_GENERIC_MODE_CONTEXT(_name_,_descriptor_) \
    cc_ctx_decl(cc_aligned_ctx, get_context_size_in_bytes(_descriptor_), __ctx_##_name_); \
    cc_ctx_decl(cc_aligned_ctx, get_extra_context_size_in_bytes(_descriptor_), __extra_ctx_##_name_);\
    cc_symmetric_context __##_name_={_descriptor_,{__ctx_##_name_},{__extra_ctx_##_name_}}; \
    cc_symmetric_context_p _name_=&__##_name_;

size_t
cc_symmetric_bloc_size(cc_ciphermode_descriptor cm);

#endif /* corecrypto_ccsymmetric_h */

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

#ifndef _CORECRYPTO_CCLR_H_
#define _CORECRYPTO_CCLR_H_

#include <corecrypto/cc.h>
#include <corecrypto/ccaes.h>
#include <corecrypto/ccmode.h>

CC_PTRCHECK_CAPABLE_HEADER()

#define CCLR_DEFAULT_NROUNDS (10)

typedef struct cclr_info cclr_info_t;

typedef struct cclr_ctx {
    // The descriptor for the LR implementation. Typically, this will
    // be set by some higher-level initialization function,
    // e.g. cclr_aes_init.
    const cclr_info_t *info;

    // The width of the LR cipher in bits. In the current
    // implementation, only byte-aligned blocks are supported;
    // i.e. the count of bits must be divisible by eight.
    size_t block_nbits;

    // The count of encryption rounds performed by the LR cipher. This
    // is a security parameter for the LR cipher. Use
    // CCLR_DEFAULT_NROUNDS for a conservative value.
    size_t nrounds;
} cclr_ctx_t;

/*!
  @function cclr_block_nbytes
  @abstract Return the count of bytes in an LR block.

  @param ctx The LR context.

  @discussion Luby-Rackoff can encrypt blocks of arbitrary
  bit-widths. This function converts the bit-width of the block to a
  size in bytes.
*/
size_t cclr_block_nbytes(const cclr_ctx_t *ctx);

/*!
  @function cclr_encrypt_block
  @abstract Encrypt a block using the LR context.

  @param ctx The LR context.
  @param block_nbytes The size in bytes of the input and output blocks.
  @param ctext_block The output ciphertext block.
  @param ptext_block The input plaintext block.

  @return 0 if successful, negative otherwise.
*/
int cclr_encrypt_block(const cclr_ctx_t *ctx,
                       size_t block_nbytes,
                       void *ctext_block cc_sized_by(block_nbytes),
                       const void *ptext_block cc_sized_by(block_nbytes));

/*!
  @function cclr_decrypt_block
  @abstract Decrypt a block using the LR context.

  @param ctx The LR context.
  @param block_nbytes The size in bytes of the input and output blocks.
  @param ptext_block The output plaintext block.
  @param ctext_block The input ciphertext block.

  @return 0 if successful, negative otherwise.
*/
int cclr_decrypt_block(const cclr_ctx_t *ctx,
                       size_t block_nbytes,
                       void *ptext_block cc_sized_by(block_nbytes),
                       const void *ctext_block cc_sized_by(block_nbytes));

typedef struct cclr_aes_ctx {
    // The parent LR context.
    cclr_ctx_t lr_ctx;

    // The AES-ECB mode descriptor.
    const struct ccmode_ecb *aes_info;

    // The AES-ECB cipher context.
    ccecb_ctx *aes_ctx;
} cclr_aes_ctx_t;

/*!
  @function cclr_aes_init
  @abstract Initialize the LR context with an AES cipher.

  @param ctx The LR context.
  @param aes_info The AES-ECB mode descriptor.
  @param aes_ctx The AES-ECB cipher context.
  @param block_nbits The size of the LR block in bits.
  @param nrounds The count of encryption rounds in the LR cipher.

  @return 0 if successful, negative otherwise.

  @discussion Memory management and initialization of the AES cipher
  context are the responsibility of the caller. Note that the block
  width is specified in bits; at present, only byte-aligned widths are
  supported. The count of encryption rounds is a security parameter to
  this function; we recommend CCLR_DEFAULT_NROUNDS as a conservative
  value.
*/
int cclr_aes_init(cclr_aes_ctx_t *ctx,
                  const struct ccmode_ecb *aes_info,
                  ccecb_ctx *aes_ctx,
                  size_t block_nbits,
                  size_t nrounds);

#endif // _CORECRYPTO_CCLR_H_

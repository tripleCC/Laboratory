/* Copyright (c) (2012,2014,2015,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef corecrypto_ccpad_cts_helper_h
#define corecrypto_ccpad_cts_helper_h

CC_INLINE void
swapblocks(uint8_t *blocks, size_t blocksize)
{
	uint8_t tmp;
    uint8_t *block1 = blocks, *block2 = blocks+blocksize;
    size_t i;
    
    for (i=0; i<blocksize; i++) {
    	tmp = block1[i];
        block1[i] = block2[i];
        block2[i] = tmp;
    }
}

CC_INLINE void
ecb_from_cbc(const struct ccmode_cbc *cbc, cccbc_ctx *cbc_key, uint8_t *in, uint8_t *out)
{
    size_t blocksize = cbc->block_size;
    cccbc_iv_decl(blocksize, iv);
    cccbc_set_iv(cbc, iv, NULL);
    cccbc_update(cbc, cbc_key, iv, 1, in, out);
    cccbc_iv_clear(blocksize, iv);
}

// Encrypt / Decrypt all but the last two blocks
CC_INLINE void ccpad_cts_crypt(const struct ccmode_cbc *cbc, cccbc_ctx *cbc_key, cccbc_iv *iv,
                        size_t *nbytes, const uint8_t **in, uint8_t **out) {
    const size_t block_size = cbc->block_size;
    size_t head_blocks = ((((*nbytes-1) / block_size) > 1) ? ((*nbytes-1) / block_size) - 1:0);
    size_t head_bytes = (head_blocks * block_size);
    size_t tail_bytes  =  *nbytes;

    if (head_blocks) {
        cbc->cbc(cbc_key, iv, head_blocks, *in, *out);
        tail_bytes  =  *nbytes - head_bytes;
        *in += head_bytes;
        *out += head_bytes;
    }
    *nbytes=tail_bytes;
}
#endif

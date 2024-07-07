/* Copyright (c) (2018,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef ccscrypt_internal_h
#define ccscrypt_internal_h

/*! @function ccscrypt_valid_parameters
 @abstract Determine if scrypt parameters (N, r, p) are valid.

 @param N  CPU/memory cost parameter
 @param r  Scrypt block size parameter
 @param p  Parallelization parameter

 @return 0 if valid, and a negative error code otherwise.
 */
int ccscrypt_valid_parameters(uint64_t N, uint32_t r, uint32_t p);

/*! @function ccscrypt_salsa20_8
 @abstract Run the Salsa20/8 core with a fixed-length (64B) input and output.

 @param in_buffer   Input buffer
 @param out_buffer  Output buffer
 */
void ccscrypt_salsa20_8(uint8_t *in_buffer, uint8_t *out_buffer);

/*! @function ccscrypt_blockmix_salsa8
 @abstract Run the scryptBlockMix core with input block B, temporary storage Y, and value r

 @param B  Input blocks
 @param Y  Temporary storage
 @param r  Block size parameter
 */
void ccscrypt_blockmix_salsa8(uint8_t *B, uint8_t *Y, size_t r);

/*! @function ccscrypt_romix
 @abstract Run the scryptROMix core.

 @param r  		Block size parameter
 @param B  		Input blocks
 @param N  		CPU/memory cost parameter
 @param T  		Temporary storage
 @param X  		Temporary storage
 @param Y  		Temporary storage
 */
void ccscrypt_romix(size_t r, uint8_t *B, size_t N, uint8_t *T, uint8_t *X, uint8_t *Y);

#endif /* ccscrypt_internal_h */

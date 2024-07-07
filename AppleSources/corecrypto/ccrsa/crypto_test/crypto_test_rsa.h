/* Copyright (c) (2012,2015,2016,2019,2020) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _crypto_test_rsa_
#define _crypto_test_rsa_

#define PADDING_PKCS1        0
#define PADDING_PKCS1_NO_OID 1
#define PADDING_OAEP         2
#define PADDING_PSS          3

#define TEST_KEY_SANITY          1
#define TEST_ALL_ALGOS           0

/*!
@function   ccrsa_privkeylength
@abstract   Compute the actual bit length of the RSA key (bit length of the modulus)
@param      fk  An initialized RSA full key
@result     bit length of the RSA key
*/
CC_INLINE size_t ccrsa_privkeylength(ccrsa_full_ctx_t fk)
{
    return cczp_bitlen(ccrsa_ctx_private_zp(fk)) +
           cczp_bitlen(ccrsa_ctx_private_zq(fk));
}

CC_INLINE size_t ccrsa_priv_n(ccrsa_full_ctx_t fk)
{
    return ccn_nof(ccrsa_privkeylength(fk));
}

#endif /* _crypto_test_rsa_ */

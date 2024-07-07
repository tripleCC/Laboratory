/* Copyright (c) (2016,2019,2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */


#ifndef _CORECRYPTO_CC_UNIT_INTERNAL_H
#define _CORECRYPTO_CC_UNIT_INTERNAL_H

#include <corecrypto/ccn.h>

// These are corecrypto constant-time primitive operations,
// and are meant to be used inside corecrypto.
//
// all ccop_*() functions return 0 or ~0 i.e. 0xFFFFFF....

//returns the most significant bit in the form of 0 or ~0

/*!
 @function cc_unit_msb(a)
 @param a The operand
 @return 0xFFF...F if most significant bit of a is 1 and 0 otherwise.
 @brief Constant time computation of a's most signficiant bit, assuming x >> b is implemented in constant time.
  */
CC_INLINE cc_unit cc_unit_msb(cc_unit a){
    return (cc_unit)((cc_int)a >> (CCN_UNIT_BITS-1));
}

/*!
 @function cc_unit_is_zero(a)
 @param a The operand
 @return 0xFFF...F if a==0 and 0 otherwise.
 @brief Constant time check if a is equal to 0.
 */
CC_INLINE cc_unit cc_unit_is_zero(cc_unit a){
    return cc_unit_msb(~a & (a - 1));
}

/*!
 @function cc_unit_eq(a, b)
 @param a The left operand
 @param b The right operand
 @return 0xFFF...F if a==b and 0 otherwise.
 @brief Constant time check if a is equal to b.
 */
CC_INLINE cc_unit cc_unit_eq(cc_unit a, cc_unit b){
    return cc_unit_is_zero(a^b);
}

/*!
 @function cc_unit_neq(a, b)
 @param a The left operand
 @param b The right operand
 @return 0xFFF...F if a!=b and 0 otherwise.
 @brief Constant time check if a is not equal to b.
 */
CC_INLINE cc_unit cc_unit_neq(cc_unit a, cc_unit b){
    return ~cc_unit_eq(a, b);
}

/*!
 @function cc_unit_lt(a, b)
 @param a The left operand
 @param b The right operand
 @return 0xFFF...F if a < b and 0 otherwise.
 @brief Constant time check if a is less than b.
 */
CC_INLINE cc_unit cc_unit_lt(cc_unit a, cc_unit b){
    return cc_unit_msb(a^ ((a^b) | ((a-b)^a)) );
}

/*!
 @function cc_unit_gt(a, b)
 @param a The left operand
 @param b The right operand
 @return 0xFFF...F if a>b and 0 otherwise.
 @brief Constant time check if a is greater than b.
 */
CC_INLINE cc_unit cc_unit_gt(cc_unit a, cc_unit b){
    return cc_unit_lt(b, a);
}

/*!
 @function cc_unit_lte(a, b)
 @param a The left operand
 @param b The right operand
 @return 0xFFF...F if a<=b and 0 otherwise.
 @brief Constant time check if a is less than or equal to b.
 */
CC_INLINE cc_unit cc_unit_lte(cc_unit a, cc_unit b){
    return (~cc_unit_gt(a, b));
}

/*!
 @function cc_unit_gte(a, b)
 @param a The left operand
 @param b The right operand
 @return 0xFFF...F if a>=b and 0 otherwise.
 @brief Constant time check if a is greater than or equal to b.
 */
CC_INLINE cc_unit cc_unit_gte(cc_unit a, cc_unit b){
    return (~cc_unit_lt(a, b));
}

/*!
 @function cc_unit_sel(sel, a, b)
 @param sel The selector; must be either 0xFF..FF or 0x00..00
 @param a The left operand
 @param b The right operand
 @return  sel ? a : b;
 @brief Constant time implementation of sel ? a : b, assuming sel is 0x00..00 or 0xFF..FF
 */
//The sel input must be either the output of a ccop_*() function or 0/~0
CC_INLINE cc_unit cc_unit_sel(cc_unit sel, cc_unit a, cc_unit b){
    return (~sel & b) | (sel & a);
}

#endif /* _CORECRYPTO_CC_UNIT_INTERNAL_H */

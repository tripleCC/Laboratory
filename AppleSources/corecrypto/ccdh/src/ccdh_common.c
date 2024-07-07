/* Copyright (c) (2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/ccdh.h>

ccdh_pub_ctx_t ccdh_ctx_public(ccdh_full_ctx_t key) {
    return (ccdh_pub_ctx_t)key;
}

void ccdh_ctx_init(ccdh_const_gp_t gp, ccdh_pub_ctx_t key) {
    key->gp = gp;
}

cc_size ccdh_gp_n(ccdh_const_gp_t gp) {
    return cczp_n((cczp_const_t)gp);
}

size_t ccdh_ccn_size(ccdh_const_gp_t gp) {
    return ccn_sizeof_n(CCZP_N(gp));
}

size_t ccdh_export_pub_size(ccdh_pub_ctx_t key) {
    return ccdh_gp_prime_size(ccdh_ctx_gp(key));
}

#if !CC_PTRCHECK

const cc_unit *cc_indexable ccdh_gp_prime(ccdh_const_gp_t gp) {
    return cczp_prime((cczp_const_t)gp);
}

const cc_unit *cc_indexable ccdh_gp_g(ccdh_const_gp_t gp) {
    return CCDH_GP_G(gp);
}

const cc_unit *cc_indexable ccdh_gp_order(ccdh_const_gp_t gp) {
    return CCDH_GP_Q(gp);
}

size_t ccdh_gp_l(ccdh_const_gp_t gp) {
    return (size_t)CCDH_GP_L(gp);
}

size_t ccdh_gp_order_bitlen(ccdh_const_gp_t gp) {
    cc_size gp_n = ccdh_gp_n(gp);
    return ccn_bitlen(gp_n,ccdh_gp_order(gp));
}

#endif // CC_PTRCHECK

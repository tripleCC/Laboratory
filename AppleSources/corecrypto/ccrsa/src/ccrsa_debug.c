/* Copyright (c) (2015,2016,2018-2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "cc_internal.h"
#include "ccrsa_internal.h"
#include <corecrypto/ccrsa_priv.h>
#include "cc_debug.h"

void ccrsa_dump_public_key(ccrsa_pub_ctx_t key) {
    CC_ENSURE_DIT_ENABLED

    cc_size nbits = ccrsa_pubkeylength(key);
    cc_printf("%lu bit rsa key\n", nbits);
    ccn_lprint(ccrsa_ctx_n(key),      "m  = 0x", ccrsa_ctx_m(key));
    ccn_lprint(ccrsa_ctx_n(key),      "e  = 0x", ccrsa_ctx_e(key));
}

void ccrsa_dump_full_key(ccrsa_full_ctx_t fk) {
    CC_ENSURE_DIT_ENABLED

    ccrsa_pub_ctx_t key = ccrsa_ctx_public(fk);

    cc_size nbits = ccrsa_pubkeylength(key);
    cc_printf("%lu bit rsa key\n", nbits);
    ccn_lprint(ccrsa_ctx_n(key),      "m  = 0x", ccrsa_ctx_m(key));
    ccn_lprint(ccrsa_ctx_n(key),      "e  = 0x", ccrsa_ctx_e(key));
    ccn_lprint(ccrsa_ctx_n(key),      "d  = 0x", ccrsa_ctx_d(key));
    ccn_lprint(cczp_n(ccrsa_ctx_private_zp(fk)),     "p  = 0x",
               cczp_prime(ccrsa_ctx_private_zp(fk)));
    ccn_lprint(cczp_n(ccrsa_ctx_private_zq(fk)),     "q  = 0x",
               cczp_prime(ccrsa_ctx_private_zq(fk)));
    ccn_lprint(cczp_n(ccrsa_ctx_private_zp(fk)),     "dp = 0x",
               ccrsa_ctx_private_dp(fk));
    ccn_lprint(cczp_n(ccrsa_ctx_private_zq(fk)),     "dq = 0x",
               ccrsa_ctx_private_dq(fk));
    ccn_lprint(cczp_n(ccrsa_ctx_private_zp(fk)),     "qinv=0x",
               ccrsa_ctx_private_qinv(fk));
    cc_printf("\n");
    //cc_printf("(p*q)-m\n");
    //cc_printf("d.modulo(p-1)-dp\n");
    //cc_printf("d.modulo(q-1)-dq\n");
    //cc_printf("(q*qinv).modulo(p)\n");
    //cc_printf("(p-1)*(q-1)-phi\n");
    //cc_printf("(d*e).modulo((p-1)*(q-1))\n");
}

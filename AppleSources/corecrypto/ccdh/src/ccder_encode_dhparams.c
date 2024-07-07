/* Copyright (c) (2013,2015,2019,2021,2022) Apple Inc. All rights reserved.
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
#include <corecrypto/ccdh.h>
#include <corecrypto/ccder.h>

size_t
ccder_encode_dhparams_size(const ccdh_const_gp_t gp)
{
    cc_size n = ccdh_gp_n(gp);
    uint64_t l = ccdh_gp_l(gp);
    return ccder_sizeof(CCDER_CONSTRUCTED_SEQUENCE,
                        ccder_sizeof_integer(n, ccdh_gp_prime(gp)) +
                        ccder_sizeof_integer(n, ccdh_gp_g(gp)) +
                        (l ? ccder_sizeof_uint64(l) : 0)
                        );
}

uint8_t *
ccder_encode_dhparams(const ccdh_const_gp_t gp, uint8_t *der, uint8_t *der_end)
{
    cc_size n = ccdh_gp_n(gp);

    return ccder_encode_constructed_tl(CCDER_CONSTRUCTED_SEQUENCE, der_end, der,
                                       ccder_encode_integer(n, ccdh_gp_prime(gp), der,
                                       ccder_encode_integer(n, ccdh_gp_g(gp), der,
                                       ccdh_gp_l(gp) == 0 ? der_end : ccder_encode_uint64(ccdh_gp_l(gp), der, der_end))));
}

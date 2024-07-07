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

#ifndef corecrypto_ccsrp_gp_h
#define corecrypto_ccsrp_gp_h

#include <corecrypto/ccdh.h>

ccdh_const_gp_t ccsrp_gp_rfc5054_1024(void);
ccdh_const_gp_t ccsrp_gp_rfc5054_2048(void);
ccdh_const_gp_t ccsrp_gp_rfc5054_3072(void);
ccdh_const_gp_t ccsrp_gp_rfc5054_4096(void);
ccdh_const_gp_t ccsrp_gp_rfc5054_8192(void);

#endif

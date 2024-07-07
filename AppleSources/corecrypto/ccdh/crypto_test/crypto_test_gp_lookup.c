/* Copyright (c) (2018-2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */
#include <corecrypto/cc.h>
#include <corecrypto/ccdh_gp.h>

#include "ccdh_internal.h"
#include "crypto_test_dh.h"
#include "../test_vectors/lookup_groups_test_vectors.h"
#include "testmore.h"

#define MAX_PRIME_N ccn_nof(8192)
static ccdh_const_gp_t ccdh_lookup_gp_bytes(size_t len_p, const uint8_t *p, size_t len_g, const uint8_t *g)
{
    cc_unit tmp_p[MAX_PRIME_N], tmp_g[MAX_PRIME_N];

    if (ccn_read_uint(MAX_PRIME_N, tmp_p, len_p, p)) {
        return NULL;
    }
    if (ccn_read_uint(MAX_PRIME_N, tmp_g, len_g, g)) {
        return NULL;
    }

    cc_size n = ccn_n(MAX_PRIME_N, tmp_p);
    return ccdh_lookup_gp(n, tmp_p, n, tmp_g);
}

// Macro to perform a lookup of a group.
// Each group that is tested against for lookup is a uniquely defined struct, so a macro makes this code easier to read, and maintain.
// Macro takes the variable name of the struct, and produces a standard group with a generator and prime.
#define GET_BIG_ENDIAN_GROUP(NAME)                    \
    ccdh_const_gp_t NAME##DHG = ccdh_lookup_gp_bytes( \
        CC_ARRAY_LEN(NAME.p), NAME.p, CC_ARRAY_LEN(NAME.g), NAME.g);

void ccdh_test_gp_lookup(CC_UNUSED ccdh_const_gp_t input_gp)
{
    // Create all the big endian numbers corresponding to test groups.
    GET_BIG_ENDIAN_GROUP(apple768)
    GET_BIG_ENDIAN_GROUP(rfc3526group05)
    GET_BIG_ENDIAN_GROUP(rfc3526group14)
    GET_BIG_ENDIAN_GROUP(rfc3526group15)
    GET_BIG_ENDIAN_GROUP(rfc3526group16)
    GET_BIG_ENDIAN_GROUP(rfc3526group17)
    GET_BIG_ENDIAN_GROUP(rfc3526group18)
    GET_BIG_ENDIAN_GROUP(rfc2409group02)
    GET_BIG_ENDIAN_GROUP(rfc5114_MODP_1024_160)
    GET_BIG_ENDIAN_GROUP(rfc5114_MODP_2048_224)
    GET_BIG_ENDIAN_GROUP(rfc5114_MODP_2048_256)
    GET_BIG_ENDIAN_GROUP(rfc5054_1024)
    GET_BIG_ENDIAN_GROUP(rfc5054_2048)
    GET_BIG_ENDIAN_GROUP(rfc5054_3072)
    GET_BIG_ENDIAN_GROUP(rfc5054_4096)
    GET_BIG_ENDIAN_GROUP(rfc5054_8192)
    
    // Create all the big endian numbers correspodning to test groups which should not be recognized.
    GET_BIG_ENDIAN_GROUP(EmptyGroup)
    GET_BIG_ENDIAN_GROUP(BogusPrime)
    GET_BIG_ENDIAN_GROUP(BogusGenerator)
    GET_BIG_ENDIAN_GROUP(TooBigGroup)
    
    // Leading Zeros tests groups check to ensure leading zeros are treated properly
    GET_BIG_ENDIAN_GROUP(LeadingZerosGeneratorApple768)
    GET_BIG_ENDIAN_GROUP(LeadingZerosPrimeApple768)
    GET_BIG_ENDIAN_GROUP(rfc5054_8192_Zeros)
    
    // Here we will check to see if all of the proper groups are accepted.
    ok(rfc5054_8192_ZerosDHG == ccsrp_gp_rfc5054_8192(), "Failed to lookup ccrsp 5054 8192 group parameters when extra zeros are present");
    ok(apple768DHG == ccdh_gp_apple768(), "Failed to lookup Apple768 group parameters");
    ok(rfc3526group05DHG == ccdh_gp_rfc3526group05(), "Failed to lookup group rfc3526 g5 group parameters");
    ok(rfc3526group14DHG == ccdh_gp_rfc3526group14(), "Failed to lookup group rfc3526 g14 group parameters");
    ok(rfc3526group15DHG == ccdh_gp_rfc3526group15(), "Failed to lookup group rfc3526 g15 group parameters");
    ok(rfc3526group16DHG == ccdh_gp_rfc3526group16(), "Failed to lookup group rfc3526 g16 group parameters");
    ok(rfc3526group17DHG == ccdh_gp_rfc3526group17(), "Failed to lookup group rfc3526 g17 group parameters");
    ok(rfc3526group18DHG == ccdh_gp_rfc3526group18(), "Failed to lookup group rfc3526 g17 group parameters");
    ok(rfc2409group02DHG == ccdh_gp_rfc2409group02(), "Failed to lookup group rfc2409 g02 group parameters");
    ok(rfc5114_MODP_1024_160DHG == ccdh_gp_rfc5114_MODP_1024_160(), "Failed to lookup group rfc5114 1024 160 group parameters");
    ok(rfc5114_MODP_2048_224DHG == ccdh_gp_rfc5114_MODP_2048_224(), "Failed to lookup group rfc5114 1024 160 group parameters");
    ok(rfc5114_MODP_2048_256DHG == ccdh_gp_rfc5114_MODP_2048_256(), "Failed to lookup group rfc5114 1024 160 group parameters");
    ok(rfc5054_1024DHG == ccsrp_gp_rfc5054_1024(), "Failed to lookup group rfc5054 1024 group parameters");
    ok(rfc5054_2048DHG == ccsrp_gp_rfc5054_2048(), "Failed to lookup group rfc5054 2048 group parameters");
    ok(rfc5054_3072DHG == ccsrp_gp_rfc5054_3072(), "Failed to lookup group rfc5054 1024 group parameters");
    ok(rfc5054_4096DHG == ccsrp_gp_rfc5054_4096(), "Failed to lookup group rfc5054 4096 group parameters");
    ok(rfc5054_8192DHG == ccsrp_gp_rfc5054_8192(), "Failed to lookup group rfc5054 8192 group parameters");
    
    // Following groups should all have returned Null because the groups are incorrect
    ok(EmptyGroupDHG == NULL, "Found the Empty Group, which should fail to NULL");
    ok(BogusPrimeDHG == NULL, "Found the Bogus Prime Group, which should fail to NULL");
    ok(BogusGeneratorDHG == NULL, "Found the Bogus Generator Group, which should fail to NULL");
    ok(TooBigGroupDHG == NULL, "Found the Too Big Group, which should fail to NULL");
    
    // Following groups all have leading zeros in front of numbers and should return apple768
    ok(LeadingZerosPrimeApple768DHG == ccdh_gp_apple768(), "Failed to lookup Apple768 group parameters");
    ok(LeadingZerosGeneratorApple768DHG == ccdh_gp_apple768(), "Failed to lookup Apple768 group parameters");
}

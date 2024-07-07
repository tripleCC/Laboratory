/* Copyright (c) (2016,2017,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "testmore.h"
#include "testbyteBuffer.h"
#include "ccdrbg_test.h"

#if (CCDRBG == 0)
entryPoint(ccdrbg_tests,"ccdrbg")
#else

int ccdrbg_tests(TM_UNUSED int argc, TM_UNUSED char *const *argv)
{
    int status=0;
    const int verbose=1;
    plan_tests(1404);

    if(verbose) diag("DRBG CTR NIST tests");
    ccdrbg_tests_ctr();

    if(verbose) diag("DRBG HMAC NIST tests");
    ccdrbg_tests_hmac();

    if(verbose) diag("DRBG tests to the limits");
    ccdrbg_limits_test();

    return status;
}

#endif // (CCDRBG == 0)

/* Copyright (c) (2012,2015,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

/* This file contains all the prototypes for all the test functions */
#ifndef __TESTLIST_H__
#define __TESTLIST_H__


#define ONE_TEST(x) int x##_tests(int argc, char *const *argv);
#define DISABLED_ONE_TEST(x) ONE_TEST(x)
#include "testlistInc.h"
#undef ONE_TEST
#undef DISABLED_ONE_TEST


#endif /* __TESTLIST_H__ */


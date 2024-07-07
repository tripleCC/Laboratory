/* Copyright (c) (2012,2014-2017,2019,2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <stdio.h>
#include <corecrypto/cc_config.h>
#include "testenv.h"
#include <stdio.h>

int main (int argc, char * const *argv) {
    int rc = tests_begin(argc, argv);
	return rc != 0;
}

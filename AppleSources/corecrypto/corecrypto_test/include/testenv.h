/* Copyright (c) (2010-2012,2015,2019,2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _TESTENV_H_
#define _TESTENV_H_  1

#ifdef __cplusplus
extern "C" {
#endif

int tests_begin(int argc, char * const *argv);
void tests_print_impls(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* !_TESTENV_H_ */

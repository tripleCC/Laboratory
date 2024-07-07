/* Copyright (c) (2016,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _HEXTOSTRING_H_
#define _HEXTOSTRING_H_

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#include <stdint.h>
#include <sys/types.h>

void printBytes(const uint8_t *buf, size_t len, const char *name, int spaced);
char nibbleToChar(uint8_t nibble);
uint8_t nibbleFromChar(char c);
size_t hexToString(char *result, size_t resultLen, const uint8_t *buf, size_t len, size_t breakOn);

#ifdef __cplusplus
}
#endif // __cplusplus
#endif

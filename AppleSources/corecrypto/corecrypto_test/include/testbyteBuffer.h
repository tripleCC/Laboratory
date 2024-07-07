/* Copyright (c) (2012,2014-2016,2018,2019,2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#ifndef _BYTEBUFFER_H_
#define _BYTEBUFFER_H_

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

typedef struct byte_buf {
    size_t  len;
    uint8_t *bytes;
} byteBufferStruct, *byteBuffer;

void printByteBuffer(byteBuffer bb, char *name);

void printByteBufferAsCharAssignment(byteBuffer bb, char *varname);

byteBuffer mallocByteBuffer(size_t len);

byteBuffer hexStringToBytes(const char *inhex);

byteBuffer hexStringToBytesWithSpaces(char *inhex, int breaks);

char *bytesToHexStringWithSpaces(byteBuffer bb, size_t breaks);

byteBuffer bytesToBytes(const void *bytes, size_t len);

int bytesAreEqual(byteBuffer b1, byteBuffer b2);

char *bytesToHexString(byteBuffer bytes);

#ifdef __cplusplus
}
#endif // __cplusplus
#endif /* _BYTEBUFFER_H_ */

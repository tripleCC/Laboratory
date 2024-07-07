/* Copyright (c) (2016,2017,2019,2022) Apple Inc. All rights reserved.
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

#include <corecrypto/cc_priv.h>

#include "../include/hexToString.h"

#if CC_KERNEL
void kprintf(const char *fmt, ...) __cc_printflike(1,2);
#define outputf kprintf
#else
#include <stdio.h>
#define outputf printf
#endif


static char byteMap[] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

void printBytes(const uint8_t *buf, size_t len, const char *name, int spaced)
{
	size_t i;
	outputf("%s (%d bytes): ", name, (int)len);
	for(i = 0; i < len; i++) {
		if (spaced && i > 0 && !(i % 8)) {
            outputf(" ");
        }
		if (spaced && i > 0 && !(i % 64)) {
            outputf("\n");
        }
		outputf("%02x", buf[i]);
	}
	outputf("\n");
}

/* Utility function to convert nibbles (4 bit values) into a hex character representation */
char nibbleToChar(uint8_t nibble)
{
	return byteMap[nibble & 0x0f];
}

/*
 * Take the supplied 'buf' of 'len' bytes and convert them to a hex string, inserting a space
 * every 'breakOn' bytes.  If the resultLen is less than the number of bytes necessary to
 * write the whole string, do nothing except return the required number of bytes.
 */
size_t hexToString(char *result, size_t resultLen, const uint8_t *buf, size_t len, size_t breakOn)
{
    size_t retLen;

    if (breakOn) {
        retLen = len * 2 + 1 + ((len * 2) / breakOn);
    } else {
        retLen = len * 2 + 1;
    }

    if (!result || resultLen < retLen) {
        return retLen;
    }

    for (size_t i = 0, j = 0; i < len; i++) {
        result[j] = nibbleToChar(buf[i] >> 4);
        result[j + 1] = nibbleToChar(buf[i]);

        if (breakOn && ((i + 1) % breakOn) == 0) {
            result[j + 2] = ' ';
            j++;
        }
        result[j + 2] = 0;
        j += 2;
    }

    return retLen;
}

uint8_t nibbleFromChar(char c)
{
	if(c >= '0' && c <= '9') return (uint8_t)(c - '0');
	if(c >= 'a' && c <= 'f') return (uint8_t)(c - 'a' + 10);
	if(c >= 'A' && c <= 'F') return (uint8_t)(c - 'A' + 10);
	return 255;
}



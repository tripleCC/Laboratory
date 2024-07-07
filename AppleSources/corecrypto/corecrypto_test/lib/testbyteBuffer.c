/* Copyright (c) (2012,2014,2015,2016,2017,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <assert.h>
#include "hexToString.h"
#include "testbyteBuffer.h"
#include "testmore.h"
#include <corecrypto/ccrng.h>

byteBuffer mallocByteBuffer(size_t len)
{
	byteBuffer retval;

    if (len >= SIZE_MAX - (sizeof(byteBufferStruct) + 1)) {
        return NULL;
    }
	if ((retval = (byteBuffer)malloc(sizeof(byteBufferStruct) + len + 1)) == NULL) {
        return NULL;
    }
    retval->len = len;

    /* just past the byteBuffer in malloc'ed space */
    retval->bytes = (uint8_t *)(retval + 1);

    return retval;
}

/*
 * Convert a string of characters representing a hex buffer into a series of
 * bytes of that real value
 */
byteBuffer hexStringToBytes(const char *inhex)
{
	byteBuffer retval;
	const char *p;
	size_t len, inhex_len, i = 0;
    
    if(!inhex) inhex = "";
    inhex_len = strlen(inhex);

	len = (inhex_len + 1) / 2;
	if ((retval = mallocByteBuffer(len)) == NULL) {
        return NULL;
    }

    // Special for odd length strings
    if ((inhex_len & 1) && len) {
        retval->bytes[i++] = nibbleFromChar(*(inhex));
        inhex++;
    }
	for(p = inhex; i < len; i++) {
        retval->bytes[i] = (uint8_t)((nibbleFromChar(*p) << 4) | nibbleFromChar(*(p + 1)));
        p += 2;
	}
    retval->bytes[len] = 0;
	return retval;
}

byteBuffer bytesToBytes(const void *bytes, size_t len)
{
    byteBuffer retval = mallocByteBuffer(len);
    if (retval && bytes) {
        memcpy(retval->bytes, bytes, len);
    }
    return retval;
}

int bytesAreEqual(byteBuffer b1, byteBuffer b2)
{
    if (b1->len != b2->len) {
        return 0;
    }
    return (memcmp(b1->bytes, b2->bytes, b1->len) == 0);
}

void printByteBuffer(byteBuffer bb, char *name)
{
    printBytes(bb->bytes, bb->len, name, 0);
}

void printByteBufferAsCharAssignment(byteBuffer bb, char *varname)
{
    printf("\t%s = \"", varname);
    for (size_t i = 0; i<bb->len; i++) {
        printf("%02x", bb->bytes[i]);
    }
    printf("\";\n");
}

char *bytesToHexStringWithSpaces(byteBuffer bb, size_t breaks)
{
	char *retval;
	size_t len;
    
    len = hexToString(NULL, 0, bb->bytes, bb->len, breaks);
    retval = malloc(len);
    hexToString(retval, len, bb->bytes, bb->len, breaks);

	return retval;
}

/* Convert a buffer of binary values into a hex string representation */
char *bytesToHexString(byteBuffer bb)
{
    return bytesToHexStringWithSpaces(bb, 0);
}

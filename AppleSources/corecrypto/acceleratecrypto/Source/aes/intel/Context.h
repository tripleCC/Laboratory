/* Copyright (c) (2012,2015,2016,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CONTEXT_H_
#define _CORECRYPTO_CONTEXT_H_

// Define byte offset of key within context structure.
#define	ContextKey			0

/*	Define byte offset of key length within context structure.  The number
	stored there is the number of bytes from the start of the first round key
	to the start of the last round key.  That is 16 less than the number of
	bytes in the entire key.
*/
#define	ContextKeyLength	240

#endif /* _CORECRYPTO_CONTEXT_H_ */

/* Copyright (c) (2015,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
*/

{ //q = base-1
"FFFF FFFF FFFF FFFF 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000",
"0000 0001 0000 0000 0000 0000 FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF"
},


{ //needs add back
"FF00 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000",
"0001 0000 0000 0000 0000 FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF"
},

{"7", "d"},
{"d", "7"},
{"3", "3"},
{"FFFFffff", "3"},
{"FFFFffff", "1"},
{"FFFFffff", "FFFFffff"},
{"FFFF ffff FFFF ffff", "0000 0001 0000 0000"},
{"FFFF ffff FFFF ffff", "FFFF 0000 0000 0000"},
{"FFFF ffff FFFF ffff", "FFFF FFFF 0000 0000"},
{"FFFF ffff FFFF ffff", "FFFF FFFF FFFF 0000"},
{"FFFF ffff FFFF ffff", "FFFF FFFF FFFF FFFF"},
{"FFFF ffff FFFF fffe", "FFFF ffff 00000000"},
{"FFFFffffFFFFffffFFFFffffFFFFffff", "00000001000000010000000000000000"},
{"FFFFffffFFFFffffFFFFffffFFFFffff", "80000000000000000000000000000000"},
{"FFFFffffFFFFffffFFFFffffFFFFffff", "0FFFffffFFFFffffFFFFffffFFFFffff"},
{"FFFFffffFFFFffffFFFFffffFFFFffff", "FFFFffffFFFFffffFFFFffffFFFFffff"},
{"0000001100000011FFFFffffFFFFffff", "0000000100000001FFFFffffFFFFffff"},
{"0000000100000001FFFFffffFFFFffff", "0000000100000001FFFFffffFFFFffff"},
{"FFFFffffFFFFffffFFFFffffFFFFffff", "0000000100000001FFFFffffFFFFffff"},
{"9876543210abcdef9876543210abcdef9876543210abcdef", "8876543210abcdef9876543210abcdef9876543210abcdef"},

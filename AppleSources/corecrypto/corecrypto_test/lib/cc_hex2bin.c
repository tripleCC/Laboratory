/* Copyright (c) (2010,2012,2015,2016,2018,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "cctest.h"
#include <stdlib.h>
#include <stdint.h>

/* Helper function to manipulate test vectors */

static uint8_t hex_nibble(char hex) {
    if ('0' <= hex && hex <= '9')
        return (uint8_t)hex - '0';
    else if ('a' <= hex && hex <= 'f')
        return (uint8_t)hex + 10 - 'a';
    else if ('A' <= hex && hex <= 'F')
        return (uint8_t)hex + 10 - 'A';
    else {
        return 0;
    }
}

static char hex_digit(uint8_t bin) {
    if(bin<0xa)
        return '0'+(char)bin;
    else if(bin<0x10)
        return 'a'+((char)(bin)-10);
    else
        return 'x';
}

/* convert a C string of hex into a binary array
 C string len should be a multiple of 2 */
void cc_hex2bin(size_t n, uint8_t *bin, const char *hex)
{
    size_t i;
    for(i=0; i<n; i++) {
        bin[i]= (uint8_t)(hex_nibble(hex[i*2])<<4) | hex_nibble(hex[i*2+1]);
    }
}

void cc_bin2hex(size_t n, char *hex, const unsigned char *bin)
{
    size_t i;
    for(i=0; i<n; i++) {
        hex[2*i]=hex_digit((bin[i]>>4)&0xf);
        hex[2*i+1]=hex_digit(bin[i]&0xf);
    }
    hex[2*n]=0;
}

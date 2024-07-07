/* Copyright (c) (2016,2018,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */


#define     thermalCryptoVersion    1

extern void thermalSHA1(uint32_t ITERATIONS,uint32_t data_size);
extern void thermalSHA224(uint32_t ITERATIONS, uint32_t data_size);
extern void thermalSHA256(uint32_t ITERATIONS, uint32_t data_size);
extern void thermalSHA384(uint32_t ITERATIONS, uint32_t data_size);
extern void thermalSHA512(uint32_t ITERATIONS, uint32_t data_size);
extern void thermalAES_ECB(uint32_t    ITERATIONS, uint32_t    data_size);
extern void thermalAES_CBC(uint32_t    ITERATIONS, uint32_t    data_size);
extern void thermalAES_XTS(uint32_t    ITERATIONS, uint32_t    data_size);
extern void thermalAES_GCM(uint32_t    ITERATIONS, uint32_t    data_size);
extern void thermalAES_CTR(uint32_t    ITERATIONS, uint32_t    data_size);
extern void thermalAES_CCM(uint32_t    ITERATIONS, uint32_t    data_size);
extern void thermalAES_CFB(uint32_t    ITERATIONS, uint32_t    data_size);
extern void thermalAES_OFB(uint32_t    ITERATIONS, uint32_t    data_size);

extern void thermalCRC32(uint32_t    ITERATIONS, uint32_t data_size);
extern void thermalAdler32(uint32_t    ITERATIONS, uint32_t data_size);

extern void validateAES_ECB(void);
extern void validateAES_CBC(void);
extern void validateAES_XTS(void);
extern void validateAES_GCM(void);
extern void validateAES_CTR(void);
extern void validateAES_CCM(void);
extern void validateAES_CFB(void);
extern void validateAES_OFB(void);

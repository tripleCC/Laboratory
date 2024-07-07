/* Copyright (c) (2020-2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_MODULEID_H_
#define _CORECRYPTO_MODULEID_H_

enum cc_module_id_format {
    cc_module_id_Full     = 0,  /* Full formatted Module ID / Version String  */
    cc_module_id_Name     = 1,  /* Module Name Only                           */
    cc_module_id_Version  = 2,  /* Version: XX.YY                             */
    cc_module_id_Target   = 3,  /* Target: User / Kernel / SEP                */
    cc_module_id_Type     = 4,  /* Type defined by CMVP: Hardware,Software... */
    cc_module_id_Proc     = 5,  /* Processor / Chip - Apple Silicon / Intel   */
    cc_module_id_SecLevel = 6,  /* FIPS 140-x Security Level:   SL#           */
};

#define moduleBaseName "Apple corecrypto Module"     // Module Base Name
#define moduleVersion  "14.0"                        // 2023 OS Releases

#if CC_KERNEL                                        // Kernel - Software
    #define moduleTarget "Kernel"
    #define moduleType "Software"
#elif !CC_USE_L4                                     // User - Software
    #define moduleTarget "User"
    #define moduleType "Software"
#else                                                // Secure Key Store - Hardware
    #define moduleTarget "Secure Key Store"
    #define moduleType "Hardware"
#endif


extern const char *cc_module_id(enum cc_module_id_format outformat);

#endif /* _CORECRYPTO_MODULEID_H_ */

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

#include "cc_internal.h"
#include "module_id.h"

#if CC_USE_L4
    #include <info.h>
#endif

//
//  Provide string version of the FIPS 140-x Validated corecrypto Module
//
extern const char *cc_module_id(enum cc_module_id_format outformat)
{
    static char moduleID[256] = { 0 };
    const size_t mod_nbytes = sizeof(moduleID);
    static char moduleSecLevel[8] = { 0 };
    const size_t sl_nbytes = sizeof(moduleSecLevel);
    static char moduleProc[16] = { 0 };
    const size_t pr_nbytes = sizeof(moduleProc);
    
    // snprintf can be a macro, and thus requires the ()

#if defined(__x86_64__) || defined(__i386__)
    (snprintf)(moduleProc, pr_nbytes, "Intel");     // Intel-based Macs
#elif defined(__arm__) || defined(__arm64__)        // Apple ARM/silicon

	#if defined(TARGET_OS_OSX) && (TARGET_OS_OSX)   // macOS on Apple silicon
        (snprintf)(moduleProc, pr_nbytes, "Apple silicon");
    #else
        (snprintf)(moduleProc, pr_nbytes, "Apple ARM");
    #endif
    
	#if CC_USE_L4
    const uint32_t cc_chipIDs[] = {
                0x8030,0x8101,0x8103,0x8110,0x8112,0x8120,0x8122,0x8130,0x8132,0x8301,
                0x8310,0x6000,0x6001,0x6002,0x6020,0x6021,0x6022,0x6030,0x6031,0x6032,
                0x6033,0x6034};
    int N_CHIP_IDS = CC_ARRAY_LEN(cc_chipIDs);

    uint32_t cc_chip_id = get_chip_id();

    (snprintf)(moduleSecLevel, sl_nbytes, "SL2");
    for (int i=0; i < N_CHIP_IDS; i++) {
        if (cc_chip_id == cc_chipIDs[i]){
            (snprintf)(moduleSecLevel, sl_nbytes, "SL2/PH3");
            break;
        }
    }
    #endif  // CC_USE_L4 //
#else
    (snprintf)(moduleProc, pr_nbytes, "Undefined SoC"); // Should never reach here, but...
#endif

#if !CC_USE_L4
    (snprintf)(moduleSecLevel, sl_nbytes, "SL1"); // FIPS 140-3 Security Level - User & Kernel
#endif

// Full (default) format:
// <moduleBaseName> v<moduleVersion> [<moduleProc>, <moduleTarget>, <moduleType>, <moduleSecLevel>]
// eg. Apple corecrypto Module v12.0 [Apple Silicon, Secure Key Store, Hardware, SL2/PH3]

    switch (outformat) {
    case cc_module_id_Full: {
        (snprintf)(moduleID, mod_nbytes, "%s v%s [%s, %s, %s, %s]",
                   moduleBaseName, moduleVersion, moduleProc, moduleTarget, moduleType, moduleSecLevel);
    } break;
    case cc_module_id_Version:
        (snprintf)(moduleID, mod_nbytes, "%s", moduleVersion);
        break;
    case cc_module_id_Target:
        (snprintf)(moduleID, mod_nbytes, "%s", moduleTarget);
        break;
    case cc_module_id_Proc:
        (snprintf)(moduleID, mod_nbytes, "%s", moduleProc);
        break;
    case cc_module_id_Name:
        (snprintf)(moduleID, mod_nbytes, "%s", moduleBaseName);
        break;
    case cc_module_id_Type:
        (snprintf)(moduleID, mod_nbytes, "%s", moduleType);
        break;
    case cc_module_id_SecLevel:
        (snprintf)(moduleID, mod_nbytes, "%s", moduleSecLevel);
        break;
    default:
        (snprintf)(moduleID, mod_nbytes, "INVALID Module ID");
    }

    return moduleID;
}

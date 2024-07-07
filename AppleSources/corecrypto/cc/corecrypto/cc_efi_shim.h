/* Copyright (c) (2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CC_EFI_SHIM_H_
#define _CORECRYPTO_CC_EFI_SHIM_H_

#include <corecrypto/cc_config.h>

#if CC_EFI

// Efi headers also define DEBUG
#ifdef DEBUG
#define CC_TEMP_DEBUG DEBUG
#undef DEBUG
#endif

#include <Foundation/Include/Tiano.h>
#include <Foundation/Include/EfiDebug.h>
#include <Foundation/Efi/Include/EfiTypes.h>
#include <Dxe/Include/EfiDriverLib.h>
#include <Dxe/Include/EfiCommonLib.h>
#include <EfiStdArg.h>
#include <EfiBind.h>

#undef DEBUG
#ifdef CC_TEMP_DEBUG
#define DEBUG CC_TEMP_DEBUG
#endif

#endif /* CC_EFI */
#endif /* _CORECRYPTO_CC_EFI_SHIM_H_ */

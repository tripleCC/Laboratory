/* Copyright (c) (2015-2019,2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef ccmode_gcm_tables_h
#define ccmode_gcm_tables_h

#include "ccaes_vng_gcm.h"
#include "ccmode_internal.h"

#if CCMODE_GCM_VNG_SPEEDUP
    #define GCM_TABLE_SIZE VNG_GCM_TABLE_SIZE
#else
    #define GCM_TABLE_SIZE 0
#endif

#endif /* ccmode_gcm_tables_h */

/* Copyright (c) (2020,2021,2023) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CCSAE_INTERNAL_H_
#define _CORECRYPTO_CCSAE_INTERNAL_H_

#include "cc_memory.h"

extern const char *SAE_KCK_PMK_LABEL;              // = "SAE KCK and PMK";
extern const char *SAE_HUNT_PECK_LABEL;            // = "SAE Hunting and Pecking";

#define SAE_KCK_PMK_LABEL_NBYTES     15
#define SAE_HUNT_PECK_LABEL_NBYTES   23
#define SAE_HUNT_AND_PECK_ITERATIONS 40

extern const uint8_t CCSAE_STATE_INIT;
extern const uint8_t CCSAE_STATE_COMMIT_INIT;
extern const uint8_t CCSAE_STATE_COMMIT_UPDATE;
extern const uint8_t CCSAE_STATE_COMMIT_GENERATED;
extern const uint8_t CCSAE_STATE_COMMIT_VERIFIED;
extern const uint8_t CCSAE_STATE_COMMIT_BOTH;
extern const uint8_t CCSAE_STATE_CONFIRMATION_GENERATED;
extern const uint8_t CCSAE_STATE_CONFIRMATION_VERIFIED;
extern const uint8_t CCSAE_STATE_CONFIRMATION_BOTH;

/*! @function ccsae_y2_from_x_ws
 @abstract Generates the square of the 'y' coordinate, if it exists, given an `x` coordinate and curve parameters.

 @param cp    ECC parameters
 @param ws    Workspace of size CCSAE_Y2_FROM_X_WORKSPACE_N(ccec_cp_n(cp))
 @param y2    Output 'y^2'
 @param x_in  Input 'x' coordinate

 @return true on success, false on failure.
 */
CC_NONNULL_ALL CC_WARN_RESULT
bool ccsae_y2_from_x_ws(cc_ws_t ws, ccec_const_cp_t cp, cc_unit *y2, const cc_unit *x_in);

/*! @function ccsae_gen_password_value_ws
 
 @abstract Generates the password value (see 12.4.4.3.2 of IEEE P802.11-REVmdTM/D1.6 Part 11)
 
 @param ws        The input workspace
 @param ctx       SAE context
 @param pwd_seed  The generated password seed
 @param output    Output buffer for the password value

 */
CC_NONNULL_ALL
void ccsae_gen_password_value_ws(cc_ws_t ws, ccsae_ctx_t ctx, const uint8_t *pwd_seed, cc_unit *output);

/*! @function ccsae_gen_keys_ws
 
 @abstract Generates the KCK and PMK (see 12.4.5.4 of IEEE P802.11-REVmdTM/D1.6 Part 11)

 @param ws        The input workspace
 @param ctx      SAE context
 @param keyseed  The generated keyseed
 @param context  Context information binding the keys to this run of the protocol

 @return 0 on success, non-zero on failure.
 */
CC_NONNULL_ALL CC_WARN_RESULT
int ccsae_gen_keys_ws(cc_ws_t ws, ccsae_ctx_t ctx, const uint8_t *keyseed, const cc_unit *context);

/*! @function ccsae_sizeof_kck_internal
 
 @param ctx SAE Context
 
 @return The size of the key `kck` in bytes
 
 @discussion Returns the size of the kck key based on the algorithm
 */
CC_NONNULL_ALL
size_t ccsae_sizeof_kck_internal(ccsae_const_ctx_t ctx);

#endif // _CORECRYPTO_CCSAE_INTERNAL_H_

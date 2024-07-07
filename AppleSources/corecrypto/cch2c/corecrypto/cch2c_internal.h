/* Copyright (c) (2020,2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CCH2C_INTERNAL_H_
#define _CORECRYPTO_CCH2C_INTERNAL_H_

#include <corecrypto/cc.h>
#include <corecrypto/ccdigest.h>
#include <corecrypto/ccec.h>
#include <corecrypto/cch2c.h>
#include "cc_memory.h"

#define CCH2C_MAX_DATA_NBYTES (255)

struct cch2c_info {
    const char *name;
    unsigned l;
    unsigned z;
    ccec_const_cp_t (*CC_SPTR(cch2c_info, curve_params))(void);
    const struct ccdigest_info *(*CC_SPTR(cch2c_info, digest_info))(void);
    int (*CC_SPTR(cch2c_info, hash_to_base))(cc_ws_t ws,
                        const struct cch2c_info *info,
                        size_t dst_nbytes, const void *dst,
                        size_t data_nbytes, const void *data,
                        uint8_t n,
                        cc_unit *u);
    int (*CC_SPTR(cch2c_info, map_to_curve))(cc_ws_t ws,
                        const struct cch2c_info *info,
                        const cc_unit *u,
                        ccec_pub_ctx_t q);
    int (*CC_SPTR(cch2c_info, clear_cofactor))(const struct cch2c_info *info,
                          ccec_pub_ctx_t q);
    int (*CC_SPTR(cch2c_info, encode_to_curve))(cc_ws_t ws,
                           const struct cch2c_info *info,
                           size_t dst_nbytes, const void *dst,
                           size_t data_nbytes, const void *data,
                           ccec_pub_ctx_t q);
};

/*!
 @function cch2c_ws
 @abstract Hash input data to an elliptic curve point as in
           https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-05.

 @param ws          Workspace
 @param info        Parameters for the hash-to-curve method
 @param dst_nbytes  Length of the application-supplied domain-separation tag
 @param dst         Application-supplied domain-separation tag
 @param data_nbytes Length of the user-supplied input data
 @param data        User-supplied input data
 @param pubkey      The output elliptic curve point

 @return CCERR_OK on success, an error code otherwise.
 */
CC_NONNULL_ALL CC_WARN_RESULT
int cch2c_ws(cc_ws_t ws,
             const struct cch2c_info *info,
             size_t dst_nbytes, const void *dst,
             size_t data_nbytes, const void *data,
             ccec_pub_ctx_t pubkey);

/*!
 @function cch2c_hash_to_base_ws
 @abstract Hashes arbitrary-length bit strings to elements of a finite field.

 @param ws          Workspace
 @param info        Parameters for the hash-to-curve method
 @param dst_nbytes  Length of the application-supplied domain-separation tag
 @param dst         Application-supplied domain-separation tag
 @param data_nbytes Length of the user-supplied input data
 @param data        User-supplied input data
 @param ctr         Counter value, either 0 or 1.
 @param u           Output element of a finite field.

 @return CCERR_OK on success, an error code otherwise.
 */
CC_NONNULL_ALL CC_WARN_RESULT
int cch2c_hash_to_base_ws(cc_ws_t ws,
                          const struct cch2c_info *info,
                          size_t dst_nbytes, const void *dst,
                          size_t data_nbytes, const void *data,
                          uint8_t ctr,
                          cc_unit *u);

/*!
 @function cch2c_hash_to_base_sae_ws
 @abstract Hashes arbitrary-length bit strings to elements of a finite field.
 @discussion Implements WPA-3 SAE H2E (hash-to-element).

 @param ws          Workspace
 @param info        Parameters for the hash-to-curve method
 @param dst_nbytes  Length of the application-supplied domain-separation tag
 @param dst         Application-supplied domain-separation tag
 @param data_nbytes Length of the user-supplied input data
 @param data        User-supplied input data
 @param ctr         Counter value, either 0 or 1.
 @param u           Output element of a finite field.

 @return CCERR_OK on success, an error code otherwise.
 */
CC_NONNULL_ALL CC_WARN_RESULT
int cch2c_hash_to_base_sae_ws(cc_ws_t ws,
                              const struct cch2c_info *info,
                              size_t dst_nbytes, const void *dst,
                              size_t data_nbytes, const void *data,
                              uint8_t ctr,
                              cc_unit *u);

/*!
 @function cch2c_hash_to_base_rfc_ws
 @abstract Hashes arbitrary-length bit strings to elements of a finite field.
 @discussion See https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-05#section-5.3.

 @param ws          Workspace
 @param info        Parameters for the hash-to-curve method
 @param dst_nbytes  Length of the application-supplied domain-separation tag
 @param dst         Application-supplied domain-separation tag
 @param data_nbytes Length of the user-supplied input data
 @param data        User-supplied input data
 @param ctr         Counter value, either 0, 1, or 2.
 @param u           Output element of a finite field.

 @return CCERR_OK on success, an error code otherwise.
 */
CC_NONNULL_ALL CC_WARN_RESULT
int cch2c_hash_to_base_rfc_ws(cc_ws_t ws,
                              const struct cch2c_info *info,
                              size_t dst_nbytes, const void *dst,
                              size_t data_nbytes, const void *data,
                              uint8_t ctr,
                              cc_unit *u);

/*!
 @function cch2c_map_to_curve_sswu_ws
 @abstract Calculates a point on the curve from a given element of a finite field
           using simplified SWU mapping.
 @discussion See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-05#section-6.6.2.

 @param ws          Workspace
 @param info        Parameters for the hash-to-curve method
 @param u           Element of a finite field.
 @param q           Output point on the curve.

 @return CCERR_OK on success, an error code otherwise.
 */
CC_NONNULL_ALL CC_WARN_RESULT
int cch2c_map_to_curve_sswu_ws(cc_ws_t ws,
                               const struct cch2c_info *info,
                               const cc_unit *u,
                               ccec_pub_ctx_t q);

/*!
 @function cch2c_map_to_curve_ws
 @abstract Calculates a point on the curve from a given element of a finite field.

 @param ws          Workspace
 @param info        Parameters for the hash-to-curve method
 @param u           Element of a finite field.
 @param q           Output point on the curve.

 @return CCERR_OK on success, an error code otherwise.
 */
CC_NONNULL_ALL CC_WARN_RESULT
int cch2c_map_to_curve_ws(cc_ws_t ws,
                          const struct cch2c_info *info,
                          const cc_unit *u,
                          ccec_pub_ctx_t q);

/*!
 @function cch2c_encode_to_curve_ro_ws
 @abstract Encodes arbitrary-length bit strings to points on a curve using
           random oracle encoding.
 @discussion See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-05#section-3.

 @param ws          Workspace
 @param info        Parameters for the hash-to-curve method
 @param dst_nbytes  Length of the application-supplied domain-separation tag
 @param dst         Application-supplied domain-separation tag
 @param data_nbytes Length of the user-supplied input data
 @param data        User-supplied input data
 @param q           The output elliptic curve point

 @return CCERR_OK on success, an error code otherwise.
 */
CC_NONNULL_ALL CC_WARN_RESULT
int cch2c_encode_to_curve_ro_ws(cc_ws_t ws,
                                const struct cch2c_info *info,
                                size_t dst_nbytes, const void *dst,
                                size_t data_nbytes, const void *data,
                                ccec_pub_ctx_t q);

/*!
 @function cch2c_encode_to_curve_ws
 @abstract Encodes arbitrary-length bit strings to points on a curve.

 @param ws          Workspace
 @param info        Parameters for the hash-to-curve method
 @param dst_nbytes  Length of the application-supplied domain-separation tag
 @param dst         Application-supplied domain-separation tag
 @param data_nbytes Length of the user-supplied input data
 @param data        User-supplied input data
 @param pubkey      The output elliptic curve point

 @return CCERR_OK on success, an error code otherwise.
 */
CC_NONNULL_ALL CC_WARN_RESULT
int cch2c_encode_to_curve_ws(cc_ws_t ws,
                             const struct cch2c_info *info,
                             size_t dst_nbytes, const void *dst,
                             size_t data_nbytes, const void *data,
                             ccec_pub_ctx_t pubkey);

#endif /* _CORECRYPTO_CCH2C_INTERNAL_H_ */

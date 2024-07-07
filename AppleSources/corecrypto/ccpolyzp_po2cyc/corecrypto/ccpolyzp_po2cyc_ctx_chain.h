/* Copyright (c) (2022,2023) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CCPOLYZP_PO2CYC_CTX_CHAIN_H_
#define _CORECRYPTO_CCPOLYZP_PO2CYC_CTX_CHAIN_H_

#include <corecrypto/cc_config.h>
#include <corecrypto/ccn.h>
#include "cc_memory.h"
#include "cc_workspaces.h"
#include "ccpolyzp_po2cyc_internal.h"

CC_PTRCHECK_CAPABLE_HEADER()

/// Stores a chain of polynomial contexts
/// The full context chain has moduli q_0, ..., q_{L-1}
/// The next context has moduli q_0, ..., q_{L-2}.
/// Each successive next context drops the last modulus.
struct ccpolyzp_po2cyc_ctx_chain {
    // The dimensions of the full context
    struct ccpolyzp_po2cyc_dims dims;
    // Storage to an array of the contexts, starting with the full context, then iteratively smaller contexts obtained by removing
    // the last modulus. Each context is stored as a value, rather than a pointer and has predictable size in memory based on the
    // index.
    cc_unit data[];
} CC_ALIGNED(CCN_UNIT_SIZE);
typedef struct ccpolyzp_po2cyc_ctx_chain *ccpolyzp_po2cyc_ctx_chain_t;
typedef const struct ccpolyzp_po2cyc_ctx_chain *ccpolyzp_po2cyc_ctx_chain_const_t;

/// @brief Initializes the entire context chain with the given moduli and dimensions
/// @param ws Workspace
/// @param chain The context chain to initialize
/// @param dims The dimensions for the full context
/// @param moduli The moduli q_0, ..., q_{L-1}
/// @return CCERR_OK if context chain is properly initialized
CC_NONNULL_ALL
int ccpolyzp_po2cyc_ctx_chain_init_ws(cc_ws_t ws,
                                      ccpolyzp_po2cyc_ctx_chain_t chain,
                                      ccpolyzp_po2cyc_dims_const_t dims,
                                      const ccrns_int *moduli);

/// @brief Returns the number of cc_units required to allocate an entire context chain with the given dimensions
/// @param dims The full context dimensions
CC_INLINE cc_size ccpolyzp_po2cyc_ctx_chain_nof_n(ccpolyzp_po2cyc_dims_const_t dims)
{
    cc_size rv = cc_ceiling(sizeof_struct_ccpolyzp_po2cyc_ctx_chain(), sizeof_cc_unit());
    rv += dims->nmoduli * ccpolyzp_po2cyc_ctx_nof_n(dims->degree);
    return rv;
}

/// @brief Allocates memory for a context chain
/// @param ws cc_ws_t Workspace
/// @param dims Dimensions of the full context
#define CCPOLYZP_PO2CYC_CTX_CHAIN_ALLOC_WS(ws, dims) \
    (ccpolyzp_po2cyc_ctx_chain_t) CC_ALLOC_WS(ws, ccpolyzp_po2cyc_ctx_chain_nof_n((dims)))

/// @brief Retrieves the context with a given number of moduli
/// @param ctx_chain The context chain
/// @param nmoduli The number of moduli in the context to retrieve
/// @return The context with the given number of moduli
CC_INLINE ccpolyzp_po2cyc_ctx_t ccpolyzp_po2cyc_ctx_chain_context(ccpolyzp_po2cyc_ctx_chain_t ctx_chain, uint32_t nmoduli)
{
    ccpolyzp_po2cyc_dims_const_t dims = &ctx_chain->dims;
    cc_assert(nmoduli > 0 && nmoduli <= dims->nmoduli);
    cc_unit *rv = ctx_chain->data;
    rv += ccpolyzp_po2cyc_ctx_nof_n(dims->degree) * (dims->nmoduli - nmoduli);
    return (ccpolyzp_po2cyc_ctx_t)rv;
}

/// @brief Retrieves the context with a given number of moduli
/// @param ctx_chain The context chain
/// @param nmoduli The number of moduli in the context to retrieve
/// @return The context with the given number of moduli
CC_INLINE ccpolyzp_po2cyc_ctx_const_t ccpolyzp_po2cyc_ctx_chain_context_const(ccpolyzp_po2cyc_ctx_chain_const_t ctx_chain,
                                                                              uint32_t nmoduli)
{
    ccpolyzp_po2cyc_dims_const_t dims = &ctx_chain->dims;
    cc_assert(nmoduli > 0 && nmoduli <= dims->nmoduli);
    const cc_unit *rv = ctx_chain->data;
    rv += ccpolyzp_po2cyc_ctx_nof_n(dims->degree) * (dims->nmoduli - nmoduli);
    return (ccpolyzp_po2cyc_ctx_const_t)rv;
}

#endif /* _CORECRYPTO_CCPOLYZP_PO2CYC_CTX_CHAIN_H_ */

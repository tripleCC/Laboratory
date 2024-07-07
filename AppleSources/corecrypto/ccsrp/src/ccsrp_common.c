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

#include <corecrypto/ccsrp.h>

size_t ccsrp_sizeof_verifier(ccsrp_const_gp_t gp)
{
    return ccsrp_gp_sizeof_n(gp);
}

size_t ccsrp_sizeof_public_key(ccsrp_const_gp_t gp)
{
    return ccsrp_gp_sizeof_n(gp);
}

size_t ccsrp_sizeof_M_HAMK(const struct ccdigest_info *di)
{
    return di->output_size;
}

int ccsrp_ctx_init_with_size_option(struct ccsrp_ctx * cc_sized_by(srp_size) srp,
                                              size_t srp_size,
                                              const struct ccdigest_info *di,
                                              ccsrp_const_gp_t gp,
                                              uint32_t option,
                                              struct ccrng_state *blinding_rng)
{
    cc_clear(srp_size, HDR(srp));
    SRP_DI(srp) = di;
    SRP_GP(srp) = gp;
    SRP_FLG(srp).authenticated = false;
    SRP_FLG(srp).sessionkey = false;
    SRP_RNG(srp) = blinding_rng;
    // Option is a bit mask. If not a power of two, it's an error.
    SRP_FLG(srp).variant = 0xFFFF & option;
    return 0; // Success
}

bool ccsrp_client_set_noUsernameInX(ccsrp_ctx_t srp, bool flag)
{
    return HDR(srp)->flags.noUsernameInX = !!flag;
}

bool ccsrp_is_authenticated(ccsrp_ctx_t srp)
{
    return HDR(srp)->flags.authenticated;
}

size_t ccsrp_exchange_size(ccsrp_ctx_t srp)
{
    return ccsrp_ctx_sizeof_n(srp);
}

size_t ccsrp_session_size(ccsrp_ctx_t srp)
{
    /* Session Keys and M and HAMK are returned in this many bytes */
    return (ccsrp_ctx_di(srp)->output_size);
}

size_t ccsrp_sizeof_session_key(const struct ccdigest_info *di,
                                          uint32_t option)
{
    if ((option & CCSRP_OPTION_KDF_MASK) == CCSRP_OPTION_KDF_HASH) {
        return di->output_size;
    }

    if (((option & CCSRP_OPTION_KDF_MASK) == CCSRP_OPTION_KDF_INTERLEAVED) ||
        ((option & CCSRP_OPTION_KDF_MASK) == CCSRP_OPTION_KDF_MGF1)) {
        return 2 * di->output_size;
    }

    return 0; // Error
}

size_t ccsrp_get_session_key_length(ccsrp_ctx_t srp)
{
    return ccsrp_sizeof_session_key(ccsrp_ctx_di(srp), HDR(srp)->flags.variant);
}

const void *ccsrp_get_session_key(ccsrp_ctx_t srp, size_t *key_length)
{
    *key_length = ccsrp_get_session_key_length(srp);
    if (HDR(srp)->flags.sessionkey) {
        return ccsrp_ctx_K(srp);
    } else {
        return NULL;
    }
}

cc_unit *ccsrp_get_premaster_secret(ccsrp_ctx_t srp)
{
    if (HDR(srp)->flags.sessionkey) {
        return ccsrp_ctx_S(srp);
    } else {
        return NULL;
    }
}

#if !CC_PTRCHECK

int ccsrp_ctx_init_option(ccsrp_ctx_t srp,
                                    const struct ccdigest_info *di,
                                    ccsrp_const_gp_t gp,
                                    uint32_t option,
                                    struct ccrng_state *blinding_rng)
{
    size_t srp_size = ccsrp_sizeof_srp(di, gp);
    return ccsrp_ctx_init_with_size_option(srp, srp_size, di, gp, option, blinding_rng);
}

void ccsrp_ctx_init(ccsrp_ctx_t srp, const struct ccdigest_info *di, ccsrp_const_gp_t gp)
{
    size_t srp_size = ccsrp_sizeof_srp(di, gp);
    ccsrp_ctx_init_with_size_option(srp, srp_size, di, gp, CCSRP_OPTION_SRP6a_HASH, ccrng(NULL));
}

#endif // !CC_PTRCHECK

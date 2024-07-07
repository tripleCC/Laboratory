/* Copyright (c) (2010-2012,2014-2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/ccrsa_priv.h>
#include "ccrsa_internal.h"
#include "cc_workspaces.h"
#include "cc_macros.h"

/*
 * power/mod using Chinese Remainder Theorem.
 *
 * result becomes base^d (mod m).
 *
 *
 * p, q such that m = p*q
 * reciprocals of p, q
 * dp = d mod (p-1)
 * dq = d mod (q-1)
 * qinv = q^(-1) mod p
 *
 */

#define SCA_MASK_BITSIZE 32
#define SCA_MASK_MASK  (((((cc_unit)1)<<(SCA_MASK_BITSIZE-1))-1) <<1 | 1)    /* required to be a power of 2 */
#define SCA_MASK_N ccn_nof(SCA_MASK_BITSIZE)
#define NB_MASK (6 * SCA_MASK_N)   // p, dp, mp, q, dq, mq

cc_static_assert(SCA_MASK_N == 1, "we use ccn_mul1() for masks");

CC_PURE cc_size CCRSA_CRT_POWER_BLINDED_WORKSPACE_N(cc_size n)
{
    // cczp_n(p) + SCA_MASK_N
    cc_size nu = (n / 2 + 1) + SCA_MASK_N;

    return 5 * nu + NB_MASK + cczp_nof_n(nu) +
       CC_MAX_EVAL(CCZP_INIT_WORKSPACE_N(nu),
         CC_MAX_EVAL(CCZP_MM_POWER_WORKSPACE_N(nu),
           CC_MAX_EVAL(CCZP_MODN_WORKSPACE_N(nu),
             CC_MAX_EVAL(CCZP_MODN_WORKSPACE_N(n),
                         CCZP_MUL_WORKSPACE_N(nu))
           )
         )
       );
}

static int ccrsa_crt_power_blinded_ws(cc_ws_t ws,
                                      struct ccrng_state *blinding_rng,
                                      ccrsa_full_ctx_t fk,
                                      cc_unit *r,
                                      const cc_unit *x)
{

    cczp_t zm=ccrsa_ctx_zm(fk);
    cczp_t zp=ccrsa_ctx_private_zp(fk); /* zp * zq = public modulus */
    cczp_t zq=ccrsa_ctx_private_zq(fk);
    const cc_unit *dp=ccrsa_ctx_private_dp(fk); /* d mod (p-1)   cczp_n(zp) sized */
    const cc_unit *dq=ccrsa_ctx_private_dq(fk); /* d mod (q-1)   cczp_n(zq) sized */
    const cc_unit *qinv=ccrsa_ctx_private_qinv(fk); /* q^(-1) mod p  cczp_n(zp) sized */
    cc_size nq=cczp_n(zq);
    cc_size np=cczp_n(zp);
    cc_size nu=np+SCA_MASK_N; // np >=nq, checked below
    int status=CCRSA_PRIVATE_OP_ERROR;
    CC_DECL_BP_WS(ws, bp);
    cc_unit *tmp =  CC_ALLOC_WS(ws, 2*nu);
    cc_unit *tmp2 = CC_ALLOC_WS(ws, nu);
    cc_unit *sp =   CC_ALLOC_WS(ws, nu);
    cc_unit *sq =   CC_ALLOC_WS(ws, nu);
    cc_unit *rnd =  CC_ALLOC_WS(ws, NB_MASK);

    // Allocate a ZP which will be used to extend p and q for randomization
    cczp_t zu_masked = (cczp_t)CC_ALLOC_WS(ws, cczp_nof_n(nu));

    // Sanity check on supported key length
    cc_require_action((cczp_bitlen(zp) >= cczp_bitlen(zq)) && (np>=nq),
                      errOut,status=CCRSA_KEY_ERROR);      // No supported here.
    cc_require_action(blinding_rng!=NULL,
                      errOut,status=CCRSA_INVALID_CONFIG); // No supported here.

    // Random for masking
    cc_require((status=ccn_random(NB_MASK, rnd, blinding_rng))==0,errOut);

    // (Re-)Seed the PRNG used for mask generation.
    ccn_mux_seed_mask(rnd[0]);

    /*------------ Step 1 ------------------*/
    /*
        Modulus blinding:   q_star = rnd[0]*q
        Exponent blinding: dq_star = dq + rnd[1]*(q-1)
        Base blinding:     mq_star = (x + rnd[2]*q) Mod q_star
     */

    /* q_star:=q*cstq; */
    CCZP_N(zu_masked)=nq+SCA_MASK_N;
    *(CCZP_PRIME(zu_masked)+nq)=ccn_mul1(nq,CCZP_PRIME(zu_masked),cczp_prime(zq),SCA_MASK_MASK & (rnd[0] | 1)); /* q_star:=q*cstq; */
    cc_require((status=cczp_init_ws(ws, zu_masked)) == CCERR_OK, errOut);

    /* mq = m + k2.q mod q_star */
    ccn_setn(cczp_n(zm)+1,tmp,nq,cczp_prime(zq)); // q
    ccn_set_bit(tmp,0,0);  // q - 1
    ccn_set(nq,tmp2,dq);   // dq
    tmp2[nq]=ccn_addmul1(nq,tmp2,tmp,SCA_MASK_MASK & rnd[1]);       /* tmp2 = dq + rnd*(q-1) */
    tmp[nq]=ccn_mul1(nq,tmp,cczp_prime(zq),SCA_MASK_MASK & rnd[2]); /* tmp = mask0*q */
    ccn_addn(cczp_n(zm)+1,tmp,tmp,cczp_n(zm),x);                    /* tmp = x + mask*q */
    cczp_modn_ws(ws, zu_masked, tmp, cczp_n(zm)+1, tmp);            /* tmp = x + mask*q mod q_star */
    /* Ignoring error code; arguments guaranteed to be valid. */
    status=cczp_mm_power_ws(ws, zu_masked, sq, tmp, cczp_bitlen(zq) + SCA_MASK_BITSIZE, tmp2); /* sq = (tmp ^ dq) mod q_star */
    cc_assert(status==0);(void) status; // Public key validation will follow, we don't want to early abort here.

    /*
        Modulus blinding:   p_star = rnd[3]*p
        Exponent blinding: dp_star = dp + rnd[4]*(p-1)
        Base blinding:     mp_star = (x + rnd[5]*p) Mod p_star
    */

    /* p_star:=p*cstp; */
    CCZP_N(zu_masked)=np+SCA_MASK_N;
    *(CCZP_PRIME(zu_masked)+np)=ccn_mul1(np,CCZP_PRIME(zu_masked),cczp_prime(zp),SCA_MASK_MASK & (rnd[3] | 1)); /* p_star:=p*cstp; */
    cc_require((status=cczp_init_ws(ws, zu_masked)) == CCERR_OK, errOut);

    /* mp = m + k1.p mod p_star */
    ccn_setn(cczp_n(zm)+1,tmp,np,cczp_prime(zp)); // p
    ccn_set_bit(tmp,0,0);  // p - 1
    ccn_set(np,tmp2,dp);   // dp
    tmp2[np]=ccn_addmul1(np,tmp2,tmp,SCA_MASK_MASK & rnd[4]);          /* tmp2 = dp + rnd*(p-1) */
    tmp[np]=ccn_mul1(np, tmp, cczp_prime(zp), SCA_MASK_MASK & rnd[5]); /* tmp = mask*p */
    ccn_addn(cczp_n(zm)+1,tmp, tmp,cczp_n(zm), x);                     /* tmp = x + mask*p */
    cczp_modn_ws(ws, zu_masked, tmp, cczp_n(zm)+1, tmp);               /* tmp = x + mask*p mod p_star */
    /* Ignoring error code; arguments guaranteed to be valid. */
    status=cczp_mm_power_ws(ws, zu_masked, sp, tmp, cczp_bitlen(zp) + SCA_MASK_BITSIZE, tmp2); /* sp = (tmp ^ dp) mod p_star */
    cc_assert(status==0);(void) status; // Public key validation will follow, we don't want to early abort here.

    /*------------ Step 2 ------------------\n
     Garner recombination (requires 2*p>q, which is verified if |p|==|q|)
        with 0 < cstp,cstq < SCA_MASK
        pstar*(2*SCA_MASK) > q*SCA_MASK >= qstar

        Values remain randomized as long as possible to protect all the operations
        tmp = (sp+(2*SCA_MASK)*p_star)-sq mod p_star
        tmp = tmp * qInv mod p_star
        tmp = tmp * q
        tmp = tmp + sq
        r = tmp mod n     Finally removes the randomization
    */
    ccn_setn(nu+2, tmp, nu, cczp_prime(zu_masked));
    ccn_shift_left_multi(nu+2, tmp, tmp, SCA_MASK_BITSIZE+1);   // 2*SCA_MASK_MASK*cstp*p
    ccn_addn(nu+2,tmp,tmp,nu,sp);                               // 2*SCA_MASK_MASK*cstp*p + sp
    cc_unit c = ccn_subn(nu+2, tmp, tmp, nq+SCA_MASK_N, sq);    // tmp: t = (sp + (2*SCA_MASK_MASK)*p_star) - sq
    cc_assert(c==0);(void)c;                    // Sanity check that there is no borrow
    cczp_modn_ws(ws, zu_masked, sp, nu+2, tmp); // sp: = t mod p_star
    ccn_setn(nu, tmp, np, qinv);                // handle nq < np
    cczp_mul_ws(ws, zu_masked, sp, sp, tmp);    // sp: t = (sp * qinv) mod p_star
    ccn_setn(nu, tmp2, nq, cczp_prime(zq));     // tmp2: q

    ccn_mul_ws(ws,nu, tmp, tmp2, sp);             // tmp: t = t * q
    ccn_addn(2*nu, tmp, tmp, nq+SCA_MASK_N, sq);  // tmp: t = t + sq
    cczp_modn_ws(ws, zm, r, 2*nu, tmp);           // r: t mod m
    status=0;

errOut:
    CC_FREE_BP_WS(ws, bp);
    sp=NULL; /* Analyser warning */
    return status;
}

int ccrsa_priv_crypt_blinded_ws(cc_ws_t ws,
                                struct ccrng_state *blinding_rng,
                                ccrsa_full_ctx_t fk,
                                cc_unit *out,
                                const cc_unit *in)
{
    int cond;

    cc_size n = ccrsa_ctx_n(fk);
    cc_size np = cczp_n(ccrsa_ctx_private_zp(fk));
    cc_size nq = cczp_n(ccrsa_ctx_private_zq(fk));

    // Reject dp=1 or dq=1 as a valid key because e=1 is not acceptable.
    // by definition dp*e=1 mod (p-1) and dq*e=1 mod (p-1)
    if ((ccn_bitlen(np, ccrsa_ctx_private_dp(fk)) <= 1)
        || (ccn_bitlen(nq, ccrsa_ctx_private_dq(fk)) <= 1)
        || (ccn_bitlen(n, ccrsa_ctx_e(fk)) <= 1)) {
        return CCRSA_KEY_ERROR;
    }

    // x >= m is not a valid input
    if (ccn_cmp(n, in, ccrsa_ctx_m(fk)) >= 0) {
        return CCRSA_INVALID_INPUT;
    }

    CC_DECL_BP_WS(ws, bp);
    cc_unit *tmp = CC_ALLOC_WS(ws, n);
    cc_unit *tmp_in = CC_ALLOC_WS(ws, n);
    ccn_set(n, tmp_in, in);

    // Compute out := in^d (mod m).
    int status = ccrsa_crt_power_blinded_ws(ws, blinding_rng, fk, out, in);

    // Verify that the computation is correct.
    (void)cczp_mm_power_fast_ws(ws, ccrsa_ctx_zm(fk), tmp, out, ccrsa_ctx_e(fk));

    // status_compare := (tmp != tmp_in) ? CCRSA_PRIVATE_OP_ERROR : 0
    CC_HEAVISIDE_STEP(cond, ccn_cmp(n, tmp, tmp_in));
    int status_compare = -cond & CCRSA_PRIVATE_OP_ERROR;

    // status := status ? status : status_compare
    CC_HEAVISIDE_STEP(cond, status);
    status |= (cond - 1) & status_compare;

    // Clear output on error.
    // out := status ? 0xAAAAAA... : out
    cc_memset(tmp_in, 0xAA, ccn_sizeof_n(n));
    CC_HEAVISIDE_STEP(cond, status);
    ccn_mux(n, (cc_unit)cond, out, tmp_in, out);

    CC_FREE_BP_WS(ws, bp);
    return status;
}

/* Copyright (c) (2011,2014,2015,2016,2018,2019,2020) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "ccdh_internal.h"
#include "cctest.h"
#include "testmore.h"
#include "crypto_test_dh.h"

int ccdh_test_compute_vector(const struct ccdh_compute_vector *v)
{
    int result,r1,r2;
    const cc_size n = ccn_nof(v->len);
    const size_t s = ccn_sizeof_n(n);
    unsigned char z[v->zLen];
    size_t zLen;
    unsigned char tmp[v->zLen]; // for negative testing
    uint32_t status=0;
    uint32_t nb_test=0;

    ccdh_gp_decl(s, gp);
    ccdh_full_ctx_decl(s, a);
    ccdh_full_ctx_decl(s, b);

    cc_unit p[n];
    cc_unit g[n];
    cc_unit q[n];

    // Bail to errOut when unexpected error happens.
    // Try all usecases otherwise

    if((result = ccn_read_uint(n, p, v->pLen, v->p)))
        goto errOut;
    if((result = ccn_read_uint(n, g, v->gLen, v->g)))
        goto errOut;
    if((result = ccn_read_uint(n, q, v->qLen, v->q)))
        goto errOut;

    ccdh_init_gp_with_order(gp, n, p, g, q);

    ccdh_ctx_init(gp, ccdh_ctx_public(a)); 
    ccdh_ctx_init(gp, ccdh_ctx_public(b));

    if((result=ccn_read_uint(n, ccdh_ctx_x(a), v->xaLen, v->xa))) // private key
        goto errOut;
    if((result=ccn_read_uint(n, ccdh_ctx_y(a), v->yaLen, v->ya))) // public key
        goto errOut;
    if((result=ccn_read_uint(n, ccdh_ctx_x(b), v->xbLen, v->xb))) // private key
        goto errOut;
    if((result=ccn_read_uint(n, ccdh_ctx_y(b), v->ybLen, v->yb))) // public key
        goto errOut;

    /*
     * Main test
     */

    /* try one side */
    zLen = v->zLen;
    r1=ccdh_compute_shared_secret(a, ccdh_ctx_public(b), &zLen,z,global_test_rng);
    r1|=!(zLen==v->zLen);
    r1|=memcmp(z, v->z, zLen);

    /* try the other side */
    zLen = v->zLen;
    r2=ccdh_compute_shared_secret(b, ccdh_ctx_public(a), &zLen,z,global_test_rng);
    r2|=!(zLen==v->zLen);
    r2|=memcmp(z, v->z, zLen);

    if ((!(r1||r2) && v->valid)||((r1||r2) && !v->valid))
    {
        status|=1<<nb_test;
    }
    nb_test++;

    // We are done if the test is not valid
    if (!v->valid) goto doneOut;

    /*
     * Corner case / negative testing
     * Only applicable for valid tests
     */

    /* Output is 1 (use private key is (p-1)/2)*/
    if((result=ccn_read_uint(n, ccdh_ctx_x(a), v->pLen, v->p))) // private key
        goto errOut;
    ccn_sub1(n,ccdh_ctx_x(a),ccdh_ctx_x(a),1);
    ccn_shift_right(n,ccdh_ctx_x(a),ccdh_ctx_x(a),1);
    zLen = v->zLen;
    if ((result=ccdh_compute_shared_secret(a, ccdh_ctx_public(b), &zLen,z,global_test_rng))!=0)
    {
        (void) result; // to read output with debugger
        status|=1<<nb_test;
    }
    if((result=ccn_read_uint(n, ccdh_ctx_x(a), v->xaLen, v->xa))) // restore private key
        goto errOut;
    nb_test++;
    
    
    /* negative testing (1 < y < p-1)*/
    /* public y = 0 */
    zLen = v->zLen;
    cc_clear(sizeof(tmp),tmp);
    if((result=ccn_read_uint(n, ccdh_ctx_y(b), zLen, tmp)))
    {
        (void) result; // to read output with debugger
        goto errOut;
    }
    if ((result=ccdh_compute_shared_secret(a, ccdh_ctx_public(b), &zLen,z,global_test_rng))!=0)
    {
        (void) result; // to read output with debugger
        status|=1<<nb_test;
    }
    nb_test++;

    /* public y = 1 */
    zLen = v->zLen;
    cc_clear(sizeof(tmp),tmp);
    tmp[zLen-1]=1;
    if((result=ccn_read_uint(n, ccdh_ctx_y(b), zLen, tmp)))
    {
        goto errOut;
    }
    if ((result=ccdh_compute_shared_secret(a, ccdh_ctx_public(b), &zLen,z,global_test_rng))!=0)
    {
        (void) result; // to read output with debugger
        status|=1<<nb_test;
    }
    nb_test++;

    /* public y = p */
    zLen = v->zLen;
    if((result=ccn_read_uint(n, ccdh_ctx_y(b), v->pLen, v->p)))
        goto errOut;

    if ((result=ccdh_compute_shared_secret(a, ccdh_ctx_public(b), &zLen,z,global_test_rng))!=0)
    {
        (void) result; // to read output with debugger
        status|=1<<nb_test;
    }
    nb_test++;

    /* public y = p-1 */
    zLen = v->zLen;
    if((result=ccn_read_uint(n, ccdh_ctx_y(b), v->pLen, v->p)))
    {
        (void) result; // to read output with debugger
        goto errOut;
    }
    ccn_sub1(n,ccdh_ctx_y(b),ccdh_ctx_y(b),1);

    if ((result=ccdh_compute_shared_secret(a, ccdh_ctx_public(b), &zLen,z,global_test_rng))!=0)
    {
        (void) result; // to read output with debugger
        status|=1<<nb_test;
    }
    nb_test++;

    /* 
     * When the order is in defined in the group 
     *  check that the implementation check the order of the public value:
     *      public y = g+1 (for rfc5114 groups, g+1 is not of order q)
     */
    zLen = v->zLen;
    if (ccdh_gp_order_bitlen(gp))
    {
        if((result=ccn_read_uint(n, ccdh_ctx_y(b), v->gLen, v->g)))
        {
            (void) result; // to read output with debugger
            goto errOut;
        }
        ccn_add1(n,ccdh_ctx_y(b),ccdh_ctx_y(b),1);

        if ((result=ccdh_compute_shared_secret(a, ccdh_ctx_public(b), &zLen,z,global_test_rng))!=0)
        {
            (void) result; // to read output with debugger
            status|=1<<nb_test;
        }
        nb_test++;
    }


    /* positive testing at the boundaries of (1 < y < p-1)*/

    // Don't set the order in gp because 2 and p-2 are not of order q
    ccdh_init_gp(gp, n, p, g, 0);

    /* public y = 2 */
    zLen = v->zLen;
    cc_clear(sizeof(tmp),tmp);
    tmp[zLen-1]=2;
    if((result=ccn_read_uint(n, ccdh_ctx_y(b), zLen, tmp)))
    {
        goto errOut;
    }
    if ((result=ccdh_compute_shared_secret(a, ccdh_ctx_public(b), &zLen,z,global_test_rng))==0)
    {
        (void) result; // to read output with debugger
        status|=1<<nb_test;
    }
    nb_test++;

    /* public y = p-2 */
    zLen = v->zLen;
    if((result=ccn_read_uint(n, ccdh_ctx_y(b), v->pLen, v->p)))
    {
        goto errOut;
    }
    ccn_sub1(n,ccdh_ctx_y(b),ccdh_ctx_y(b),2);

    if ((result=ccdh_compute_shared_secret(a, ccdh_ctx_public(b), &zLen,z,global_test_rng))==0)
    {
        (void) result; // to read output with debugger
        status|=1<<nb_test;
    }
    nb_test++;

    /* Negative testing: p is even */
    zLen = v->zLen;
    if((result=ccn_read_uint(n, p, v->pLen, v->p)))
        goto errOut;
    ccn_set_bit(p,0,0); // Set LS bit to 0
    ccdh_init_gp(gp, n, p, g, 0);
    ccdh_ctx_init(gp, ccdh_ctx_public(a));
    ccdh_ctx_init(gp, ccdh_ctx_public(b));

    if ((result=ccdh_compute_shared_secret(a, ccdh_ctx_public(b), &zLen,z,global_test_rng))!=0)
    {
        (void) result; // to read output with debugger
        status|=1<<nb_test;
    }
    nb_test++;

    /* Test aftermath */
doneOut:
    if ((nb_test==0) || (status!=((1<<nb_test)-1)))
    {
        result=1;
    }
    else
    {
        result=0; // Test is successful, Yeah!
    }

errOut:
    return result;
}

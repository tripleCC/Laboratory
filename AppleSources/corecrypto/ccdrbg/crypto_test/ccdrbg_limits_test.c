/* Copyright (c) (2015-2017,2019,2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/ccdrbg.h>
#include "cc_debug.h"
#include <corecrypto/ccaes.h>
#include <corecrypto/ccsha2.h>
#include <corecrypto/ccdrbg.h>
#include "testbyteBuffer.h"
#include <stdlib.h>
#include <limits.h>
#include "testmore.h"
#include "ccdrbg_test.h"
#include "cc_macros.h"


//very boring piece of code
typedef void (*ccdrbg_factory_t)(struct ccdrbg_info *,  void *);
#define ok2(cond, s) (ok((cond), (s))?0:-1)
static const char *s32 = "01234567890123456789012345678901";
static const int WHATEVER=5;

static int drbg_init_limits_test( ccdrbg_factory_t ccdrbg_factory, void *custom)
{
    struct ccdrbg_info drbg;
    int rc, rc2;
    struct ccdrbg_state *state;
    char *entropy=" ";
    char *nonce=" ";
    char *ps=" ";
    
    //too much entropy
    ccdrbg_factory(&drbg, custom);
    char b[drbg.size];     state = (struct ccdrbg_state *) b;
    rc = ccdrbg_init(&drbg, state, CCDRBG_MAX_ENTROPY_SIZE+1, entropy, WHATEVER, nonce, WHATEVER, ps);
    rc2 = ok2(rc!=0, "drbg init: max entropy length test failed");
    
    //too little entropy
    ccdrbg_factory(&drbg, custom);
    rc = ccdrbg_init(&drbg, state, 0, entropy, WHATEVER, nonce, WHATEVER, ps);
    rc2|=ok2(rc!=0, "drbg init: min entropy length test failed");

    //no test for nonce as it ias not checked.
    
    //too much PS
    ccdrbg_factory(&drbg, custom);
    rc = ccdrbg_init(&drbg, state, 32, s32, WHATEVER, nonce, CCDRBG_MAX_PSINPUT_SIZE+1, ps);
    rc2|=ok2(rc!=0, "drbg init: max personalization string length test failed");

    //NULL PS
    ccdrbg_factory(&drbg, custom);
    rc = ccdrbg_init(&drbg, state, 32, s32, WHATEVER, s32, 0, NULL);
    rc2|=ok2(rc==0, "drbg init: NULL personalization string  test failed");

    return rc2;
}

static int drbg_reseed_limits_test( ccdrbg_factory_t ccdrbg_factory, void *custom)
{
    struct ccdrbg_info drbg;
    int rc, rc2;
    struct ccdrbg_state *state;

    //init
    ccdrbg_factory(&drbg, custom);
    char b[drbg.size];     state = (struct ccdrbg_state *) b;
    rc = ccdrbg_init(&drbg, state, 32, s32, WHATEVER, s32, WHATEVER, s32);
    rc2 = ok2(rc==0, "drbg init failed");
    
    //too much entropy
    rc = drbg.reseed(state, CCDRBG_MAX_ENTROPY_SIZE+1, s32, WHATEVER, s32);
    rc2 |= ok2(rc!=0, "drbg reseed: max entropy length test failed");
    
    //too little entropy
    rc = drbg.reseed(state, 2, s32, WHATEVER, s32);
    rc2|=ok2(rc!=0, "drbg reseed: min entropy length test failed");
    
    
    //too much additional input
    rc = drbg.reseed(state, 32, s32, CCDRBG_MAX_ADDITIONALINPUT_SIZE+1, s32);
    rc2|=ok2(rc!=0, "drbg reseed: max personalization string length test failed");
    
    //reseed with NULL additional input
    rc = drbg.reseed(state, 32, s32, 0, NULL);
    rc2|=ok2(rc==0, "drbg reseed: NULL personalization string  test failed");
    
    return rc2;
}

static int drbg_generate_limits_test( ccdrbg_factory_t ccdrbg_factory, void *custom)
{
    struct ccdrbg_info drbg;
    int rc, rc2;
    struct ccdrbg_state *state;
    char out[1024];
    uint64_t v1,v2;
    uint64_t v12[2];
    
    ccdrbg_factory(&drbg, custom);
    char b[drbg.size];     state = (struct ccdrbg_state *) b;

    // one chunk 8 bytes
    rc = ccdrbg_init(&drbg, state, 32, s32, WHATEVER, s32, WHATEVER, s32);
    rc2 = ok2(rc==0, "drbg init failed");
    rc = ccdrbg_generate(&drbg,state, sizeof(v12), v12, WHATEVER, s32);
    rc2|=ok2(rc==0, "drbg generate: input 8 failed");

    // Same as 2x 4bytes must not be the same as single shot 8bytes.
    rc = ccdrbg_init(&drbg, state, 32, s32, WHATEVER, s32, WHATEVER, s32);
    rc2 |= ok2(rc==0, "drbg init failed");
    rc = ccdrbg_generate(&drbg,state, sizeof(v1), &v1, WHATEVER, s32);
    rc2|=ok2(rc==0, "drbg generate: input 4 failed");
    rc = ccdrbg_generate(&drbg,state, sizeof(v2), &v2, WHATEVER, s32);
    rc2|=ok2(rc==0, "drbg generate: input 4 failed");
    rc2|=ok2((v1==v12[0]) && (v2!=v12[1]), "drbg generate must differ");

    // Generate with 0 byte is supported, it does not return any bytes
    // but it updates the internal state
    rc = ccdrbg_init(&drbg, state, 32, s32, WHATEVER, s32, WHATEVER, s32);
    rc2 |= ok2(rc==0, "drbg init failed");
    rc = ccdrbg_generate(&drbg,state, 0, NULL, WHATEVER, s32);
    rc2|=ok2(rc==0, "drbg generate: input 0 failed");
    rc = ccdrbg_generate(&drbg,state, sizeof(v12), out, WHATEVER, s32);
    rc2|=ok2(rc==0, "drbg generate: input 4 failed");
    rc2|=ok2(memcmp(v12,out,sizeof(v12))!=0, "drbg generate must differ");

    // Output too big, check for error
    rc = ccdrbg_generate(&drbg,state, CCDRBG_MAX_REQUEST_SIZE+1, out, WHATEVER, s32);
    rc2|=ok2(rc!=0, "drbg generate: maximum input len failed");

    // Personalization string is too big, check for error
    rc = ccdrbg_generate(&drbg,state, 16, out, CCDRBG_MAX_PSINPUT_SIZE+1, s32);
    rc2|=ok2(rc!=0, "drbg generate: max personalization string length test failed");

    return rc2;
}

static uint32_t largest(uint32_t a, uint32_t b, uint32_t c)
{
   if( a>b && a>c )
       return a;
    if(b>c)
        return b;
    else
        return c;
}

static int drbg_stress_test( ccdrbg_factory_t ccdrbg_factory, void *custom)
{

    struct ccdrbg_info drbg;
    int rc=-1;
    struct ccdrbg_state *state;
    char *buf, *out;
    out=buf=NULL;
    
    ccdrbg_factory(&drbg, custom);
    char b[drbg.size]; state = (struct ccdrbg_state *) b;
    
    uint32_t n = largest(CCDRBG_MAX_ENTROPY_SIZE, CCDRBG_MAX_ADDITIONALINPUT_SIZE, CCDRBG_MAX_PSINPUT_SIZE);
    cc_assert(n <((uint32_t)1<<30));
    buf = malloc(n); cc_require(buf!=NULL, end);
    out = malloc(CCDRBG_MAX_REQUEST_SIZE); cc_require(out!=NULL, end);
    
    rc = ccdrbg_init(&drbg, state, CCDRBG_MAX_ENTROPY_SIZE-1, buf, CCDRBG_MAX_ENTROPY_SIZE-1, buf, CCDRBG_MAX_PSINPUT_SIZE-1, buf);
    rc |= ccdrbg_generate(&drbg,state, CCDRBG_MAX_REQUEST_SIZE-1, out, CCDRBG_MAX_ADDITIONALINPUT_SIZE-1, buf);
    rc |= drbg.reseed  (state, CCDRBG_MAX_ENTROPY_SIZE-1, buf, CCDRBG_MAX_ADDITIONALINPUT_SIZE-1, buf);
    rc |= ccdrbg_generate(&drbg,state, CCDRBG_MAX_REQUEST_SIZE-1, out, CCDRBG_MAX_ADDITIONALINPUT_SIZE-1, buf);
    
end:
    free(buf);
    free(out);
    
    return rc;
}

static int drbg_all_limits_test( ccdrbg_factory_t ccdrbg_factory, void *custom)
{
    int rc;
    
    rc =  drbg_init_limits_test(ccdrbg_factory, custom);
    rc |= drbg_generate_limits_test(ccdrbg_factory, custom);
    rc |= drbg_reseed_limits_test(ccdrbg_factory, custom);
    ok(rc==0, "drbg limit test failed");
    
    rc = drbg_stress_test(ccdrbg_factory, custom);
    ok(rc==0, "drbg stress tst failed");
    
    return rc;
}

int ccdrbg_limits_test(void)
{
    int rc;

    ccdrbg_df_bc_ctx_t df_ctx;
    rc = ccdrbg_df_bc_init(&df_ctx,
                           ccaes_cbc_encrypt_mode(),
                           16);
    struct ccdrbg_nistctr_custom ctr_custom = {
        .ctr_info = ccaes_ctr_crypt_mode(),
        .keylen = 16,
        .strictFIPS = 1,
        .df_ctx = (ccdrbg_df_ctx_t *)&df_ctx,
    };
    
    struct ccdrbg_nisthmac_custom mac_custom = {
        .di = ccsha256_di(),
        .strictFIPS = 1,
    };

#if CORECRYPTO_DEBUG
    diag("Negative test");
#endif
    // generates 3 error messages"
    rc |= drbg_all_limits_test((ccdrbg_factory_t)ccdrbg_factory_nistctr,  &ctr_custom);
    rc |= drbg_all_limits_test((ccdrbg_factory_t)ccdrbg_factory_nisthmac, &mac_custom);

#if CORECRYPTO_DEBUG
    diag("End of negative tests");
#endif

    return rc;
}





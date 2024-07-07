/* Copyright (c) (2019-2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "testmore.h"
#include "testbyteBuffer.h"
#include "testccnBuffer.h"
#include "cc_debug.h"

#if (CCHPKE == 0)
entryPoint(cchpke_tests, "cchpke test")
#else
#include <corecrypto/cchpke_priv.h>
#include <corecrypto/ccrng.h>
#include <corecrypto/cc_priv.h>
#include <corecrypto/cchpke_priv.h>
#include "cchpke_internal.h"
#include "cc_priv.h"

static void cchpke_kat(void)
{
    int result;
    struct ccrng_state *rng = global_test_rng;
    cchpke_const_params_t params = cchpke_params_x25519_AESGCM128_HKDF_SHA256();
    
    struct cchpke_initiator initiator;
    memset(&initiator, 0, sizeof(initiator));
    struct cchpke_inner_context *inner_context = (struct cchpke_inner_context *)(&initiator.context);
    
    struct cchpke_responder responder;
    memset(&responder, 0, sizeof(responder));
    
    byteBuffer info = hexStringToBytes("4f6465206f6e2061204772656369616e2055726e");
    byteBuffer skEm = hexStringToBytes("ee9fcf08d07241b13b93f2cf6dbdd56f94e940d788c3e4c860f757a08974a883");
    byteBuffer pkEm = hexStringToBytes("890e346283bf75af9d786a526c4a191b84d0110c794b6aa7e9a0b6205fe2c10c");
    byteBuffer skRm = hexStringToBytes("c867f27c253f720c7074f9b4a495f2c690060629e249f86991bb55edf804f7bd");
    byteBuffer pkRm = hexStringToBytes("8bd766c487fa9266ce3ac898827439aea2fa9c0099ab62da954b06f979f2141b");
    byteBuffer enc_kat = hexStringToBytes("890e346283bf75af9d786a526c4a191b84d0110c794b6aa7e9a0b6205fe2c10c");
    byteBuffer key_kat = hexStringToBytes("96d0b503c045e18f6e9f62a52d7f59d2");
    byteBuffer base_nonce = hexStringToBytes("aa39425b7270fcaf1c7b69ec");
    byteBuffer exporter_secret = hexStringToBytes("304296751e7583846d4ec1d49f78b511dee838a32e18dd1bfa44a30a1c1012e0");
    
    uint8_t enc[cchpke_params_sizeof_kem_enc(params)];
    
    result = cchpke_initiator_setup_deterministic(&initiator, params, rng,
                                                  skEm->len, skEm->bytes,
                                                  pkEm->len, pkEm->bytes,
                                                  pkRm->len, pkRm->bytes,
                                                  info->len, info->bytes,
                                                  sizeof(enc), enc);
    is(result, CCERR_OK, "hpke setup initiator");
    ok_memcmp(enc, enc_kat->bytes, enc_kat->len, "enc kat");
    ok_memcmp(inner_context->key, key_kat->bytes, key_kat->len, "key kat");
    ok_memcmp(inner_context->nonce, base_nonce->bytes, base_nonce->len, "base_nonce kat");
    ok_memcmp(inner_context->exporter_secret, exporter_secret->bytes, exporter_secret->len, "exp secret kat");
    
    result = cchpke_responder_setup(&responder, params, skRm->len, skRm->bytes, info->len, info->bytes, sizeof(enc), enc);
    is(result, CCERR_OK, "hpke setup responder");
    
    byteBuffer pt1 = hexStringToBytes("4265617574792069732074727574682c20747275746820626561757479");
    byteBuffer aad1 = hexStringToBytes("436f756e742d30");
    byteBuffer ct1 = hexStringToBytes("1d2ae93bff2fc322a909669c94372cdd2ac0da261face2a706e417a952272f6e5eaa20d0cd15fc28ee52026c4d");
    
    uint8_t pt1_out[pt1->len];
    uint8_t ct1_out[ct1->len - 16];
    uint8_t tag_out[16];
    
    result = cchpke_initiator_encrypt(&initiator, aad1->len, aad1->bytes, pt1->len, pt1->bytes, ct1_out, sizeof(tag_out), tag_out);
    is(result, CCERR_OK, "hpke encrypt");
    ok_memcmp(ct1_out, ct1->bytes, ct1->len - 16, "ct1");
    ok_memcmp(tag_out, ct1->bytes + ct1->len - 16, 16, "tag1");
    
    result = cchpke_responder_decrypt(&responder, aad1->len, aad1->bytes, ct1->len - 16, ct1_out, 16, tag_out, pt1_out);
    is(result, CCERR_OK, "hpke decrypt");
    ok_memcmp(pt1_out, pt1->bytes, pt1->len, "pt1");
    
    uint8_t export_secret_context[8] = {0,1,2,3,4,5,6,7};
    uint8_t export_secreti[32];
    uint8_t export_secretr[32];
    
    result = cchpke_initiator_export(&initiator, sizeof(export_secret_context), export_secret_context, sizeof(export_secreti), export_secreti);
    is(result, CCERR_OK, "hpke initiator export");
    result = cchpke_responder_export(&responder, sizeof(export_secret_context), export_secret_context, sizeof(export_secretr), export_secretr);
    is(result, CCERR_OK, "hpke initiator export");
    ok_memcmp(export_secreti, export_secretr, sizeof(export_secreti), "export secret1");
    
    // Test one-shot
    
    result = cchpke_initiator_seal(params, rng, pkRm->len, pkRm->bytes, info->len, info->bytes,
                                   aad1->len, aad1->bytes,
                                   pt1->len, pt1->bytes,
                                   ct1_out, 16, tag_out,
                                   sizeof(enc), enc);
    is(result, CCERR_OK, "hpke oneshot initiator");
    
    result = cchpke_responder_open(params, skRm->len, skRm->bytes, info->len, info->bytes, aad1->len, aad1->bytes, sizeof(ct1_out), ct1_out, 16, tag_out, sizeof(enc), enc, pt1_out);
    is(result, CCERR_OK, "hpke oneshot responder");
    ok_memcmp(pt1_out, pt1->bytes, pt1->len, "pt1");
    
    result = cchpke_initiator_export(&initiator, sizeof(export_secret_context), export_secret_context, sizeof(export_secreti), export_secreti);
    is(result, CCERR_OK, "hpke initiator export");
    result = cchpke_responder_export(&responder, sizeof(export_secret_context), export_secret_context, sizeof(export_secretr), export_secretr);
    is(result, CCERR_OK, "hpke initiator export");
    ok_memcmp(export_secreti, export_secretr, sizeof(export_secreti), "export secret1");

    free(pt1);
    free(aad1);
    free(ct1);
    
    free(info);
    free(skEm);
    free(pkEm);
    free(skRm);
    free(pkRm);
    free(enc_kat);
    free(key_kat);
    free(base_nonce);
    free(exporter_secret);
    
}

int cchpke_tests(TM_UNUSED int argc, TM_UNUSED char *const *argv)
{
    plan_tests(20);
    cchpke_kat();
    return 0;
}
#endif // (CCHPKE != 0)


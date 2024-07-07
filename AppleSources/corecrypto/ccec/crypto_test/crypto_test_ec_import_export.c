/* Copyright (c) (2014-2016,2018-2023) Apple Inc. All rights reserved.
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

#include <corecrypto/ccder.h>
#include <corecrypto/ccrng.h>
#include <corecrypto/ccrng_ecfips_test.h>
#include <corecrypto/ccec.h>
#include <corecrypto/ccec_priv.h>
#include "cc_macros.h"
#include "crypto_test_ec.h"
#include "crypto_test_ec_import_export.h"
#include "ccec_internal.h"
#include <corecrypto/ccn.h>
#include <corecrypto/cc_error.h>

static ccoid_t ccoid_secp192r1 = CC_EC_OID_SECP192R1;
static ccoid_t ccoid_secp256r1 = CC_EC_OID_SECP256R1;
static ccoid_t ccoid_secp521r1 = CC_EC_OID_SECP521R1;

static void
signVerify(ccec_full_ctx_t full, ccec_pub_ctx_t public, const char * CC_UNUSED name, struct ccrng_state *rng)
{
    size_t siglen = ccec_sign_max_size(ccec_ctx_cp(full));
    uint8_t sig[siglen];
    uint8_t digest[24] = "012345678912345678901234";

    ok(siglen > sizeof(digest), "siglen large enough");

    siglen = sizeof(sig);
    is(ccec_sign(full, sizeof(digest), digest,
                             &siglen, sig, rng), 0, "ccec_sign failed");
    bool valid;
    is(ccec_verify(public, sizeof(digest), digest, siglen, sig, &valid),
                   0, "ccec_verify failed");
    ok(valid, "ecdsa_verify ok");
    is(ccec_verify_strict(public, sizeof(digest), digest, siglen, sig, &valid), 0, "ccec_verify_strict failed");
    ok(valid, "ecdsa_verify_strict ok");
    
}

static void doImportKeyTypeCheck(const char* der_key_string)
{
    byteBuffer fullkey_der = hexStringToBytes(der_key_string);

    const unsigned char oid_buffer[256];
    ccoid_t oid = oid_buffer;
    size_t n;
    int import_result = ccec_der_import_priv_keytype(fullkey_der->len, fullkey_der->bytes, &oid, &n);
    ok(import_result == 0, "ccec_der_import_priv_keytype for valid key failed. Expected 0, got %d", import_result);

    free(fullkey_der);
}

static void doExportImportDER_oneKAT(ccec_const_cp_t cp,struct ccrng_state *rng, const char* der_key_string)
{
    ccec_full_ctx_decl_cp(cp, full);
    ccec_full_ctx_decl_cp(cp, full2);

    byteBuffer fullkey_der = hexStringToBytes(der_key_string);

    is(ccec_der_import_priv(cp, fullkey_der->len, fullkey_der->bytes, full), CCERR_OK, "ccec_der_import_priv");
    byteBuffer fullkey_der_bis = mallocByteBuffer(ccec_der_export_priv_size(full, NULL, 1));
    is(ccec_der_export_priv(full, NULL, 1, fullkey_der_bis->len, fullkey_der_bis->bytes), CCERR_OK, "ccec_export_priv(NULL, 1) 2");
    is(ccec_der_import_priv(cp, fullkey_der_bis->len, fullkey_der_bis->bytes, full2), CCERR_OK, "ccec_der_import_priv");

    ok(fullkey_der->len == fullkey_der_bis->len, "key size same");
    ok_memcmp(fullkey_der->bytes, fullkey_der_bis->bytes, fullkey_der->len, "der key same");

    signVerify(full, ccec_ctx_pub(full), "Imported key working", rng);    // If this pass, import was working
    signVerify(full2, ccec_ctx_pub(full2), "Re-imported key working", rng);

    free(fullkey_der);
    free(fullkey_der_bis);
}

static void doExportImportDER_KATs(struct ccrng_state *rng)
{
    const char *randomDer = "30530201010418670902dd80999724dcf751f2bc2c340fb6f377312be93736a1340332000403a731d8bd0c192c8b732e887b4d69c852f9a583a2bbc37a73d7f46ae34c30880d0253193bb43eb33d1265a7379daac5";
    const char *derWithLeading0InK = "3053020101041800f9cab2200806e4b51b23fa85cf258c67ab5839015f9667a13403320004f360dac619f7a286a84a84b9b7b9c586fe466ec06a61a2d4f4818fefd9ea2f521cd38677013a26909942261eaf5a586b";
    const char *derWithLeading0InX = "305302010104182c3dfc53cba9a38028e89ffc1c1a390cf3218e284c792326a1340332000400d62388a47dbd308fa7810f45897da581b9b4e9565708de216e54ae118363544fd55e4be8980e61f1206d4608c5e804";
    const char *derWithLeading0InY = "306b020101042086877959d1c63c502430a4af891dd194235679469372313924e60196c8ebf388a144034200048cfad78af1b9add73a33b59aad520d14d66b355679d6742a377e2f33a6abee35007082899cfc97c4895c1650ad6055a670ee071bfee4f0a063c07324979204c7";

    doImportKeyTypeCheck(randomDer);
    doImportKeyTypeCheck(derWithLeading0InK);
    doImportKeyTypeCheck(derWithLeading0InX);
    doImportKeyTypeCheck(derWithLeading0InY);

    doExportImportDER_oneKAT(ccec_cp_192(), rng, randomDer);
    doExportImportDER_oneKAT(ccec_cp_192(), rng, derWithLeading0InK);
    doExportImportDER_oneKAT(ccec_cp_192(), rng, derWithLeading0InX);
    doExportImportDER_oneKAT(ccec_cp_256(), rng, derWithLeading0InY);
}

#if defined(_WIN32)
#include <stdarg.h>

int asprintf(char **str, const char *format, ...)
{
	char *rb = NULL;
	if (format==NULL) return 0;

	va_list args;
	va_start(args, format);
	int size = _vscprintf(format, args);

	if (size > 0) {
		rb = malloc(size+1);
		if (rb!=NULL) _vsnprintf(rb, size, format, args);
	}

	va_end(args);
	*str = rb;
	return size;
}
#endif

static void
doExportImportDER(ccec_const_cp_t cp, ccoid_t oid, const char *name, struct ccrng_state *rng)
{
    char *testname;
    size_t size;

    ccec_full_ctx_decl_cp(cp, full);
    ccec_full_ctx_decl_cp(cp, full2);

    is(ccec_generate_key_fips(cp, rng, full),0,"Generate key");

    signVerify(full, ccec_ctx_pub(full), name, rng);

    /*
     * no oid, with public
     */

    asprintf(&testname, "no oid, public: %s", name);

    size = ccec_der_export_priv_size(full, (ccoid_t){ NULL }, 1);
    uint8_t public[size], public2[size];
    ok(ccec_der_export_priv(full, (ccoid_t){ NULL }, 1, size, public) == 0, "ccec_export_priv(NULL, 1)");
    ok(ccec_der_import_priv(cp, size, public, full2) == 0, "ccec_der_import_priv");
    ok(ccec_der_export_priv(full2, (ccoid_t){ NULL }, 1, size, public2) == 0, "ccec_export_priv(NULL, 1) 2");

    ok_memcmp(public, public2, size, "key same");

    if (   ccn_cmp(ccec_cp_n(cp),
                   ccec_ctx_k(full),
                   ccec_ctx_k(full2))
        || ccn_cmp(ccec_cp_n(cp), ccec_ctx_x(full), ccec_ctx_x(full2))
        || ccn_cmp(ccec_cp_n(cp), ccec_ctx_y(full), ccec_ctx_y(full2))
        || ccn_cmp(ccec_cp_n(cp), ccec_ctx_z(full), ccec_ctx_z(full2)))
    {
        ccec_print_full_key("Generated key",full);
        ccec_print_full_key("Reconstructed key",full2);
        cc_print("Exported public key", sizeof(public),public);
        ok(false, "key reconstruction mismatch");
    }

    signVerify(full , ccec_ctx_pub(full2), testname, rng);
    signVerify(full2, ccec_ctx_pub(full) , testname, rng);
    signVerify(full2, ccec_ctx_pub(full2), testname, rng);

    free(testname);

    /*
     * no oid, no public
     */

    asprintf(&testname, "no oid, no public: %s", name);

    size = ccec_der_export_priv_size(full, (ccoid_t){ NULL }, 0);
    uint8_t nopublic[size];
    ok(ccec_der_export_priv(full, (ccoid_t){ NULL }, 0, size, nopublic) == 0, "ccec_export_priv(NULL, 0)");

    ok(ccec_der_import_priv(cp, size, nopublic, full2) == 0, "ccec_der_import_priv");

    signVerify(full2, ccec_ctx_pub(full), testname, rng);
    signVerify(full, ccec_ctx_pub(full2), testname, rng);
    signVerify(full2, ccec_ctx_pub(full2), testname, rng);

    free(testname);

    /*
     * oid, no public
     */

    asprintf(&testname, "oid, no public:: %s", name);

    size = ccec_der_export_priv_size(full, oid, 0);
    uint8_t nopublicoid[size];
    ok(ccec_der_export_priv(full, oid, 0, size, nopublicoid) == 0, "ccec_export_priv(oid, 0)");
    
    ok(ccec_der_import_priv(cp, size, nopublicoid, full2) == 0, "ccec_der_import_priv");

    signVerify(full2, ccec_ctx_pub(full), testname, rng);
    signVerify(full, ccec_ctx_pub(full2), testname, rng);
    signVerify(full2, ccec_ctx_pub(full2), testname, rng);

    free(testname);

}

static ccec_const_cp_t ccec_cp_for_oid(ccoid_t oid)
{
    if (ccoid_equal(oid, ccoid_secp192r1)) {
        return ccec_cp_192();
    } else if (ccoid_equal(oid, ccoid_secp256r1)) {
        return ccec_cp_256();
    } else if (ccoid_equal(oid, ccoid_secp521r1)) {
        return ccec_cp_521();
    }
    return (ccec_const_cp_t){NULL};
}

static void testImportDEROIDOnly(void)
{
    ccoid_t oid;
    size_t n;
    ccec_const_cp_t cp;

    is(0, ccec_der_import_priv_keytype(key_bin_oid_only_len, key_bin_oid_only, &oid, &n), "ccec_der_import_priv_keytype() == 0");

    cp = ccec_cp_for_oid(oid);
    ccec_full_ctx_decl_cp(cp, full); ccec_ctx_init(cp, full); // declaration initializes with cp as well

    ok((ccec_cp_zp(cp)), "bad oid");
    is(0, ccec_der_import_priv(cp, key_bin_oid_only_len, key_bin_oid_only, full), "ccec_der_import_priv() == 0");

    size_t size = ccec_der_export_priv_size(full, oid, 0);
    ok(size == key_bin_oid_only_len, "key same size");

    uint8_t exp[size];
    is(0, ccec_der_export_priv(full, oid, 0, size, exp), "ccec_export_priv(oid, 0)");

    ok_memcmp(exp, key_bin_oid_only, size, "key same");
}

static void testImportDERPrivOnly(void)
{
    ccoid_t oid;
    size_t n;
    ccec_const_cp_t cp;

    is(0, ccec_der_import_priv_keytype(key_bin_priv_only_len, key_bin_priv_only, &oid, &n), "ccec_der_import_priv_keytype() == 0");
    is(NULL, CCOID(oid), "no oid in imported private key type");

    cp = ccec_curve_for_length_lookup(n * 8 /* bytes -> bits */,
                                      ccec_cp_192(), ccec_cp_224(), ccec_cp_256(), ccec_cp_384(), ccec_cp_521(), NULL);
    ccec_full_ctx_decl_cp(cp, full); ccec_ctx_init(cp, full);

    if (cp) {
        ok(cp == ccec_cp_256(), "bad oid: oid should correspond to P256 curve");
    }
    else{
        ok(cp, "failed to allocate cp in test_importDERPrivOlnly");
    }
    is(0, ccec_der_import_priv(cp, key_bin_priv_only_len, key_bin_priv_only, full), "ccec_der_import_priv() == 0");

    size_t size = ccec_der_export_priv_size(full, oid, 0);
    is(size, key_bin_priv_only_len, "key same size");

    uint8_t exp[size];
    is(0, ccec_der_export_priv(full, oid, 0, size, exp), "ccec_export_priv(NULL, 0)");

    ok_memcmp(exp, key_bin_priv_only, size, "key same");
}

static void testBareCompressed(void)
{
    ccec_const_cp_t cp = ccec_cp_256();
    ccec_pub_ctx_decl_cp(cp, pub_comp);
    ccec_ctx_init(cp, pub_comp);
    uint8_t compressed_key[ccec_compressed_x962_export_pub_size(cp)];
    // Verify that known corresponding p256 compressed/uncompressed keys match
    is(ccec_compressed_x962_import_pub(cp, CC_ARRAY_LEN(key_pubComp_p256), key_pubComp_p256, pub_comp),
       CCERR_OK,
       "Failed to import proper compressed p256 key");
    ccec_pub_ctx_decl_cp(cp, pub_uncomp);
    ccec_ctx_init(cp, pub_uncomp);
    is(ccec_x963_import_pub(cp, CC_ARRAY_LEN(key_pubunComp_p256), key_pubunComp_p256, pub_uncomp),
       CCERR_OK,
       "Failed to import proper uncompressed p256 key");
    ok_ccn_cmp(ccec_ctx_n(pub_comp),
               ccec_ctx_x(pub_comp),
               ccec_ctx_x(pub_uncomp),
               "X coordinates don't match between compressed and uncompressed p256 keys");
    ok_ccn_cmp(ccec_ctx_n(pub_comp),
               ccec_ctx_y(pub_comp),
               ccec_ctx_y(pub_uncomp),
               "Y coordinates don't match between compressed and uncompressed p256 keys");
    ok_ccn_cmp(ccec_ctx_n(pub_comp),
               ccec_ctx_z(pub_comp),
               ccec_ctx_z(pub_uncomp),
               "Z coordinates don't match between compressed and uncompressed p256 keys");
    is(ccec_x963_import_pub(cp, CC_ARRAY_LEN(compressed_unit_point), compressed_unit_point, pub_uncomp),
       CCEC_KEY_CANNOT_BE_UNIT,
       "Failed to reject point at infinity key");
    is(ccec_x963_import_pub(cp, CC_ARRAY_LEN(bad_compressed_unit_point), bad_compressed_unit_point, pub_uncomp),
       CCEC_COMPRESSED_POINT_ENCODING_ERROR,
       "Failed to detect improperly encoded point at infinity key");
    is(ccec_compressed_x962_import_pub(
           cp, CC_ARRAY_LEN(bad_length_compressed_p256_point), bad_length_compressed_p256_point, pub_uncomp),
       CCEC_COMPRESSED_POINT_ENCODING_ERROR,
       "Failed to reject improper length key");
    is(ccec_compressed_x962_import_pub(
           cp, CC_ARRAY_LEN(bad_prefix_compressed_p256_point), bad_prefix_compressed_p256_point, pub_uncomp),
       CCEC_COMPRESSED_POINT_ENCODING_ERROR,
       "Failed to reject improper prefix key");
    is(ccec_x963_import_pub(
           cp, CC_ARRAY_LEN(leading_zeros_compressed_p256_point), leading_zeros_compressed_p256_point, pub_uncomp),
       CCERR_OK,
       "Failed to import proper uncompressed p256 key");
    is(ccec_compressed_x962_export_pub(pub_uncomp, compressed_key) > 0,
       false,
       "reported padded 0s in error result in compressed key export key");
    is(ccec_compressed_x962_export_pub(pub_uncomp, compressed_key), CCERR_OK, "Failed to properly re-export valid key");
}

static void testInvalidPubkeyImport(void)
{
    ccec_const_cp_t cp = ccec_cp_256();
    
    // Attempt to import an invalid compressed p256 key
    ccec_pub_ctx_decl_cp(cp, pub_comp);
    ccec_ctx_init(cp, pub_comp);
    isnt(ccec_compressed_x962_import_pub(cp, CC_ARRAY_LEN(bogus_pub_compressed), bogus_pub_compressed, pub_comp),
         CCERR_OK,
       "Should fail to import invalid compressed p256 key");
    
    // Attempt to import an invalid key via x963_import_pub
    ccec_pub_ctx_decl_cp(cp, pub_x963);
    ccec_ctx_init(cp, pub_x963);
    isnt(ccec_x963_import_pub(cp, CC_ARRAY_LEN(bogus_pub_uncompressed), bogus_pub_uncompressed, pub_x963),
         CCERR_OK,
       "Should fail to import invalid uncompressed p256 key via x963_import_pub");
    
    // Attempt to import an invalid key via import_affine_point
    ccec_pub_ctx_decl_cp(cp, pub_affine);
    ccec_ctx_init(cp, pub_affine);
    isnt(ccec_import_affine_point(cp, CCEC_FORMAT_UNCOMPRESSED, CC_ARRAY_LEN(bogus_pub_uncompressed), bogus_pub_uncompressed, (ccec_affine_point_t)ccec_ctx_point(pub_affine)),
         CCERR_OK,
         "Should fail to import invalid uncompressed p256 key via import_affine_point");
    
    // Attempt to import an invalid key via import_pub
    ccec_pub_ctx_decl_cp(cp, pubkey);
    ccec_ctx_init(cp, pubkey);
    isnt(ccec_import_pub(cp, CC_ARRAY_LEN(bogus_pub_uncompressed), bogus_pub_uncompressed, pubkey),
         CCERR_OK,
         "Should fail to import invalid uncompressed p256 key via import_pub");

    // Attempt to import an 0-length key
    ccec_pub_ctx_decl_cp(cp, pubkey0);
    ccec_ctx_init(cp, pubkey0);
    const uint8_t *deadbeef = (const uint8_t*)0xdeadbeef;
    isnt(ccec_import_pub(cp, 0, deadbeef, pubkey0),
         CCERR_OK,
         "Should fail to import pub a zero-length buffer");

    // Attempt to import an 0-length point via import_affine_point
    ccec_pub_ctx_decl_cp(cp, pub_affine0);
    ccec_ctx_init(cp, pub_affine0);
    isnt(ccec_import_affine_point(cp, CCEC_FORMAT_COMPACT, 0, deadbeef, (ccec_affine_point_t)ccec_ctx_point(pub_affine0)),
         CCERR_OK,
         "Should fail to import a zero-length buffer as an affine point");
}

static void testCompressedGenAndDecode(ccec_const_cp_t cp,  struct ccrng_state *rng)
{
    ccec_full_ctx_decl_cp(cp, gen_key);
    ccec_pub_ctx_decl_cp(cp, decompressed_key);
    ccec_ctx_init(cp, gen_key);
    ccec_ctx_init(cp, decompressed_key);
    for (int i = 0; i < 10; i++) {
        uint8_t compressed_key[ccec_compressed_x962_export_pub_size(cp)];
        is (0, ccec_generate_key(cp, rng, gen_key), "Failed to generated ec key");
        is (true, (ccec_compressed_x962_export_pub(ccec_ctx_public(gen_key), compressed_key)>=0), "Failed to export compressed key");
        is (0, ccec_import_pub(cp, ccec_compressed_x962_export_pub_size(cp), compressed_key, decompressed_key), "Failed to import key generated by ccec_compressed_x963_export_pub");
        ok_ccn_cmp(ccec_ctx_n(gen_key),ccec_ctx_x(gen_key), ccec_ctx_x(decompressed_key), "X coordinates don't match between generated and compressed->uncompressed p256 keys");
        ok_ccn_cmp(ccec_ctx_n(gen_key),ccec_ctx_y(gen_key), ccec_ctx_y(decompressed_key), "Y coordinates don't match between generated and compressed->uncompressed p256 keys");
        ok_ccn_cmp(ccec_ctx_n(gen_key),ccec_ctx_z(gen_key), ccec_ctx_z(decompressed_key), "Z coordinates don't match between generated and compressed->uncompressed p256 keys");
    }
    
    // Test to ensure that we don't accept compressed points where x>=p, as per ANSI standard
    // Export prime p as x value in compressed point, and ensure it is not accepted.
    size_t bytes_for_p = ccec_cp_prime_size(cp) + 1;
    uint8_t encoded_p_buffer[bytes_for_p];
    encoded_p_buffer[0] = 0x02; //arbitrary side of the curve
    ccn_write_uint_padded(ccec_cp_n(cp), ccec_cp_p(cp), bytes_for_p - 1, encoded_p_buffer + 1);
    is (CCEC_COMPRESSED_POINT_ENCODING_ERROR, ccec_import_pub(cp, ccec_compressed_x962_export_pub_size(cp), encoded_p_buffer, decompressed_key), "Failed to recognize compressed point x value >= prime p");    
}

int ccec_import_export_tests(TM_UNUSED int argc, TM_UNUSED char *const *argv)
{
    plan_tests(546);
    struct ccrng_state *rng = global_test_rng;
    doExportImportDER_KATs(rng);
    doExportImportDER(ccec_cp_192(), ccoid_secp192r1, "secp192r1", rng);
    doExportImportDER(ccec_cp_256(), ccoid_secp256r1, "secp256r1", rng);
    testImportDEROIDOnly();
    testImportDERPrivOnly();
    testBareCompressed();
    testInvalidPubkeyImport();
    testCompressedGenAndDecode(ccec_cp_192(), rng);
    testCompressedGenAndDecode(ccec_cp_224(), rng);
    testCompressedGenAndDecode(ccec_cp_256(), rng);
    testCompressedGenAndDecode(ccec_cp_384(), rng);
    testCompressedGenAndDecode(ccec_cp_521(), rng);
    return 0;
}

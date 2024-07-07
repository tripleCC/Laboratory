/* Copyright (c) (2016,2017,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

// This files can be compiled with the Visual Studio C++ compiler
#include "stdafx.h"
#include <windows.h>
#include <stdio.h>
#include <malloc.h>

#pragma warning(disable:4003) //for the empty 'pre' parameter in __CCZP_ELEMENTS_DEFINITIONS()
#pragma warning(disable:4200) //zero - sized array in struct / union like in cczp

extern "C" {  
#include <corecrypto/ccn.h>
#include <corecrypto/ccrng_system.h>
#include <corecrypto/ccsha1.h>
#include <corecrypto/ccaes.h>
#include <corecrypto/ccder.h>
#include <corecrypto/ccder_decode_eckey.h>
#include <corecrypto/ccdh.h>
#include <corecrypto/ccdh_gp.h>
#include <corecrypto/ccdigest.h>
#include <corecrypto/ccdigest.h>
#include <corecrypto/ccec.h>
#include <corecrypto/ccecies.h>
#include <corecrypto/cchkdf.h>
#include <corecrypto/cchmac.h>
#include <corecrypto/ccmode.h>
#include <corecrypto/ccmode_factory.h>
#include <corecrypto/ccn.h>
#include <corecrypto/ccpbkdf2.h>
#include <corecrypto/ccrng.h>
#include <corecrypto/ccrng_pbkdf2_prng.h>
#include <corecrypto/ccrng_system.h>
#include <corecrypto/ccrsa.h>
#include <corecrypto/ccsha1.h>
#include <corecrypto/ccsha2.h>
#include <corecrypto/ccsrp.h>
#include <corecrypto/cczp.h>
#include <corecrypto/ccrng_drbg.h>
#include <corecrypto/ccdigest.h>
#include <corecrypto/ccaes.h>
#include <corecrypto/ccmode.h>
#include <corecrypto/ccec.h>
}

// Key in x9.63 format.
// Use the following command to generate the C array.
// echo "<key>" | xxd -r -p | xxd -i
/*
044d40a45e3d517c3b6bb2971c771811700ba2640d03a1c4985eb3af405a0aee6e8f7405aa4476fb8af8b540e5ebdbd84c70874fb6181461b09d203d44d043a131efcdab9078563412efcdab9078563412efcdab9078563412efcdab9078563412
*/

// SHA256('a')
// ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb
const uint8_t CC_ALIGNED(8) test_sha256_digest[] = {
	0xca, 0x97, 0x81, 0x12, 0xca, 0x1b, 0xbd, 0xca, 0xfa, 0xc2, 0x31, 0xb3,
	0x9a, 0x23, 0xdc, 0x4d, 0xa7, 0x86, 0xef, 0xf8, 0x14, 0x7c, 0x4e, 0x72,
	0xb9, 0x80, 0x77, 0x85, 0xaf, 0xee, 0x48, 0xbb
};

// AES
const uint8_t CC_ALIGNED(8) sample_key[] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
	0x0c, 0x0d, 0x0e, 0x0f }; // "000102030405060708090a0b0c0d0e0f";

const uint8_t CC_ALIGNED(8) sample_iv[] = {
	0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04,
	0x03, 0x02, 0x01, 0x00 }; // "0f0e0d0c0b0a09080706050403020100";

const uint8_t CC_ALIGNED(8) sample_pt[] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
// "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

const uint8_t CC_ALIGNED(8) sample_ct[] = {
	0x20, 0xa9, 0xf9, 0x92, 0xb4, 0x4c, 0x5b, 0xe8, 0x04, 0x1f, 0xfc, 0xdc,
	0x6c, 0xae, 0x99, 0x6a, 0xe4, 0x0e, 0x2d, 0x6f, 0x47, 0x62, 0xa0, 0xc5,
	0x84, 0x04, 0x2b, 0x8b, 0xd5, 0x34, 0x70, 0x4b, 0x8b, 0x9c, 0x1f, 0x12,
	0x37, 0x6c, 0x87, 0xfd, 0xb0, 0x8b, 0x35, 0x4e, 0x40, 0x41, 0x8f, 0x9d }; //
 // "20a9f992b44c5be8041ffcdc6cae996ae40e2d6f4762a0c584042b8bd534704b8b9c1f12376c87fdb08b354e40418f9d";

static int verbose = 1;

#define report(rc, s) { \
 if(verbose) diag(s); \
 ok((rc), "error");\
 test_rc |= (rc)?0 : -1; \
 }

#define diag(s) printf("\n"); printf(s)

static int test_ok(int passed, char *description, const char *file, unsigned line)
{
	if (!passed)
	{
		printf("%s:%d: error: Failed test [%s]\n", file, line, description);
	}
	return passed;
}

#define ok(THIS, TESTNAME) \
{ \
int __this = (THIS); \
test_ok(__this, TESTNAME, __FILE__, __LINE__);\
}

int corecrypto_wintest(void) {

	int rc, test_rc;
	test_rc = 0;
	diag("\n-------individual sanity checks");

	//==========================================================================
	// AES CBC
	//==========================================================================
	const struct ccmode_cbc *cbc = ccaes_cbc_decrypt_mode();
	unsigned char out[sizeof(sample_ct)];
	cccbc_one_shot(cbc,
		sizeof(sample_key), sample_key,
		sample_iv,
		sizeof(sample_ct) / CCAES_BLOCK_SIZE,
		sample_ct, out);

	rc = memcmp(out, sample_pt, sizeof(sample_pt)); 
	report(rc == 0, "AES128-CBC");

	//==========================================================================
	// SHA256
	//==========================================================================
	const struct ccdigest_info *di = ccsha256_di();
	unsigned char c = 'a';
	//uint8_t digest[di->output_size];
	uint8_t digest[256];
	ccdigest(di, sizeof(c), &c, digest);

	rc = memcmp(digest, test_sha256_digest, sizeof(test_sha256_digest));
	report(rc == 0, "SHA256 single test");


	//==========================================================================
	// Random
	//==========================================================================
	struct ccrng_drbg_state rng_drbg;
	struct ccdrbg_info info;
	struct ccrng_state *rng = (struct ccrng_state*)&rng_drbg;
	uint8_t drbg_init_salt[32];

	memset(drbg_init_salt, 123, sizeof(drbg_init_salt));

	// Set DRBG - NIST HMAC
	struct ccdrbg_nisthmac_custom custom = { ccsha256_di(), 0,}; 
	ccdrbg_factory_nisthmac(&info, &custom);

	//uint8_t state[info.size];
	uint8_t *state = (uint8_t *) alloca(info.size);
	rc = ccrng_drbg_init(&rng_drbg, &info, (struct ccdrbg_state *)state, sizeof(drbg_init_salt), drbg_init_salt);
	report(rc == 0, "Initialization of the rng");

	//==========================================================================
	// EC Sign / Verify using x963 format
	//==========================================================================
	const uint8_t CC_ALIGNED(8) test_p256_x963_key[] = {
		0x04, 0x4d, 0x40, 0xa4, 0x5e, 0x3d, 0x51, 0x7c, 0x3b, 0x6b, 0xb2, 0x97,
		0x1c, 0x77, 0x18, 0x11, 0x70, 0x0b, 0xa2, 0x64, 0x0d, 0x03, 0xa1, 0xc4,
		0x98, 0x5e, 0xb3, 0xaf, 0x40, 0x5a, 0x0a, 0xee, 0x6e, 0x8f, 0x74, 0x05,
		0xaa, 0x44, 0x76, 0xfb, 0x8a, 0xf8, 0xb5, 0x40, 0xe5, 0xeb, 0xdb, 0xd8,
		0x4c, 0x70, 0x87, 0x4f, 0xb6, 0x18, 0x14, 0x61, 0xb0, 0x9d, 0x20, 0x3d,
		0x44, 0xd0, 0x43, 0xa1, 0x31, 0xef, 0xcd, 0xab, 0x90, 0x78, 0x56, 0x34,
		0x12, 0xef, 0xcd, 0xab, 0x90, 0x78, 0x56, 0x34, 0x12, 0xef, 0xcd, 0xab,
		0x90, 0x78, 0x56, 0x34, 0x12, 0xef, 0xcd, 0xab, 0x90, 0x78, 0x56, 0x34,
		0x12
	};
	// Import a test key
	// Select curve
	ccec_const_cp_t cp = ccec_cp_256();
	ccec_full_ctx_decl_cp(cp, full_key);

	rc = ccec_x963_import_priv(cp, sizeof(test_p256_x963_key), test_p256_x963_key, full_key);
	//printf("Size of full_key is %lu\n", sizeof(full_key));
	report(rc == 0, "Import EC key");

	// Sign / Verify
	size_t  raw_siglen = 2 * ccec_signature_r_s_size(ccec_ctx_pub(full_key));
	uint8_t *sig = (uint8_t *)alloca(raw_siglen);//uint8_t sig[raw_siglen];
	//printf("Raw Signature length is %zu\n", raw_siglen);

	rc = ccec_sign_composite(full_key, sizeof(digest), digest, &sig[0], &sig[raw_siglen / 2], rng);
	report(rc == 0, "Signature generation");

	bool result = false;
	rc = ccec_verify_composite((ccec_pub_ctx_t)full_key, sizeof(digest), digest, &sig[0], &sig[raw_siglen / 2], &result);
	report(rc == 0, "Signature verification");
	report(result == true, "Signature valid");

	return test_rc;
}

int main(int argc, const char * argv[])
{
	int rc = corecrypto_wintest();
	printf("\n\ntest %s\n", rc == 0 ? "ok" : "failed");
	return rc;
}


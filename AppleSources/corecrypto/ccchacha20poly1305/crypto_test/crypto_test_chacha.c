/* Copyright (c) (2016-2019,2021) Apple Inc. All rights reserved.
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

#if (CCCHACHATEST == 0)
entryPoint(ccchacha_test,"ccchacha test")
#else
#include <corecrypto/ccchacha20poly1305.h>
#include <corecrypto/ccchacha20poly1305_priv.h>
#include "cc_priv.h"

static int verbose = 0;

typedef struct {
	const char *	key;
	const char *	nonce;
    uint32_t        counter;
	const char *	input;
	const char *	output;
}	chacha20_test_vector;

static const chacha20_test_vector		chacha20TestVectors[] = {
	// Test 1 from "RFC 7539"
	{
	/* key */		"0000000000000000000000000000000000000000000000000000000000000000",
	/* nonce */		"000000000000000000000000",
        0,
	/* input */		"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
	/* output */	"76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586"
	},
	// Test 2 from "RFC 7539"
	{
	/* key */		"0000000000000000000000000000000000000000000000000000000000000001",
	/* nonce */		"000000000000000000000002",
        1,
	/* input */		"416e79207375626d697373696f6e20746f20746865204945544620696e74656e6465642062792074686520436f6e7472696275746f7220666f72207075626c69636174696f6e20617320616c6c206f722070617274206f6620616e204945544620496e7465726e65742d4472616674206f722052464320616e6420616e792073746174656d656e74206d6164652077697468696e2074686520636f6e74657874206f6620616e204945544620616374697669747920697320636f6e7369646572656420616e20224945544620436f6e747269627574696f6e222e20537563682073746174656d656e747320696e636c756465206f72616c2073746174656d656e747320696e20494554462073657373696f6e732c2061732077656c6c206173207772697474656e20616e6420656c656374726f6e696320636f6d6d756e69636174696f6e73206d61646520617420616e792074696d65206f7220706c6163652c207768696368206172652061646472657373656420746f",
	/* output */	"a3fbf07df3fa2fde4f376ca23e82737041605d9f4f4f57bd8cff2c1d4b7955ec2a97948bd3722915c8f3d337f7d370050e9e96d647b7c39f56e031ca5eb6250d4042e02785ececfa4b4bb5e8ead0440e20b6e8db09d881a7c6132f420e52795042bdfa7773d8a9051447b3291ce1411c680465552aa6c405b7764d5e87bea85ad00f8449ed8f72d0d662ab052691ca66424bc86d2df80ea41f43abf937d3259dc4b2d0dfb48a6c9139ddd7f76966e928e635553ba76c5c879d7b35d49eb2e62b0871cdac638939e25e8a1e0ef9d5280fa8ca328b351c3c765989cbcf3daa8b6ccc3aaf9f3979c92b3720fc88dc95ed84a1be059c6499b9fda236e7e818b04b0bc39c1e876b193bfe5569753f88128cc08aaa9b63d1a16f80ef2554d7189c411f5869ca52c5b83fa36ff216b9c1d30062bebcfd2dc5bce0911934fda79a86f6e698ced759c3ff9b6477338f3da4f9cd8514ea9982ccafb341b2384dd902f3d1ab7ac61dd29c6f21ba5b862f3730e37cfdc4fd806c22f221"
	},
	// Test 3 from "RFC 7539"
	{
	/* key */		"1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0",
	/* nonce */		"000000000000000000000002",
        42,
	/* input */		"2754776173206272696c6c69672c20616e642074686520736c6974687920746f7665730a446964206779726520616e642067696d626c6520696e2074686520776162653a0a416c6c206d696d737920776572652074686520626f726f676f7665732c0a416e6420746865206d6f6d65207261746873206f757467726162652e",
	/* output */	"62e6347f95ed87a45ffae7426f27a1df5fb69110044c0d73118effa95b01e5cf166d3df2d721caf9b21e5fb14c616871fd84c54f9d65b283196c7fe4f60553ebf39c6402c42234e32a356b3e764312a61a5532055716ead6962568f87d3f3f7704c6a8d1bcd1bf4d50d6154b6da731b187b58dfd728afa36757a797ac188d1"
	},
};

static void test_chacha20(void) {
	size_t		i, n;

	n = CC_ARRAY_LEN(chacha20TestVectors);
	for(i = 0; i < n; ++i) {
		const chacha20_test_vector * const 	tv				= &chacha20TestVectors[i];
		byteBuffer							key				= hexStringToBytes(tv->key);
		byteBuffer							nonce			= hexStringToBytes(tv->nonce);
        uint32_t                            counter         = tv->counter;
		byteBuffer							input			= hexStringToBytes(tv->input);
		byteBuffer							outputExpected	= hexStringToBytes(tv->output);
		byteBuffer							outputActual	= mallocByteBuffer(outputExpected->len);

		ccchacha20(key->bytes, nonce->bytes, counter, input->len, input->bytes, outputActual->bytes);
        ok_memcmp(outputActual->bytes, outputExpected->bytes, outputExpected->len, "Check chacha20 test vector %zu", i + 1);

		free(key);
		free(nonce);
		free(input);
		free(outputExpected);
		free(outputActual);
	}
}

typedef struct {
	const char *	key;
	const char *	input;
	const char *	tag;
}	poly1305_test_vector;

static const poly1305_test_vector		poly1305TestVectors[] = {
	// Test 1 from RFC 7539.
	{
	/* key */	"0000000000000000000000000000000000000000000000000000000000000000",
	/* input */	"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
	/* tag */	"00000000000000000000000000000000"
	},
	// Test 2 from RFC 7539.
	{
	/* key */	"0000000000000000000000000000000036e5f6b5c5e06070f0efca96227a863e",
	/* input */	"416e79207375626d697373696f6e20746f20746865204945544620696e74656e6465642062792074686520436f6e7472696275746f7220666f72207075626c69636174696f6e20617320616c6c206f722070617274206f6620616e204945544620496e7465726e65742d4472616674206f722052464320616e6420616e792073746174656d656e74206d6164652077697468696e2074686520636f6e74657874206f6620616e204945544620616374697669747920697320636f6e7369646572656420616e20224945544620436f6e747269627574696f6e222e20537563682073746174656d656e747320696e636c756465206f72616c2073746174656d656e747320696e20494554462073657373696f6e732c2061732077656c6c206173207772697474656e20616e6420656c656374726f6e696320636f6d6d756e69636174696f6e73206d61646520617420616e792074696d65206f7220706c6163652c207768696368206172652061646472657373656420746f",
	/* tag */	"36e5f6b5c5e06070f0efca96227a863e"
	},
	// Test 3 from RFC 7539.
	{
	/* key */	"36e5f6b5c5e06070f0efca96227a863e00000000000000000000000000000000",
	/* input */	"416e79207375626d697373696f6e20746f20746865204945544620696e74656e6465642062792074686520436f6e7472696275746f7220666f72207075626c69636174696f6e20617320616c6c206f722070617274206f6620616e204945544620496e7465726e65742d4472616674206f722052464320616e6420616e792073746174656d656e74206d6164652077697468696e2074686520636f6e74657874206f6620616e204945544620616374697669747920697320636f6e7369646572656420616e20224945544620436f6e747269627574696f6e222e20537563682073746174656d656e747320696e636c756465206f72616c2073746174656d656e747320696e20494554462073657373696f6e732c2061732077656c6c206173207772697474656e20616e6420656c656374726f6e696320636f6d6d756e69636174696f6e73206d61646520617420616e792074696d65206f7220706c6163652c207768696368206172652061646472657373656420746f",
	/* tag */	"f3477e7cd95417af89a6b8794c310cf0"
    },
    // Test 4 from RFC 7539.
    {
        "1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0",
        "2754776173206272696c6c69672c20616e642074686520736c6974687920746f7665730a446964206779726520616e642067696d626c6520696e2074686520776162653a0a416c6c206d696d737920776572652074686520626f726f676f7665732c0a416e6420746865206d6f6d65207261746873206f757467726162652e",
        "4541669a7eaaee61e708dc7cbcc5eb62"
    }
};

static void test_poly1305(void) {
	size_t		i, n;

	n = CC_ARRAY_LEN(poly1305TestVectors);
	for(i = 0; i < n; ++i) {
		const poly1305_test_vector * const 	tv			= &poly1305TestVectors[i];
		byteBuffer							key			= hexStringToBytes(tv->key);
		byteBuffer							input		= hexStringToBytes(tv->input);
		byteBuffer							tagExpected	= hexStringToBytes(tv->tag);
		byteBuffer							tagActual	= mallocByteBuffer(tagExpected->len);

		ccpoly1305(key->bytes, input->len, input->bytes, tagActual->bytes);
		ok_memcmp(tagActual->bytes, tagExpected->bytes, tagExpected->len, "Check poly1305 test vector %zu", i + 1);

		free(key);
		free(input);
		free(tagExpected);
		free(tagActual);
	}
}

typedef struct {
	const char *	key;
	const char *	nonce;
	const char *	aad;
	const char *	pt;
	const char *	ct;
	const char *	tag;
    int             invalid;
}	chacha20_poly1305_test_vector;

static const chacha20_poly1305_test_vector		chacha20_poly1305TestVectors[] =
{
#include "test_vectors/crypto_test_chacha20poly1305_vectors.inc"
#include "test_vectors/crypto_test_chacha20poly1305_wycheproof_vectors.inc"
};

static void test_chacha20_poly1305(void) {
	size_t		testIndex, testCount;

	testCount = CC_ARRAY_LEN(chacha20_poly1305TestVectors);
	for (testIndex = 0; testIndex < testCount; ++testIndex) {
		const chacha20_poly1305_test_vector * const 	tv			= &chacha20_poly1305TestVectors[testIndex];
		byteBuffer										key			= hexStringToBytes(tv->key);
		byteBuffer										nonce		= hexStringToBytes(tv->nonce);
		byteBuffer										aad			= hexStringToBytes(tv->aad);
		byteBuffer										pt			= hexStringToBytes(tv->pt);
		byteBuffer										ptActual	= mallocByteBuffer(pt->len);
		byteBuffer										ct			= hexStringToBytes(tv->ct);
		byteBuffer										ctActual	= mallocByteBuffer(ct->len);
		byteBuffer										tag			= hexStringToBytes(tv->tag);
		byteBuffer										tagActual	= mallocByteBuffer(tag->len);
		ccchacha20poly1305_ctx                          state;
		size_t											i;
		int												err;

        // We do not test for misuse of the API
        if (nonce->len != CCCHACHA20_NONCE_NBYTES) {
            goto next;
        }

        const struct ccchacha20poly1305_info *info = ccchacha20poly1305_info();
        if (tv->invalid) {
            ccchacha20poly1305_encrypt_oneshot(info, key->bytes, nonce->bytes, aad->len, aad->bytes, pt->len, pt->bytes, ctActual->bytes, tagActual->bytes);
            err = cc_cmp_safe(tag->len, tagActual->bytes, tag->bytes);
            isnt(err, 0, "Check invalid tag generation with chacha20-poly1305 one-shot encrypt test vector %zu");
        } else {
            // All-at-once test using the update API.
            ccchacha20poly1305_init(info, &state, key->bytes);
            ccchacha20poly1305_setnonce(info, &state, nonce->bytes);
            ccchacha20poly1305_aad(info, &state, aad->len, aad->bytes);
            ccchacha20poly1305_encrypt(info, &state, pt->len, pt->bytes, ctActual->bytes);
            ccchacha20poly1305_finalize(info, &state, tagActual->bytes);
            ok_memcmp(ctActual->bytes, ct->bytes, ct->len, "Check chacha20-poly1305 init ciphertext all-at-once via update encrypt test vector %zu", testIndex + 1);
            ok_memcmp(tagActual->bytes, tag->bytes, tag->len, "Check chacha20-poly1305 init tag all-at-once via update encrypt test vector %zu", testIndex + 1);

            ccchacha20poly1305_reset(info, &state);
            ccchacha20poly1305_setnonce(info, &state, nonce->bytes);
            ccchacha20poly1305_aad(info, &state, aad->len, aad->bytes);
            ccchacha20poly1305_encrypt(info, &state, pt->len, pt->bytes, ctActual->bytes);
            ccchacha20poly1305_finalize(info, &state, tagActual->bytes);
            ok_memcmp(ctActual->bytes, ct->bytes, ct->len, "Check chacha20-poly1305 reset ciphertext all-at-once via update encrypt test vector %zu", testIndex + 1);
            ok_memcmp(tagActual->bytes, tag->bytes, tag->len, "Check chacha20-poly1305 reset tag all-at-once via update encrypt test vector %zu", testIndex + 1);

            ccchacha20poly1305_init(info, &state, key->bytes);
            ccchacha20poly1305_setnonce(info, &state, nonce->bytes);
            ccchacha20poly1305_aad(info, &state, aad->len, aad->bytes);
            ccchacha20poly1305_decrypt(info, &state, ct->len, ct->bytes, ptActual->bytes);
            err = ccchacha20poly1305_verify(info, &state, tag->bytes);
            ok(err == 0, "Check chacha20-poly1305 init tag all-at-once via update decrypt test vector %zu", testIndex + 1);
            ok_memcmp(ptActual->bytes, pt->bytes, pt->len, "Check chacha20-poly1305 init plaintext all-at-once via update decrypt test vector %zu", testIndex + 1);

            ccchacha20poly1305_reset(info, &state);
            ccchacha20poly1305_setnonce(info, &state, nonce->bytes);
            ccchacha20poly1305_aad(info, &state, aad->len, aad->bytes);
            ccchacha20poly1305_decrypt(info, &state, ct->len, ct->bytes, ptActual->bytes);
            err = ccchacha20poly1305_verify(info, &state, tag->bytes);
            ok(err == 0, "Check chacha20-poly1305 reset tag all-at-once via update decrypt test vector %zu", testIndex + 1);
            ok_memcmp(ptActual->bytes, pt->bytes, pt->len, "Check chacha20-poly1305 reset plaintext all-at-once via update decrypt test vector %zu", testIndex + 1);

            // Byte-by-byte test using the update API.
            ccchacha20poly1305_init(info, &state, key->bytes);
            ccchacha20poly1305_setnonce(info, &state, nonce->bytes);
            for(i = 0; i < aad->len; ++i) ccchacha20poly1305_aad(info, &state, 1, &aad->bytes[i]);
            for(i = 0; i < pt->len; ++i) ccchacha20poly1305_encrypt(info, &state, 1, &pt->bytes[i], &ctActual->bytes[i]);
            ccchacha20poly1305_finalize(info, &state, tagActual->bytes);
            ok_memcmp(ctActual->bytes, ct->bytes, ct->len, "Check chacha20-poly1305 init ciphertext byte-by-byte via update encrypt test vector %zu", testIndex + 1);
            ok_memcmp(tagActual->bytes, tag->bytes, tag->len, "Check chacha20-poly1305 init tag byte-by-byte via update encrypt test vector %zu", testIndex + 1);

            ccchacha20poly1305_reset(info, &state);
            ccchacha20poly1305_setnonce(info, &state, nonce->bytes);
            for(i = 0; i < aad->len; ++i) ccchacha20poly1305_aad(info, &state, 1, &aad->bytes[i]);
            for(i = 0; i < pt->len; ++i) ccchacha20poly1305_encrypt(info, &state, 1, &pt->bytes[i], &ctActual->bytes[i]);
            ccchacha20poly1305_finalize(info, &state, tagActual->bytes);
            ok_memcmp(ctActual->bytes, ct->bytes, ct->len, "Check chacha20-poly1305 reset ciphertext byte-by-byte via update encrypt test vector %zu", testIndex + 1);
            ok_memcmp(tagActual->bytes, tag->bytes, tag->len, "Check chacha20-poly1305 reset tag byte-by-byte via update encrypt test vector %zu", testIndex + 1);

            ccchacha20poly1305_init(info, &state, key->bytes);
            ccchacha20poly1305_setnonce(info, &state, nonce->bytes);
            for(i = 0; i < aad->len; ++i) ccchacha20poly1305_aad(info, &state, 1, &aad->bytes[i]);
            for(i = 0; i < ct->len; ++i) ccchacha20poly1305_decrypt(info, &state, 1, &ct->bytes[i], &ptActual->bytes[i]);
            err = ccchacha20poly1305_verify(info, &state, tag->bytes);
            ok(err == 0, "Check chacha20-poly1305 init byte-by-byte tag via update decrypt test vector %zu", testIndex + 1);
            ok_memcmp(ptActual->bytes, pt->bytes, pt->len, "Check chacha20-poly1305 init byte-by-byte plaintext via update decrypt test vector %zu", testIndex + 1);

            ccchacha20poly1305_reset(info, &state);
            ccchacha20poly1305_setnonce(info, &state, nonce->bytes);
            for(i = 0; i < aad->len; ++i) ccchacha20poly1305_aad(info, &state, 1, &aad->bytes[i]);
            for(i = 0; i < ct->len; ++i) ccchacha20poly1305_decrypt(info, &state, 1, &ct->bytes[i], &ptActual->bytes[i]);
            err = ccchacha20poly1305_verify(info, &state, tag->bytes);
            ok(err == 0, "Check chacha20-poly1305 reset byte-by-byte tag via update decrypt test vector %zu", testIndex + 1);
            ok_memcmp(ptActual->bytes, pt->bytes, pt->len, "Check chacha20-poly1305 reset byte-by-byte plaintext via update decrypt test vector %zu", testIndex + 1);

            // All-at-once test using the one-shot API.
            ccchacha20poly1305_encrypt_oneshot(info, key->bytes, nonce->bytes, aad->len, aad->bytes, pt->len, pt->bytes, ctActual->bytes, tagActual->bytes);
            ok_memcmp(ctActual->bytes, ct->bytes, ct->len, "Check chacha20-poly1305 ciphertext all-at-once via one-shot encrypt test vector %zu", testIndex + 1);
            ok_memcmp(tagActual->bytes, tag->bytes, tag->len, "Check chacha20-poly1305 tag all-at-once via one-shot encrypt test vector %zu", testIndex + 1);

            err = ccchacha20poly1305_decrypt_oneshot(info, key->bytes, nonce->bytes, aad->len, aad->bytes, ct->len, ct->bytes, ptActual->bytes, tag->bytes);
            ok(err == 0, "Check chacha20-poly1305 tag all-at-once via one-shot decrypt test vector %zu", testIndex + 1);
            ok_memcmp(ptActual->bytes, pt->bytes, pt->len, "Check chacha20-poly1305 plaintext all-at-once via one-shot decrypt test vector %zu", testIndex + 1);
        }

next:
		free(key);
		free(nonce);
		free(aad);
		free(pt);
		free(ptActual);
		free(ct);
		free(ctActual);
		free(tag);
		free(tagActual);
	}
}

/* In this test we reach into the internal state to trigger the validation error on long messages. */
static int test_chacha20poly1305_counter_wrap(void)
{
    uint8_t buf[CCCHACHA20_BLOCK_NBYTES] = { 0 };
    const struct ccchacha20poly1305_info *info;
    ccchacha20poly1305_ctx ctx;

    info = ccchacha20poly1305_info();

    ok_or_fail(ccchacha20poly1305_init(info, &ctx, buf) == 0, "ccchacha20poly1305_init encrypt counter wrap");
    ok_or_fail(ccchacha20poly1305_setnonce(info, &ctx, buf) == 0, "ccchacha20poly1305_setnonce encrypt counter wrap");
    ok_or_fail(ccchacha20poly1305_encrypt(info, &ctx, sizeof (buf), buf, buf) == 0, "ccchacha20poly1305_encrypt (begin) encrypt counter wrap");
    ctx.text_nbytes = CCCHACHA20POLY1305_TEXT_MAX_NBYTES - CCCHACHA20_BLOCK_NBYTES;
    ok_or_fail(ccchacha20poly1305_encrypt(info, &ctx, sizeof (buf), buf, buf) == 0, "ccchacha20poly1305_encrypt (end) encrypt counter wrap");
    ok_or_fail(ccchacha20poly1305_encrypt(info, &ctx, 1, buf, buf) != 0, "ccchacha20poly1305_encrypt (overflow) encrypt counter wrap");

    ok_or_fail(ccchacha20poly1305_init(info, &ctx, buf) == 0, "ccchacha20poly1305_init decrypt counter wrap");
    ok_or_fail(ccchacha20poly1305_setnonce(info, &ctx, buf) == 0, "ccchacha20poly1305_setnonce decrypt counter wrap");
    ok_or_fail(ccchacha20poly1305_decrypt(info, &ctx, sizeof (buf), buf, buf) == 0, "ccchacha20poly1305_decrypt (begin) decrypt counter wrap");
    ctx.text_nbytes = CCCHACHA20POLY1305_TEXT_MAX_NBYTES - CCCHACHA20_BLOCK_NBYTES;
    ok_or_fail(ccchacha20poly1305_decrypt(info, &ctx, sizeof (buf), buf, buf) == 0, "ccchacha20poly1305_decrypt (end) decrypt counter wrap");
    ok_or_fail(ccchacha20poly1305_decrypt(info, &ctx, 1, buf, buf) != 0, "ccchacha20poly1305_decrypt (overflow) decrypt counter wrap");

    return 1;
}

int ccchacha_tests(TM_UNUSED int argc, TM_UNUSED char *const *argv) {
	plan_tests(2197);

	if(verbose) diag("Starting chacha tests\n");
	test_chacha20();
	test_poly1305();
	test_chacha20_poly1305();
    test_chacha20poly1305_counter_wrap();
	return 0;
}

#endif // CCCHACHATEST

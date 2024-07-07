/* Copyright (c) (2021,2022) Apple Inc. All rights reserved.
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

#include <corecrypto/ccz_priv.h>
#include <stdlib.h>

static void* cc_alloc(CC_UNUSED void *ctx, size_t size)
{
    return malloc(size);
}

static void cc_free(CC_UNUSED void *ctx, CC_UNUSED size_t oldsize, void *p)
{
    free(p);
}

static void* cc_realloc(CC_UNUSED void *ctx, CC_UNUSED size_t oldsize, void *p, size_t newsize)
{
    return realloc(p, newsize);
}

static struct ccz_class ccz_c = {
    .ctx = 0,
    .ccz_alloc = cc_alloc,
    .ccz_realloc = cc_realloc,
    .ccz_free = cc_free
};

static void test_ccz_mul(void)
{
    const uint8_t a_bytes[] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
    };

    const uint8_t b_bytes[] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
    };

    const uint8_t ab_bytes[] = {
        0x01, 0x04, 0x0a, 0x14, 0x23, 0x38, 0x54, 0x78,
        0x94, 0xa8, 0xb4, 0xb8, 0xb4, 0xa8, 0x94, 0x78,
        0x93, 0xa4, 0xaa, 0xa4, 0x91, 0x70, 0x40
    };

    const uint8_t ab2_bytes[] = {
        0x01, 0x08, 0x24, 0x79, 0x4d, 0x1e, 0xc1, 0x81,
        0x2d, 0x08, 0xa1, 0x88, 0xf0, 0x26, 0xfa, 0xf8,
        0x27, 0xcb, 0x0f, 0xbc, 0xd5, 0x2d, 0xf7, 0x2c,
        0x3e, 0xf6, 0x84, 0xd4, 0x0e, 0x62, 0x03, 0x74,
        0xb5, 0x85, 0xaa, 0x36, 0xdc, 0x3c, 0x45, 0xbf,
        0x72, 0x59, 0xb8, 0x10, 0x00
    };

    ccz a, b, r;
    ccz_init(&ccz_c, &a);
    ccz_init(&ccz_c, &b);
    ccz_init(&ccz_c, &r);

    ccz_read_uint(&a, sizeof(a_bytes), a_bytes);
    ccz_read_uint(&b, sizeof(b_bytes), b_bytes);

    // Compute r := a * b
    ccz_mul(&r, &a, &b);
    ccz_read_uint(&a, sizeof(ab_bytes), ab_bytes);
    is(ccz_cmp(&a, &r), 0, "ccz_cmp() failed");

    // Inverse argument order (b,a)
    ccz_read_uint(&a, sizeof(a_bytes), a_bytes);
    ccz_mul(&r, &b, &a);
    ccz_read_uint(&a, sizeof(ab_bytes), ab_bytes);
    is(ccz_cmp(&a, &r), 0, "ccz_cmp() failed");

    // Pass argument r twice, r := r * r
    ccz_mul(&r, &r, &r);
    ccz_read_uint(&a, sizeof(ab2_bytes), ab2_bytes);
    is(ccz_cmp(&a, &r), 0, "ccz_cmp() failed");

    ccz_free(&a);
    ccz_free(&b);
    ccz_free(&r);
}

static void test_ccz_write_radix(void)
{
    const uint8_t a_bytes[] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
    };

    char buf[20] = { 0 };

    ccz a;
    ccz_init(&ccz_c, &a);
    ccz_read_uint(&a, sizeof(a_bytes), a_bytes);

    // Check invalid parameters.
    is(ccz_write_radix_size(&a, 8), 0, "ccz_write_radix_size() should fail");
    is(ccz_write_radix_size(&a, 64), 0, "ccz_write_radix_size() should fail");

    isnt(ccz_write_radix(&a, sizeof(buf) - 1, buf, 8), CCERR_OK, "ccz_write_radix() should fail");
    isnt(ccz_write_radix(&a, sizeof(buf) - 1, buf, 64), CCERR_OK, "ccz_write_radix() should fail");
    isnt(ccz_write_radix(&a, 0, buf, 10), CCERR_OK, "ccz_write_radix() should fail");

    // Now something valid.
    is(ccz_write_radix_size(&a, 10), 17, "ccz_write_radix_size() failed");
    is(ccz_write_radix_size(&a, 16), 15, "ccz_write_radix_size() failed");

    is(ccz_write_radix(&a, sizeof(buf) - 1, buf, 10), CCERR_OK, "ccz_write_radix() failed");
    is(strcmp(buf, "0072623859790382856"), 0, "strcmp() failed");

    is(ccz_write_radix(&a, sizeof(buf) - 1, buf, 16), CCERR_OK, "ccz_write_radix() failed");
    is(strcmp(buf, "0000102030405060708"), 0, "strcmp() failed");

    // Check truncation.
    memset(buf, 0, sizeof(buf));

    is(ccz_write_radix(&a, 8, buf, 10), CCERR_OK, "ccz_write_radix() failed");
    is(strcmp(buf, "90382856"), 0, "strcmp() failed");

    is(ccz_write_radix(&a, 8, buf, 16), CCERR_OK, "ccz_write_radix() failed");
    is(strcmp(buf, "05060708"), 0, "strcmp() failed");

    // Check negative values.
    ccz_set_sign(&a, -1);

    is(ccz_write_radix_size(&a, 10), 18, "ccz_write_radix_size() failed");
    is(ccz_write_radix_size(&a, 16), 16, "ccz_write_radix_size() failed");

    // Ensure that len(buf) >= 2 for negative numbers.
    isnt(ccz_write_radix(&a, 1, buf, 10), CCERR_OK, "ccz_write_radix() should fail");

    is(ccz_write_radix(&a, sizeof(buf) - 1, buf, 10), CCERR_OK, "ccz_write_radix() failed");
    is(strcmp(buf, "-072623859790382856"), 0, "strcmp() failed");

    is(ccz_write_radix(&a, sizeof(buf) - 1, buf, 16), CCERR_OK, "ccz_write_radix() failed");
    is(strcmp(buf, "-000102030405060708"), 0, "strcmp() failed");

    // Check truncation.
    memset(buf, 0, sizeof(buf));

    is(ccz_write_radix(&a, 8, buf, 10), CCERR_OK, "ccz_write_radix() failed");
    is(strcmp(buf, "-0382856"), 0, "strcmp() failed");

    is(ccz_write_radix(&a, 8, buf, 16), CCERR_OK, "ccz_write_radix() failed");
    is(strcmp(buf, "-5060708"), 0, "strcmp() failed");

    ccz_mul(&a, &a, &a);
    is(ccz_write_radix(&a, 8, buf, 10), CCERR_OK, "ccz_write_radix() failed");
    is(strcmp(buf, "58716736"), 0, "strcmp() failed");

    is(ccz_write_radix(&a, 8, buf, 16), CCERR_OK, "ccz_write_radix() failed");
    is(strcmp(buf, "A4917040"), 0, "strcmp() failed");

    // Check zero.
    ccz_zero(&a);

    is(ccz_write_radix_size(&a, 10), 1, "ccz_write_radix_size() failed");
    is(ccz_write_radix_size(&a, 16), 1, "ccz_write_radix_size() failed");

    is(ccz_write_radix(&a, 8, buf, 10), CCERR_OK, "ccz_write_radix() failed");
    is(strcmp(buf, "00000000"), 0, "strcmp() failed");

    is(ccz_write_radix(&a, 8, buf, 16), CCERR_OK, "ccz_write_radix() failed");
    is(strcmp(buf, "00000000"), 0, "strcmp() failed");

    // Check negative zero.
    ccz_set_sign(&a, -1);

    is(ccz_write_radix(&a, 8, buf, 10), CCERR_OK, "ccz_write_radix() failed");
    is(strcmp(buf, "00000000"), 0, "strcmp() failed");

    is(ccz_write_radix(&a, 8, buf, 16), CCERR_OK, "ccz_write_radix() failed");
    is(strcmp(buf, "00000000"), 0, "strcmp() failed");

    ccz_free(&a);
}

static void test_ccz_read_radix(void)
{
    const char *hex1 = "0000102030405060708";
    const char *hex1_pos = "+0000102030405060708";
    const char *hex1_neg = "-0000102030405060708";
    const char *hex1_err = "-000010203040506070M";

    const char *dec1 = "0072623859790382856";
    const char *dec1_pos = "+0072623859790382856";
    const char *dec1_neg = "-0072623859790382856";
    const char *dec1_err = "-007262385979038285A";

    const uint8_t bytes1[] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
    };

    const char *hex2 = "00000102030405060708090a0b0C0D";
    const char *dec2 = "079850778293499848189627010061";

    const uint8_t bytes2[] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d
    };

    const char *zero = "00000";
    const char *zero_pos = "+00000";
    const char *zero_neg = "-00000";

    const char *sign_pos = "+";
    const char *sign_neg = "-";

    ccz a, b, r;
    ccz_init(&ccz_c, &a);
    ccz_init(&ccz_c, &b);
    ccz_init(&ccz_c, &r);
    ccz_read_uint(&a, sizeof(bytes1), bytes1);
    ccz_read_uint(&b, sizeof(bytes2), bytes2);

    // Check invalid parameters.
    isnt(ccz_read_radix(&r, strlen(hex1), hex1, 8), CCERR_OK, "ccz_read_radix() should fail");
    isnt(ccz_read_radix(&r, strlen(hex1), hex1, 64), CCERR_OK, "ccz_read_radix() should fail");
    isnt(ccz_read_radix(&r, 0, hex1, 16), CCERR_OK, "ccz_read_radix() should fail");

    // Now something valid.
    is(ccz_read_radix(&r, strlen(dec1), dec1, 10), CCERR_OK, "ccz_read_radix() failed");
    is(ccz_cmp(&r, &a), 0, "ccz_cmp() failed");

    is(ccz_read_radix(&r, strlen(hex1), hex1, 16), CCERR_OK, "ccz_read_radix() failed");
    is(ccz_cmp(&r, &a), 0, "ccz_cmp() failed");

    is(ccz_read_radix(&r, strlen(hex2), hex2, 16), CCERR_OK, "ccz_read_radix() failed");
    is(ccz_cmp(&r, &b), 0, "ccz_cmp() failed");

    is(ccz_read_radix(&r, strlen(dec1_pos), dec1_pos, 10), CCERR_OK, "ccz_read_radix() failed");
    is(ccz_cmp(&r, &a), 0, "ccz_cmp() failed");

    is(ccz_read_radix(&r, strlen(hex1_pos), hex1_pos, 16), CCERR_OK, "ccz_read_radix() failed");
    is(ccz_cmp(&r, &a), 0, "ccz_cmp() failed");

    is(ccz_read_radix(&r, strlen(dec2), dec2, 10), CCERR_OK, "ccz_read_radix() failed");
    is(ccz_cmp(&r, &b), 0, "ccz_cmp() failed");

    // Check negative values.
    ccz_set_sign(&a, -1);

    is(ccz_read_radix(&r, strlen(dec1_neg), dec1_neg, 10), CCERR_OK, "ccz_read_radix() failed");
    is(ccz_cmp(&r, &a), 0, "ccz_cmp() failed");

    is(ccz_read_radix(&r, strlen(hex1_neg), hex1_neg, 16), CCERR_OK, "ccz_read_radix() failed");
    is(ccz_cmp(&r, &a), 0, "ccz_cmp() failed");

    // Check invalid values.
    isnt(ccz_read_radix(&r, strlen(dec1_err), dec1_err, 10), CCERR_OK, "ccz_read_radix() should fail");
    isnt(ccz_read_radix(&r, strlen(hex1_err), hex1_err, 16), CCERR_OK, "ccz_read_radix() should fail");

    isnt(ccz_read_radix(&r, strlen(sign_pos), sign_pos, 10), CCERR_OK, "ccz_read_radix() should fail");
    isnt(ccz_read_radix(&r, strlen(sign_neg), sign_neg, 16), CCERR_OK, "ccz_read_radix() should fail");

    // Check zero.
    is(ccz_read_radix(&r, strlen(zero), zero, 10), CCERR_OK, "ccz_read_radix() failed");
    ok(ccz_is_zero(&r), "should be zero");

    is(ccz_read_radix(&r, strlen(zero), zero, 16), CCERR_OK, "ccz_read_radix() failed");
    ok(ccz_is_zero(&r), "should be zero");

    is(ccz_read_radix(&r, strlen(zero_pos), zero_pos, 10), CCERR_OK, "ccz_read_radix() failed");
    ok(ccz_is_zero(&r), "should be zero");

    is(ccz_read_radix(&r, strlen(zero_pos), zero_pos, 16), CCERR_OK, "ccz_read_radix() failed");
    ok(ccz_is_zero(&r), "should be zero");

    is(ccz_read_radix(&r, strlen(zero_neg), zero_neg, 10), CCERR_OK, "ccz_read_radix() failed");
    ok(ccz_is_zero(&r), "should be zero");
    is(ccz_sign(&r), 1, "sign should positive");

    is(ccz_read_radix(&r, strlen(zero_neg), zero_neg, 16), CCERR_OK, "ccz_read_radix() failed");
    ok(ccz_is_zero(&r), "should be zero");
    is(ccz_sign(&r), 1, "sign should positive");

    ccz_free(&a);
    ccz_free(&b);
    ccz_free(&r);
}

static void test_ccz_read_write_radix(void)
{
    const char *dec = "1002030405060708090021222324252627282920";
    const char *hex = "2F1D80946529AF5CA4FDA61E2BA41ABE8";

    char dec_buf[strlen(dec) + 1];
    dec_buf[strlen(dec)] = 0;

    char hex_buf[strlen(hex) + 1];
    hex_buf[strlen(hex)] = 0;

    ccz r;
    ccz_init(&ccz_c, &r);

    // Roundtrip.
    is(ccz_read_radix(&r, strlen(dec), dec, 10), CCERR_OK, "ccz_read_radix() failed");
    is(ccz_write_radix(&r, sizeof(dec_buf) - 1, dec_buf, 10), CCERR_OK, "ccz_write_radix() failed");
    is(strcmp(dec_buf, dec), 0, "strcmp() failed");

    is(ccz_read_radix(&r, strlen(hex), hex, 16), CCERR_OK, "ccz_read_radix() failed");
    is(ccz_write_radix(&r, sizeof(hex_buf) - 1, hex_buf, 16), CCERR_OK, "ccz_write_radix() failed");
    is(strcmp(hex_buf, hex), 0, "strcmp() failed");

    ccz_free(&r);
}

static void test_ccz_expmod(void)
{
    const uint8_t s_bytes[] = {
        0x01, 0x08, 0x24, 0x79, 0x4d, 0x1e, 0xc1, 0x81,
        0x2d, 0x08, 0xa1, 0x88, 0xf0, 0x26, 0xfa, 0xf8,
        0x27, 0xcb, 0x0f, 0xbc, 0xd5, 0x2d, 0xf7, 0x2c,
        0x3e, 0xf6, 0x84, 0xd4, 0x0e, 0x62, 0x03, 0x74,
        0xb5, 0x85, 0xaa, 0x36, 0xdc, 0x3c, 0x45, 0xbf,
        0x72, 0x59, 0xb8, 0x10, 0x00, 0x01
    };

    const uint8_t t_bytes[] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
    };

    const uint8_t u_bytes[] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x09
    };

    const uint8_t r1_bytes[] = {
        0x87, 0xef, 0xd5, 0x0b, 0x33, 0x79, 0x76, 0x48,
        0xa1, 0x9d, 0xc1, 0x47, 0x13, 0x23, 0x47
    };

    const uint8_t r2_bytes[] = {
        0xe2, 0xa9, 0x24, 0xf9, 0x67, 0x65, 0x54, 0xea,
        0xf2, 0x5d, 0xbc, 0x7b, 0x6e, 0xd6, 0xcc, 0x12,
        0xaf, 0xb7, 0x59, 0x79, 0x35, 0x15, 0x14, 0xa5,
        0x50, 0x84, 0xdc, 0x7f, 0x91, 0x06, 0xb3, 0x44,
        0x7a, 0x49, 0xf5, 0x6d, 0x1c, 0x13, 0x63, 0x92,
        0x75, 0x10, 0x25, 0xa9, 0x76
    };

    const uint8_t r3_bytes[] = {
        0xd3, 0xef, 0xe5, 0x38, 0x44, 0xba, 0x1c, 0x7b,
        0xdf, 0x6e, 0x26, 0xcb, 0x22, 0x74, 0x2e, 0xf3,
        0x6e, 0xc1, 0x69, 0x60, 0xd1, 0xa4, 0x8a, 0xed,
        0xc5, 0xc7, 0x28, 0x18, 0x7e, 0x0d, 0xb1, 0xb6,
        0x5a, 0xe2, 0xd4, 0xd9, 0x8c, 0x18, 0x98, 0x6e,
        0xf4, 0x39, 0x13, 0xd8, 0x60
    };

    ccz r, s, t, u, v;
    ccz_init(&ccz_c, &r);
    ccz_init(&ccz_c, &s);
    ccz_init(&ccz_c, &t);
    ccz_init(&ccz_c, &u);
    ccz_init(&ccz_c, &v);

    ccz_read_uint(&s, sizeof(s_bytes), s_bytes);
    ccz_read_uint(&t, sizeof(t_bytes), t_bytes);
    ccz_read_uint(&u, sizeof(u_bytes), u_bytes);

    // Compute a^b (mod p) where a >= p.
    is(ccz_expmod(&r, &s, &t, &u), CCERR_OK, "ccz_expmod() failed");

    ccz_read_uint(&v, sizeof(r1_bytes), r1_bytes);
    is(ccz_cmp(&r, &v), 0, "ccz_cmp() failed");

    // Compute a^b (mod p) where ccz_n(a) < ccz_n(p).
    is(ccz_expmod(&r, &u, &t, &s), CCERR_OK, "ccz_expmod() failed");

    ccz_read_uint(&v, sizeof(r2_bytes), r2_bytes);
    is(ccz_cmp(&r, &v), 0, "ccz_cmp() failed");

    // Compute a^b (mod p) where ccz_n(a) = ccz_n(p).
    is(ccz_expmod(&r, &v, &t, &s), CCERR_OK, "ccz_expmod() failed");

    ccz_read_uint(&v, sizeof(r3_bytes), r3_bytes);
    is(ccz_cmp(&r, &v), 0, "ccz_cmp() failed");

    ccz_free(&r);
    ccz_free(&s);
    ccz_free(&t);
    ccz_free(&u);
    ccz_free(&v);
}

int ccz_tests(TM_UNUSED int argc, TM_UNUSED char *const *argv)
{
    int num_tests = 0;
    num_tests += 3;  // test_ccz_mul
    num_tests += 40; // test_ccz_write_radix
    num_tests += 37; // test_ccz_read_radix
    num_tests += 6;  // test_ccz_read_write_radix
    num_tests += 6;  // test_ccz_expmod
    plan_tests(num_tests);

    test_ccz_mul();
    test_ccz_write_radix();
    test_ccz_read_radix();
    test_ccz_read_write_radix();
    test_ccz_expmod();

    return 0;
}

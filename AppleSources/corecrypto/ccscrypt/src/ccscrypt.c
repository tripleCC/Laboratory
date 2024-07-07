/* Copyright (c) (2018-2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "cc_internal.h"
#include <corecrypto/ccscrypt.h>
#include <corecrypto/ccpbkdf2.h>
#include <corecrypto/ccsha2.h>
#include "cc_memory.h"

#include "ccscrypt_internal.h"

static void
ccscrypt_block_xor(uint8_t *Z, uint8_t *X, uint8_t *Y, size_t length)
{
    for (size_t i = 0; i < length; i++) {
        Z[i] = X[i] ^ Y[i];
    }
}

static uint64_t
ccscrypt_integerify(uint8_t *B, size_t r, size_t N)
{
    size_t index = (2 * r - 1) * 64;
    uint8_t *X = &B[index];
    uint64_t j = (uint64_t)X[0] << 0 | (uint64_t)X[1] << 8 | (uint64_t)X[2] << 16 | (uint64_t)X[3] << 24
        | (uint64_t)X[4] << 32 | (uint64_t)X[5] << 40 | (uint64_t)X[6] << 48 | (uint64_t)X[7] << 56;
    return j & (N - 1);
}

void
ccscrypt_salsa20_8(uint8_t *in_buffer, uint8_t *out_buffer)
{
    uint32_t x[16];

    for (int i = 0; i < 16; i++) {
        x[i] = ((uint32_t)in_buffer[(i * 4) + 0] <<  0 |
                (uint32_t)in_buffer[(i * 4) + 1] <<  8 |
                (uint32_t)in_buffer[(i * 4) + 2] << 16 |
                (uint32_t)in_buffer[(i * 4) + 3] << 24);
    }

    // This implementation is taken from:
    // https://tools.ietf.org/html/rfc7914#section-3
    for (size_t i = 8; i > 0; i -= 2) {
#define R(a,b) (((a) << (b)) | ((a) >> (32 - (b))))
        x[ 4] ^= R(x[ 0]+x[12], 7);  x[ 8] ^= R(x[ 4]+x[ 0], 9);
        x[12] ^= R(x[ 8]+x[ 4],13);  x[ 0] ^= R(x[12]+x[ 8],18);
        x[ 9] ^= R(x[ 5]+x[ 1], 7);  x[13] ^= R(x[ 9]+x[ 5], 9);
        x[ 1] ^= R(x[13]+x[ 9],13);  x[ 5] ^= R(x[ 1]+x[13],18);
        x[14] ^= R(x[10]+x[ 6], 7);  x[ 2] ^= R(x[14]+x[10], 9);
        x[ 6] ^= R(x[ 2]+x[14],13);  x[10] ^= R(x[ 6]+x[ 2],18);
        x[ 3] ^= R(x[15]+x[11], 7);  x[ 7] ^= R(x[ 3]+x[15], 9);
        x[11] ^= R(x[ 7]+x[ 3],13);  x[15] ^= R(x[11]+x[ 7],18);
        x[ 1] ^= R(x[ 0]+x[ 3], 7);  x[ 2] ^= R(x[ 1]+x[ 0], 9);
        x[ 3] ^= R(x[ 2]+x[ 1],13);  x[ 0] ^= R(x[ 3]+x[ 2],18);
        x[ 6] ^= R(x[ 5]+x[ 4], 7);  x[ 7] ^= R(x[ 6]+x[ 5], 9);
        x[ 4] ^= R(x[ 7]+x[ 6],13);  x[ 5] ^= R(x[ 4]+x[ 7],18);
        x[11] ^= R(x[10]+x[ 9], 7);  x[ 8] ^= R(x[11]+x[10], 9);
        x[ 9] ^= R(x[ 8]+x[11],13);  x[10] ^= R(x[ 9]+x[ 8],18);
        x[12] ^= R(x[15]+x[14], 7);  x[13] ^= R(x[12]+x[15], 9);
        x[14] ^= R(x[13]+x[12],13);  x[15] ^= R(x[14]+x[13],18);
#undef R
    }

    for (size_t i = 0; i < 16; i++) {
        uint32_t input_value = ((uint32_t)in_buffer[(i * 4) + 0] <<  0 |
                                (uint32_t)in_buffer[(i * 4) + 1] <<  8 |
                                (uint32_t)in_buffer[(i * 4) + 2] << 16 |
                                (uint32_t)in_buffer[(i * 4) + 3] << 24);
        uint32_t result = x[i] + input_value;
        out_buffer[(i * 4) + 0] = (uint8_t)(result >> 0);
        out_buffer[(i * 4) + 1] = (uint8_t)(result >> 8);
        out_buffer[(i * 4) + 2] = (uint8_t)(result >> 16);
        out_buffer[(i * 4) + 3] = (uint8_t)(result >> 24);
    }
}

void
ccscrypt_blockmix_salsa8(uint8_t *B, uint8_t *Y, size_t r)
{
    uint8_t X[64];

    cc_memcpy(X, &B[(2 * r - 1) * 64], 64);

    for (size_t i = 0; i < 2 * r; i++) {
        ccscrypt_block_xor(X, X, &B[i * 64], 64);
        ccscrypt_salsa20_8(X, X);
        cc_memcpy(&Y[i * 64], X, 64);
    }

    for (size_t i = 0; i < r; i++) {
        cc_memcpy(&B[i * 64], &Y[(i * 2) * 64], 64);
    }
    for (size_t i = 0; i < r; i++) {
        cc_memcpy(&B[(i + r) * 64], &Y[(i * 2 + 1) * 64], 64);
    }
}

void
ccscrypt_romix(size_t r, uint8_t *B, size_t N, uint8_t *T, uint8_t *X, uint8_t *Y)
{
    cc_memcpy(X, B, 128 * r);

    for (size_t i = 0; i < N; i++) {
        cc_memcpy(&T[i * (128 * r)], X, 128 * r);
        ccscrypt_blockmix_salsa8(X, Y, r);
    }

    for (size_t i = 0; i < N; i++) {
        uint64_t j = ccscrypt_integerify(X, r, N);
        ccscrypt_block_xor(X, X, &T[j * (128 * r)], 128 * r);
        ccscrypt_blockmix_salsa8(X, Y, r);
    }

    cc_memcpy(B, X, 128 * r);
}

int
ccscrypt_valid_parameters(uint64_t N, uint32_t r, uint32_t p)
{
    // r > 0
    if (r == 0) {
        return CCERR_PARAMETER;
    }

    // p is less than ((2^32-1) * 32) / (128 * r)
    if (p > (UINT32_MAX * 32 / (128 * r))) {
        return CCERR_PARAMETER;
    }

    // N > 1 and power of 2
    if (N == 0) {
        return CCERR_PARAMETER;
    }
    if ((N & (N - 1)) != 0) {
        return CCERR_PARAMETER;
    }

    return CCERR_OK;
}

int64_t
ccscrypt_storage_size(uint64_t N, uint32_t r, uint32_t p)
{
    CC_ENSURE_DIT_ENABLED

    int valid = ccscrypt_valid_parameters(N, r, p);
    if (valid != CCERR_OK) {
        return valid;
    }

    int64_t x, y, z, result;
    bool overflow = false;

    overflow |= cc_mul_overflow(128, r, &x);
    overflow |= cc_mul_overflow(p, x, &x);
    overflow |= cc_mul_overflow(256, r, &y);
    overflow |= cc_mul_overflow(128, r, &z);
    overflow |= cc_mul_overflow(N, z, &z);
    overflow |= cc_add_overflow(x, y, &result);
    overflow |= cc_add_overflow(z, result, &result);

    if (overflow) {
        return CCERR_OVERFLOW;
    }

    return result;
}

int
ccscrypt(size_t password_len, const uint8_t *password, size_t salt_len, const uint8_t *salt,
         uint8_t *storage, uint64_t N_in, uint32_t r_in, uint32_t p_in, size_t dk_len, uint8_t *dk)
{
    CC_ENSURE_DIT_ENABLED

    cc_assert(storage);

    int64_t total_size = ccscrypt_storage_size(N_in, r_in, p_in);
    if (total_size < 0) {
        // This will either be CCERR_PARAMETER or CCERR_OVERFLOW.
        return (int)total_size;
    }

    if (dk_len > (size_t)INT32_MAX * 32) {
        return CCERR_PARAMETER;
    }

    size_t N = (size_t)N_in;
    size_t r = (size_t)r_in;
    size_t p = (size_t)p_in;
    size_t B_len = 128 * r * p;
    size_t X_len = 128 * r;
    size_t Y_len = 128 * r;

    uint8_t *B = storage;
    uint8_t *X = &storage[B_len];
    uint8_t *Y = &storage[B_len + X_len];
    uint8_t *T = &storage[B_len + X_len + Y_len];

    if (0 != ccpbkdf2_hmac(ccsha256_di(), password_len, password, salt_len, salt, 1, B_len, B)) {
        return CCERR_INTERNAL;
    }

    for (size_t i = 0; i < p; i++) {
        ccscrypt_romix(r, &B[i * 128 * r], N, T, X, Y);
    }

    if (0 != ccpbkdf2_hmac(ccsha256_di(), password_len, password, B_len, B, 1, dk_len, dk)) {
        return CCERR_INTERNAL;
    }

    cc_clear((size_t)total_size, storage);

    return 0;
}

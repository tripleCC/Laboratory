/* Copyright (c) (2021,2023) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "ccrsa_internal.h"

/**
 * Compute the required number of Miller-Rabin iterations as per
 * FIPS 186-4 F.1 and 186-5 C.1.
 *
 * As these prime candidates are exclusively used for RSA key generation,
 * we'll use the equivalent security level of the final RSA key pair as
 * the upper bound on the probability p_{k,t} that a k-bit composite is
 * falsely declared prime after t MR iterations. We target at minimum
 * a security level of 2^-100.
 */

/**
 * We can use SageMath to compute RSA security strengths and round to
 * common security strengths provided by symmetric algorithms (DES, AES).
 *
 * for n in [512, 1024, 2048, 3072, 4096]:
 *     s = log(exp((64/9 * log(2^n))^(1/3) * (log(log(2^n)))^(2/3)), 2).n()
 *     print('RSA-%d ~ %d-bit security' % (n, s))
 *
 *  RSA-512  ~  63-bit security (= 2^-100)
 *  RSA-1024 ~  86-bit security (= 2^-100)
 *  RSA-2048 ~ 116-bit security (= 2^-112)
 *  RSA-3072 ~ 138-bit security (= 2^-128)
 *  RSA-4096 ~ 156-bit security (= 2^-144)
 */

/**
 * We can use SageMath again to compute the required number of iterations t
 * for a given k-bit prime (resulting in a 2*k-bit modulus) targeting the
 * desired security level as determined above.
 *
 * The algorithm is given by FIPS 186-4 F.1 and 186-5 C.1.
 *
 * def compute_pkt(k, t, A, B, M):
 *     S = sum(2^(m-(m-1)*t) * sum(1/2^(j+(k-1)/j) for j in range(2, m+1)) for m in range(3, M+1))
 *     C = 2^(k - 2 - M * t)
 *     return B * 2^-k * (C + A * S)
 *
 * def mr_iterations(nbits, sectarget):
 *     A = (8*(pi^2 - 6) / 3) * 2^(nbits - 2)
 *     B = 2.00743 * log(2) * nbits
 *     MM = floor(2 * sqrt(nbits - 1) - 1)
 *
 *     for t in range(1, sectarget / 2 + 1):
 *         for M in range(3, MM + 1):
 *             pkt = compute_pkt(nbits, t, A, B, M)
 *             if floor(-log(pkt, 2)) >= sectarget:
 *                 return t
 */

size_t ccrsa_num_mr_iterations(size_t pbits)
{
    // RSA-4096, p_{k,t} < 2^-144.
    if (pbits >= 2048) {
        return 4;
    }

    // RSA-3072, p_{k,t} < 2^-128.
    if (pbits >= 1536) {
        return 4;
    }

    // RSA-2048, p_{k,t} < 2^-112.
    if (pbits >= 1024) {
        return 5;
    }

    // RSA-1024, p_{k,t} < 2^-100.
    if (pbits >= 512) {
        return 7;
    }

    // RSA-512, p_{k,t} < 2^-100.
    return 16;
}

/**
 * For auxiliary primes we use the following lengths:
 *
 *   200+ bits for RSA-4096
 *   170+ bits for RSA-3072
 *   140+ bits for RSA-2048
 *   100+ bits otherwise
 *
 * Based on that table we use the appropriate security strengths
 * to compute the required number of MR iterations.
 */
size_t ccrsa_num_mr_iterations_aux(size_t pbits)
{
    cc_assert(pbits > 100);

    // RSA-4096, p_{k,t} < 2^-144.
    if (pbits > 200) {
        return 44;
    }

    // RSA-3072, p_{k,t} < 2^-128.
    if (pbits > 170) {
        return 41;
    }

    // RSA-2048, p_{k,t} < 2^-112.
    if (pbits > 140) {
        return 38;
    }

    // RSA-1024, p_{k,t} < 2^-100.
    return 38;
}

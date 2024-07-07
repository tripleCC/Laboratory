# Copyright (c) (2019-2023) Apple Inc. All rights reserved.
#
# corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
# is contained in the License.txt file distributed with corecrypto) and only to
# people who accept that license. IMPORTANT:  Any license rights granted to you by
# Apple Inc. (if any) are limited to internal use within your organization only on
# devices and computers you own or control, for the sole purpose of verifying the
# security characteristics and correct functioning of the Apple Software.  You may
# not, directly or indirectly, redistribute the Apple Software or any portions thereof.

// void ccn_mul_256(cc_unit *r, const cc_unit *a, const cc_unit *b);

    // Load A.
    ldp A0, A1, [x1], #16
    ldp A2, A3, [x1]

    // Load B.
    ldp B0, B1, [x2], #16
    ldp B2, B3, [x2]

    // Z0 = A0 * B0
    mul   Z0, A0, B0
    umulh Z1, A0, B0

    // Z1 += A1 * B0
    mul    u, A1, B0
    umulh Z2, A1, B0

    // Z2 += A2 * B0
    mul    v, A2, B0
    umulh Z3, A2, B0

    adds Z1, Z1, u
    adcs Z2, Z2, v

    // Z3 += A3 * B0
    mul    u, A3, B0
    umulh Z4, A3, B0

    // Z4 += A3 * B1
    mul    v, A3, B1
    umulh Z5, A3, B1

    adcs Z3, Z3, u
    adcs Z4, Z4, v

    // Z5 += A3 * B2
    mul    u, A3, B2
    umulh Z6, A3, B2

    // Z6 = A3 * B3
    mul    v, A3, B3
    umulh Z7, A3, B3

    adcs Z5, Z5, u
    adcs Z6, Z6, v
    adc  Z7, Z7, xzr

    // Z1 += A0 * B1
    mul   u, A0, B1
    umulh v, A0, B1

    adds Z1, Z1, u
    adcs Z2, Z2, v

    // Z3 += A2 * B1
    mul   u, A2, B1
    umulh v, A2, B1

    adcs Z3, Z3, u
    adcs Z4, Z4, v

    // Z5 += A2 * B3
    mul   u, A2, B3
    umulh v, A2, B3

    adcs Z5, Z5, u
    adcs Z6, Z6, v
    adc  Z7, Z7, xzr

    // Z2 += A1 * B1
    mul   u, A1, B1
    umulh v, A1, B1

    adds Z2, Z2, u
    adcs Z3, Z3, v

    // Z4 += A2 * B2
    mul   u, A2, B2
    umulh v, A2, B2

    adcs Z4, Z4, u
    adcs Z5, Z5, v
    adc  A3, xzr, xzr

    // Z2 += A0 * B2
    mul   u, A0, B2
    umulh v, A0, B2

    adds Z2, Z2, u
    adcs Z3, Z3, v

    // Z4 += A1 * B3
    mul   u, A1, B3
    umulh v, A1, B3

    adcs Z4, Z4, u
    adcs Z5, Z5, v
    adc  A3, A3, xzr

    // Z3 += A1 * B2
    mul   u, A1, B2
    umulh v, A1, B2

    adds Z3, Z3, u
    adcs Z4, Z4, v
    adc  B1, xzr, xzr

    // Z3 += A0 * B3
    mul   u, A0, B3
    umulh v, A0, B3

    adds Z3, Z3, u
    adcs Z4, Z4, v
    adcs Z5, Z5, B1
    adcs Z6, Z6, A3
    adc  Z7, Z7, xzr

# Copyright (c) (2020-2023) Apple Inc. All rights reserved.
#
# corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
# is contained in the License.txt file distributed with corecrypto) and only to
# people who accept that license. IMPORTANT:  Any license rights granted to you by
# Apple Inc. (if any) are limited to internal use within your organization only on
# devices and computers you own or control, for the sole purpose of verifying the
# security characteristics and correct functioning of the Apple Software.  You may
# not, directly or indirectly, redistribute the Apple Software or any portions thereof.

// void ccn_mul_256(cc_unit *r, const cc_unit *a, const cc_unit *b);

    // Free %rdx.
    movq %rdx, b

    // Load A0.
    movq (a), %rdx

    // A0 * B0
    mulxq (b), Z0, Z1

    // A0 * B1
    mulxq 8(b), v, Z2

    addq v, Z1

    // A0 * B2
    mulxq 16(b), v, Z3

    adcq v, Z2

    // A0 * B3
    mulxq 24(b), v, Z4

    adcq v, Z3
    adcq $0, Z4

    // Load A1.
    movq 8(a), %rdx

    // Clear CF.
    xorq q, q

    // A1 * B0
    mulxq (b), q, v

    adox q, Z1
    adcx v, Z2

    // A1 * B1
    mulxq 8(b), q, v

    adox q, Z2
    adcx v, Z3

    // A1 * B2
    mulxq 16(b), q, v

    adox q, Z3
    adcx v, Z4

    // A1 * B3
    mulxq 24(b), q, Z5

    adox q, Z4

    movq $0, v
    adox v, Z5
    adcx v, Z5

    // Load A2.
    movq 16(a), %rdx

    // Clear CF.
    xorq q, q

    // A2 * B0
    mulxq (b), q, v

    adox q, Z2
    adcx v, Z3

    // A2 * B1
    mulxq 8(b), q, v

    adox q, Z3
    adcx v, Z4

    // A2 * B2
    mulxq 16(b), q, v

    adox q, Z4
    adcx v, Z5

    // A2 * B3
    mulxq 24(b), q, Z6

    adox q, Z5

    movq $0, v
    adox v, Z6
    adcx v, Z6

    // Load A3.
    movq 24(a), %rdx

    // Clear CF.
    xorq q, q

    // A3 * B0
    mulxq (b), q, v

    adox q, Z3
    adcx v, Z4

    // A3 * B1
    mulxq 8(b), q, v

    adox q, Z4
    adcx v, Z5

    // A3 * B2
    mulxq 16(b), q, v

    adox q, Z5
    adcx v, Z6

    // A3 * B3
    mulxq 24(b), q, Z7

    adox q, Z6

    movq $0, v
    adox v, Z7
    adcx v, Z7

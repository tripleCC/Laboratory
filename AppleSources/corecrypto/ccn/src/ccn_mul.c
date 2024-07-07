/* Copyright (c) (2010-2012,2014-2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "ccn_internal.h"

void ccn_mul_ws(CC_UNUSED cc_ws_t ws, cc_size n, cc_unit *r, const cc_unit *s, const cc_unit *t)
{
    ccn_mul(n, r, s, t);
}

#if !CCN_MUL_ASM

#if CCN_MUL1_ASM && CCN_ADDMUL1_ASM

/* Constant time. NOTE: Seems like r and s may overlap, but r and t may not.
   Also if n is 0 this still writes one word to r. */
void ccn_mul(cc_size n, cc_unit *r, const cc_unit *s, const cc_unit *t)
{
    const cc_size sn = n;
    cc_size tn = n;
    assert(r != s);
    assert(r != t);

    r[sn] = ccn_mul1 (sn, r, s, t[0]);
    while (tn > 1)
    {
        r += 1;
        t += 1;
        tn -= 1;
        r[sn] = ccn_addmul1 (sn, r, s, t[0]);
    }
}

#else /* !(CCN_MUL1_ASM && CCN_ADDMUL1_ASM) */

/* Do r = s * t, r is 2 * count cc_units in size, s and t are count * cc_units in size. */
void ccn_mul(cc_size count, cc_unit *r, const cc_unit *s, const cc_unit *t)
{
    cc_assert(r != s);
    cc_assert(r != t);
    ccn_zero(count * 2, r);

#if CC_DUNIT_SUPPORTED
    typedef cc_unit cc_mulw;
    typedef cc_dunit cc_muld;
 #define CCMULW_BITS  CCN_UNIT_BITS
 #define CCMULW_MASK CCN_UNIT_MASK
#else
    typedef uint32_t cc_mulw;
    typedef uint64_t cc_muld;
 #define r ((cc_mulw *)r)
 #define s ((const cc_mulw *)s)
 #define t ((const cc_mulw *)t)
 #define CCMULW_BITS  (32)
 #define CCMULW_MASK ((cc_mulw)~0)
    count *= CCN_UNIT_SIZE / sizeof(cc_mulw);
#endif // CC_DUNIT_SUPPORTED

    cc_muld prod1, prod2, carry1 = 0, carry2 = 0;
    const cc_mulw *aptr, *bptr = t;
    cc_mulw *destptr, mult1, mult2;
    cc_size ix;
	for (ix = 0; ix < count - 1; ix += 2) {
		mult1 = *(bptr++);
		mult2 = *(bptr++);

		cc_mulw prevmul = 0;
		carry1 = 0;
		carry2 = 0;
		aptr = s;
		destptr = &r[ix];
		cc_muld prevDigit = *destptr;

		for (cc_size j = 0; j < count; ++j) {
			cc_mulw curmul = *aptr++;
			prevDigit += carry1 + carry2;

			prod1 = (cc_muld)curmul * mult1;
			prod2 = (cc_muld)prevmul * mult2;

			carry1 = prod1 >> CCMULW_BITS;
			carry2 = prod2 >> CCMULW_BITS;

			prod1 &= CCMULW_MASK;
			prod2 &= CCMULW_MASK;

			cc_muld prodsum = prod1 + prod2 + prevDigit;
			carry1 += prodsum >> CCMULW_BITS;
			prevDigit = *(destptr+1);
			*(destptr++) = (cc_mulw)prodsum;
			prevmul = curmul;
		}

		prod1 = prevDigit + carry1;
		prod1 += (cc_muld)prevmul * mult2;
		prod1 += carry2;
		carry1 = prod1 >> CCMULW_BITS;
		*(destptr++) = (cc_mulw)prod1;
		*destptr = (cc_mulw)carry1;
	}

    if (ix < count) {
        mult1 = *bptr;
        carry1 = 0;
        aptr = s;
        destptr = &r[ix];
        for (cc_size j = 0; j < count; ++j) {
            //prod = *(aptr++) * mult + *destptr + carry;
            prod1 = (cc_muld)(*aptr++);
            prod1 *= mult1;
            prod1 += *destptr;
            prod1 += carry1;
            *(destptr++) = (cc_mulw)prod1;
            carry1 = prod1 >> CCMULW_BITS;
        }
        *destptr = (cc_mulw)carry1;
    }
}

#endif /* !(CCN_MUL1_ASM && CCN_ADDMUL1_ASM) */

#endif /* !CCN_MUL_ASM */

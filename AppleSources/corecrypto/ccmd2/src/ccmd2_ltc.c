/* Copyright (c) (2010,2011,2012,2015,2016,2017,2018,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 *
 * Tom St Denis, tomstdenis@gmail.com, http://libtom.org
 */


#include <corecrypto/ccmd2.h>
#include <corecrypto/cc_priv.h>


static const unsigned char PI_SUBST[256] = {
    41, 46, 67, 201, 162, 216, 124, 1, 61, 54, 84, 161, 236, 240, 6,
    19, 98, 167, 5, 243, 192, 199, 115, 140, 152, 147, 43, 217, 188,
    76, 130, 202, 30, 155, 87, 60, 253, 212, 224, 22, 103, 66, 111, 24,
    138, 23, 229, 18, 190, 78, 196, 214, 218, 158, 222, 73, 160, 251,
    245, 142, 187, 47, 238, 122, 169, 104, 121, 145, 21, 178, 7, 63,
    148, 194, 16, 137, 11, 34, 95, 33, 128, 127, 93, 154, 90, 144, 50,
    39, 53, 62, 204, 231, 191, 247, 151, 3, 255, 25, 48, 179, 72, 165,
    181, 209, 215, 94, 146, 42, 172, 86, 170, 198, 79, 184, 56, 210,
    150, 164, 125, 182, 118, 252, 107, 226, 156, 116, 4, 241, 69, 157,
    112, 89, 100, 113, 135, 32, 134, 91, 207, 101, 230, 45, 168, 2, 27,
    96, 37, 173, 174, 176, 185, 246, 28, 70, 97, 105, 52, 64, 126, 15,
    85, 71, 163, 35, 221, 81, 175, 58, 195, 92, 249, 206, 186, 197,
    234, 38, 44, 83, 13, 110, 133, 40, 132, 9, 211, 223, 205, 244, 65,
    129, 77, 82, 106, 220, 55, 200, 108, 193, 171, 250, 36, 225, 123,
    8, 12, 189, 177, 74, 120, 136, 149, 139, 227, 99, 232, 109, 233,
    203, 213, 254, 59, 0, 29, 57, 242, 239, 183, 14, 102, 88, 208, 228,
    166, 119, 114, 248, 235, 117, 75, 10, 49, 68, 80, 180, 143, 237,
    31, 26, 219, 153, 141, 51, 159, 17, 131, 20
};

/* adds 16 bytes to the checksum */
static void md2_update_chksum(unsigned char *chksum, const unsigned char *buf)
{
    int j;
    unsigned char L;

    L = chksum[15];
    for (j = 0; j < 16; j++) {
        /* caution, the RFC says its "C[j] = S[M[i*16+j] xor L]" but the
         * reference source code [and test vectors] say otherwise.
         */
        L = (chksum[j] ^= PI_SUBST[(buf[j] ^ L)]);
    }
}

static void md2_compress(unsigned char *X, const unsigned char *buf)
{
    int j, k;
    unsigned char t;

    /* copy block */
    for (j = 0; j < 16; j++) {
        X[16+j] = buf[j];
        X[32+j] = X[j] ^ X[16+j];
    }

    t = (unsigned char)0;

    /* do 18 rounds */
    for (j = 0; j < 18; j++) {
        for (k = 0; k < 48; k++) {
            t = (X[k] ^= PI_SUBST[t]);
        }
        t = (t + (unsigned char)j) & 255;
    }
}

static void md2_processblock(ccdigest_state_t state, size_t nblocks, const void *in)
{
    unsigned char *X=ccdigest_u8(state);
    unsigned char *chksum=X+48;
    const unsigned char *buf = in;

    while (nblocks--) {
        md2_compress(X, buf);
        md2_update_chksum(chksum, buf);
        buf+=CCMD2_BLOCK_SIZE;
    }
}


static void md2_final(const struct ccdigest_info *di, ccdigest_ctx_t ctx,
                      unsigned char *out)
{
    size_t i, k;

    // Clone the state.
    ccdigest_di_decl(di, tmp);
    cc_memcpy(tmp, ctx, ccdigest_di_size(di));

    unsigned char *X=ccdigest_state_u8(di, tmp);
    unsigned char *chksum=X+48;

    /* pad the message */
    k = 16 - ccdigest_num(di, tmp);
    for (i = ccdigest_num(di, tmp); i < 16; i++) {
        ccdigest_data(di, tmp)[i] = (unsigned char)k;
    }

    /* hash and update */
    md2_compress(X, ccdigest_data(di, tmp));
    md2_update_chksum(chksum, ccdigest_data(di, tmp));

    /* hash checksum */
    cc_memcpy(ccdigest_data(di, tmp), chksum, 16);
    md2_compress(X, ccdigest_data(di, tmp));

    /* output is lower 16 bytes of X */
    cc_memcpy(out, X, 16);

    ccdigest_di_clear(di, tmp);
}

/* MD2 initial state is zero */
static const uint32_t ccmd2_initial_state[] = {
    0, 0, 0 , 0,
    0, 0, 0 , 0,
    0, 0, 0 , 0,
    0, 0, 0 , 0,
};


const struct ccdigest_info ccmd2_ltc_di = {
    .output_size = CCMD2_OUTPUT_SIZE,
    .state_size = CCMD2_STATE_SIZE,
    .block_size = CCMD2_BLOCK_SIZE,
    .oid_size = 10,
    .oid = CC_DIGEST_OID_MD2,
    .initial_state = ccmd2_initial_state,
    .compress = md2_processblock,
    .final = md2_final
};

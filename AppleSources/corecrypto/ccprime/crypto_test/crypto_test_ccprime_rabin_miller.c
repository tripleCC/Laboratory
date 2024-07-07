/* Copyright (c) (2018-2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "ccprime_internal.h"
#include "cc_memory.h"
#include "testmore.h"
#include "testccnBuffer.h"
#include "cc_workspaces.h"
#include <stdlib.h>

#if (CCRABIN_MILLER == 0)
entryPoint(ccprime_rabin_miller_tests, "ccprime_rabin_miller")
#else // CCRABIN_MILLER
int ccprime_rabin_miller_tests(TM_UNUSED int argc, TM_UNUSED char *const *argv);
#endif // CCRABIN_MILLER

const uint8_t PRIME_512[] = {
    0xca, 0x29, 0x04, 0xd0, 0x71, 0xdf, 0xd9, 0xbe,
    0x67, 0x2a, 0xb8, 0xfc, 0xfb, 0xf6, 0xce, 0x94,
    0x7b, 0x00, 0x46, 0x8d, 0xb6, 0x20, 0x72, 0x85,
    0x8a, 0xa6, 0x7c, 0xf6, 0x71, 0x4c, 0x87, 0x90,
    0x67, 0xa5, 0xce, 0xd5, 0xa9, 0x33, 0xbb, 0x98,
    0x80, 0x3d, 0x4c, 0xb5, 0x2b, 0x91, 0x06, 0x70,
    0xd2, 0x05, 0x1a, 0x8e, 0xfa, 0x49, 0x28, 0x3e,
    0x88, 0xb1, 0x92, 0x7a, 0x83, 0x0b, 0xbe, 0x17
};

const uint8_t PRIME_928[] = {
    0xd7, 0x4b, 0x8a, 0x94, 0xcf, 0xf5, 0x4e, 0x72,
    0x77, 0xb3, 0xfc, 0xa3, 0x2a, 0xc9, 0x80, 0x29,
    0x67, 0xb8, 0x99, 0x2f, 0x7f, 0x14, 0xb8, 0x67,
    0x8f, 0x4d, 0x1e, 0x52, 0x00, 0x9c, 0x69, 0x91,
    0x89, 0xe8, 0x69, 0x34, 0xf1, 0x89, 0x0f, 0x69,
    0x50, 0xaa, 0x83, 0x9c, 0x3f, 0x72, 0xb4, 0xb7,
    0x8a, 0x24, 0x20, 0x90, 0x01, 0xd2, 0xe8, 0xe1,
    0xd2, 0xaf, 0x26, 0xc3, 0xe0, 0xd2, 0x79, 0x8d,
    0x6e, 0xb2, 0x07, 0x4d, 0x6a, 0xeb, 0x4f, 0xac,
    0x76, 0x5a, 0x71, 0x58, 0x48, 0xad, 0x5a, 0x92,
    0x8a, 0x21, 0xeb, 0x14, 0x96, 0x8d, 0xa0, 0x44,
    0x7d, 0xbc, 0x2c, 0x71, 0x2a, 0x09, 0x57, 0x06,
    0x93, 0x38, 0xfd, 0xbc, 0xe9, 0xc9, 0x2a, 0x21,
    0x38, 0x04, 0x1f, 0x92, 0x42, 0xde, 0xcf, 0x79,
    0x5f, 0xe5, 0x3a, 0xcb
};

const uint8_t PRIME_1024[] = {
    0xbe, 0x70, 0x68, 0x7c, 0x23, 0x51, 0x4d, 0xb4,
    0x4a, 0x99, 0x12, 0x6c, 0xde, 0x19, 0xf9, 0x54,
    0xa2, 0xf2, 0x14, 0x67, 0x31, 0x95, 0x1b, 0xf3,
    0xea, 0xbf, 0xbf, 0x24, 0xf4, 0x56, 0x62, 0xc8,
    0x3a, 0xd5, 0x70, 0xe3, 0xa9, 0xd2, 0x54, 0x28,
    0xf4, 0x12, 0xa3, 0x08, 0xff, 0x82, 0xf5, 0xe1,
    0xfd, 0xd1, 0x81, 0xb3, 0x86, 0xd0, 0xd5, 0x46,
    0xf0, 0xf1, 0x50, 0x5d, 0x65, 0x29, 0x2f, 0x0f,
    0x9d, 0x66, 0xe1, 0x07, 0x04, 0x0e, 0x32, 0x66,
    0x70, 0x24, 0x83, 0x2c, 0x2d, 0xbc, 0x1d, 0x82,
    0xa6, 0x35, 0xc9, 0x35, 0x2b, 0xd8, 0x48, 0x0a,
    0x02, 0xec, 0xe9, 0x03, 0xf8, 0x61, 0x7a, 0x5d,
    0xf9, 0xbc, 0xcc, 0xdd, 0x36, 0xae, 0xcd, 0x43,
    0xed, 0xab, 0x70, 0x0b, 0xe8, 0x3c, 0xaa, 0x10,
    0xff, 0xce, 0x66, 0xf9, 0xc8, 0xfa, 0xdd, 0xc8,
    0xf3, 0x07, 0x3e, 0x69, 0x76, 0x30, 0x2e, 0xa5
};

const uint8_t PRIME_2048[] = {
    0xfb, 0x00, 0x18, 0xa5, 0xa5, 0x37, 0x24, 0x68,
    0x07, 0x31, 0xdc, 0xc9, 0x4a, 0xf5, 0x64, 0x21,
    0xbb, 0x87, 0xce, 0x2c, 0xa5, 0xe0, 0x54, 0x50,
    0x31, 0xfd, 0x40, 0x3c, 0xca, 0x26, 0x39, 0xbd,
    0x6a, 0x45, 0x0f, 0x28, 0xf6, 0x95, 0x2d, 0x8e,
    0x11, 0x1c, 0xbe, 0x95, 0xf0, 0x36, 0x98, 0xc2,
    0x39, 0xb6, 0x61, 0xe4, 0x45, 0xd6, 0x51, 0x1a,
    0x16, 0x61, 0x64, 0x01, 0x17, 0x66, 0x57, 0xcd,
    0xfb, 0x0a, 0x17, 0x51, 0xc8, 0x5d, 0xaa, 0xf0,
    0xa4, 0x4d, 0x24, 0x24, 0xfb, 0x4c, 0xa4, 0x5c,
    0x76, 0x5b, 0xd3, 0x63, 0xf7, 0xe9, 0x07, 0xef,
    0xf0, 0x1a, 0xd5, 0x58, 0xd1, 0x7c, 0x17, 0x30,
    0xd8, 0x09, 0x9b, 0xcb, 0x39, 0x7e, 0x6e, 0xff,
    0x39, 0xc4, 0xc3, 0x4d, 0x6c, 0x7f, 0x48, 0x90,
    0x50, 0xaa, 0x04, 0x79, 0x40, 0x75, 0x6e, 0x30,
    0xa9, 0xe7, 0xdf, 0xd6, 0x35, 0x6b, 0xae, 0x00,
    0xac, 0x8b, 0x39, 0x2d, 0xda, 0xef, 0xa6, 0xb9,
    0x7c, 0x1a, 0xa4, 0x83, 0x9e, 0x6d, 0x9b, 0x2d,
    0x54, 0xdb, 0x62, 0x92, 0x96, 0x41, 0xf7, 0x34,
    0x9c, 0x63, 0x57, 0x5b, 0x80, 0x53, 0x39, 0xd1,
    0x98, 0xf5, 0xd1, 0x44, 0x4a, 0xf7, 0xb4, 0xff,
    0xd8, 0x5e, 0x05, 0xdf, 0xdf, 0xc0, 0x69, 0x70,
    0xdb, 0xde, 0xc0, 0x1b, 0x54, 0x4d, 0xa9, 0xbe,
    0x55, 0xd1, 0x03, 0x5b, 0x0a, 0x0a, 0xf5, 0xaa,
    0x48, 0xfe, 0x36, 0x2d, 0x1f, 0x1b, 0x80, 0x8f,
    0xba, 0xbe, 0x5d, 0xe6, 0x41, 0x33, 0x14, 0xed,
    0xd3, 0xde, 0x88, 0x6d, 0x67, 0xa1, 0x23, 0x7b,
    0xe8, 0xee, 0xe3, 0xbe, 0x25, 0xc3, 0xab, 0x54,
    0x50, 0x59, 0xd6, 0xce, 0x29, 0xb5, 0x1c, 0x21,
    0x7c, 0xd6, 0x6e, 0xe8, 0xea, 0x55, 0x9e, 0xc9,
    0xeb, 0xdb, 0x5a, 0x6f, 0x27, 0x08, 0x0e, 0xfc,
    0x89, 0x7c, 0xd4, 0x6d, 0x65, 0xac, 0x58, 0xf9
};

static int test_ccprime_rabin_miller_small(void)
{
    const cc_unit zero[2] = { 0, 0 };
    is(ccprime_rabin_miller(2, zero, 1, global_test_rng), 0, "primality test failed");

    const cc_unit one[2] = { 1, 0 };
    is(ccprime_rabin_miller(1, one, 1, global_test_rng), 0, "primality test failed");
    is(ccprime_rabin_miller(2, one, 1, global_test_rng), 0, "primality test failed");

    const cc_unit two[1] = { 2 };
    is(ccprime_rabin_miller(1, two, 1, global_test_rng), 1, "primality test failed");

    const cc_unit even[2] = { 2, 2 };
    is(ccprime_rabin_miller(2, even, 1, global_test_rng), 0, "primality test failed");

    const cc_unit odd[2] = { 3, 0 };
    is(ccprime_rabin_miller(2, odd, 1, global_test_rng), 1, "primality test failed");

    const cc_unit odd_le[2] = { 0, 3 };
    is(ccprime_rabin_miller(2, odd_le, 1, global_test_rng), 0, "primality test failed");

    const cc_unit one_one[2] = { 1, 1 };
    is(ccprime_rabin_miller(1, one_one, 1, global_test_rng), 0, "primality test failed");

    return 0;
}

static int test_ccprime_rabin_miller_zero_rounds(void)
{
    cc_unit p[] = { 0x9c75b };
    is(ccprime_rabin_miller(1, p, 0, global_test_rng), CCERR_PARAMETER, "MR should fail");

    return 0;
}

static int test_ccprime_rabin_miller_known_primes(void)
{
    cc_size n = ccn_nof_size(sizeof(PRIME_2048));
    cc_unit p[n];
    ccn_read_uint(n, p, sizeof(PRIME_2048), PRIME_2048);
    is(ccprime_rabin_miller(n, p, 10, global_test_rng), 1, "primality test failed");

    n = ccn_nof_size(sizeof(PRIME_1024));
    ccn_read_uint(n, p, sizeof(PRIME_1024), PRIME_1024);
    is(ccprime_rabin_miller(n, p, 10, global_test_rng), 1, "primality test failed");

    n = ccn_nof_size(sizeof(PRIME_928));
    ccn_read_uint(n, p, sizeof(PRIME_928), PRIME_928);
    is(ccprime_rabin_miller(n, p, 10, global_test_rng), 1, "primality test failed");

    n = ccn_nof_size(sizeof(PRIME_512));
    ccn_read_uint(n, p, sizeof(PRIME_512), PRIME_512);
    is(ccprime_rabin_miller(n, p, 10, global_test_rng), 1, "primality test failed");

    n = 1;
    p[0] = 0x9c75b;
    is(ccprime_rabin_miller(n, p, 10, global_test_rng), 1, "primality test failed");

    return 0;
}

struct vector {
    char *p;
    char *b;
    int r;
};

static struct vector vectors[] = {
    // Test a small prime.
    { .p = "7", .b = "1", .r = 1 },
    { .p = "7", .b = "2", .r = 1 },
    { .p = "7", .b = "3", .r = 1 },
    { .p = "7", .b = "4", .r = 1 },
    { .p = "7", .b = "5", .r = 1 },
    { .p = "7", .b = "6", .r = 1 },

    // Some random inputs where b^d = p-1.
    { .p = "d6b4ffc7cf70b2a2fc5d6023015875504d40e3dcce7c2e6b762c3de7bb806a5074144e7054198dabf53d23108679ccc541d5a99efeb1d1abaf89e0dbcead2a8b",
      .b = "00fabbafdbec6494ddb5ea4bf458536e87082369b0e53a200ed413f3e64b2fddc7c57c565710fbe73fae5b188fce97d8dcca74c2b5d90906c96d3c2c358a735c",
      .r = 1 },
    { .p = "52cc61c42b341ad56dc11495e7cb2fe31e506b9e99522efbf44cd7c28468d3833c5e360f3c77b0aa43c0495c4e14665ab0d7cee9294c722f0de47d4401828401",
      .b = "3bdc9639c0fc2e77ab48d46e0b4ac6529c11c900e8fe4d82d75767c0556feb23d3f42d4924d16876a743feb386b7b84c7fd16a6c252f662faf0024d19972e62f",
      .r = 1 },
    { .p = "cff9897aa7dce0f2afad262b2de57d301305de717f3539c537c4ce062f8cb70df13fbc1eb4a3b9f0958a8810d1ca9042b4f23334b285a15fee3fc66498761d4b",
      .b = "9ceb43132fddf9ee4104ea1cb3eb2253c1d7f803f05f0305de9e31a17dd75832f47b8bf189a9b7ca0905f2a7470d9c6349080f481ff1708696fa12d972e7d7ba",
      .r = 1 },

    // Some random inputs where b^(2^j*d) = p-1.
    { .p = "67d1825dad5344170e65247a87aef1634a1b32bdc22f2f04d9d2959767bb5a27610fba55cd607e0f9fdd9fbb0f7f98e40d5e1eb2f52318fb5be4dbfd30d38861",
      .b = "0260fb14724ff80984736859d8755ee98b25bcb56db9fde1db001a1e1273374034c5b75fd60b3710c7a08ce7d390776f010f384d4e32943cf0c477497d53e9e0",
      .r = 1 },
    { .p = "ad0bc85b58aaa204177aa9431a40929beb1cbea2dd6f66a25cc54600013213b225ba881805661df43f4208965ada7aacc8095d07d3cbef1a7bbfaae8b745f731",
      .b = "3d9310f20e9c80269fa6830c7e1a6f02fc5c58646001a9ef6b8b3e496602ff22c3dcb2ddb6a221723fc1722ce237fb46f7a7bb2945e415c8839b15a972f076c9",
      .r = 1 },
    { .p = "b25c917f55f6c7b596921daba919f35039e5d805119c1587e99849dd7104460c86214f162a6f17aea847bc7f3859e59f2991d457059511972ef373d4bc75e309",
      .b = "a1f10b261dee84619b0423201d46af19eef9ec0612cf947c4d5c36c0c4b28207f75967e69452eabad0a5dcd28f27f7a8a7ed9c8b3e5026c6e0ba5634d94c2d44",
      .r = 1 },

    // Some random inputs where b^d = 1.
    { .p = "d3eeb0eff05b6992e9fa61b02755e155f4aae28c6e45ddb874edd86acdd2d83d18a20e0e00d8b8bc94b92d14fc3f41ced6ababe8ac98c7730c075dbe0f699369",
      .b = "6b7717269c6225203681a1cacec87cacd83003ec6e9e3f04effcc4f86634770c0860e1f2770b8f303719a44949664a1094205a99d95a0856758fed66d690105e",
      .r = 1 },
    { .p = "64561b8d9aa50340c3a01ccb3e6e17f5023513661c012be288f3900a3ca76890e67290b9560fa1d480f9d2aacccca581b5690636665f243fa13aff5d0bff12d3",
      .b = "1f5ff70d3d60671ebc5fbfca731898a04438053dbc3c841e6335f487e457d92d9efb5d506d5bef6872d58d12b9a41c950bfc38d12ed977c90eacdd6535b811a0",
      .r = 1 },
    { .p = "69c63fbf44df21b0ed0ee929a740c12d1f3f064da0dcd9d509f31fa45fa27d1a759ab5a9f6f1040d7ee90a0b1e68f779273c41ea1c1198fd547ff6bd70c7e787",
      .b = "5f7996a9bbfd8fd88e472220b70077bfdacdd63d88885134431f024c2acb7126827b174eb093eb5313f07bb5461de9b0feb7d77ca2c39c2a323a150f33ea525f",
      .r = 1 },

    // Some random composites.
    { .p = "28cc3e08c44571c6dcb98a9ab8b4f3e2b16e1f884997d94a3188bcbb7f1b7cdaecdae8329c013ec8f75dc00004da0039943e4262cd080b16a42910102e00dddb",
      .b = "00512061ab1c69931c2fa0bb89d8d09f3c9209230bf927ddd6fb6a72075f967ed3c4dbb5f437bf4d31ca7344782b22011ad56609dc19aed65319bababfc13dd7",
      .r = 0 },
    { .p = "4eeb7b4d371c45fe8586fee3b1efd792176b70f6cc2698dfa1dd028366626febe0199c3c5f77a5c3cad0057a04767383051d41965255d03681b2a37edad34a9b",
      .b = "4afc2e85f84017b3fd6967a227eb74c8297b40ea02733d9513bff9b3f01081963f25872f4254afc4e9321eea35b2a1e42eadb186fcc84f2f30f4a994350b93b8",
      .r = 0 },
    { .p = "8e35a959555dd2eb66c65cee3c264071d20671f159e1f9896f1d0ceb041905fcf053eacc189de317c3ee6f93901223cbf30d5b7ddbbdab981790e2f6397e6803",
      .b = "44c0153759309ec4e5b1e59d57c1b126545ef7ea302b6e43561df4d16068b922389d6924f01c945d9080d1f93a0732599bdedae72d6d590839dc0884dd860441",
      .r = 0 },

    // 0x6c1 = 1729 = 7 * 13 * 19 is a Fermat pseudoprime.
    { .p = "6c1", .b = "0b8", .r = 0 },
    { .p = "6c1", .b = "111", .r = 0 },
    { .p = "6c1", .b = "11d", .r = 0 },
    { .p = "6c1", .b = "19c", .r = 0 },
    { .p = "6c1", .b = "223", .r = 0 },
    { .p = "6c1", .b = "3aa", .r = 0 },
    { .p = "6c1", .b = "653", .r = 0 },

    // 1729 has a number of false witnesses.
    { .p = "6c1", .b = "078", .r = 1 }, // b^d = 1
    { .p = "6c1", .b = "0eb", .r = 1 }, // b^d = 1
    { .p = "6c1", .b = "178", .r = 1 }, // b^d = p-1
    { .p = "6c1", .b = "1aa", .r = 1 }, // b^d = p-1
    { .p = "6c1", .b = "271", .r = 1 }, // b^d = 1
    { .p = "6c1", .b = "2b2", .r = 1 }, // b^d = 1

    // 1 and p-1 are always non-witnesses.
    { .p = "6c1", .b = "001", .r = 1 },
    { .p = "6c1", .b = "6c0", .r = 1 },

    // 0x41 = 65
    { .p = "41", .b = "01", .r = 1 }, // b^d = 1
    { .p = "41", .b = "08", .r = 1 }, // b^(d*2^j) = p-1
    { .p = "41", .b = "12", .r = 1 }, // b^(d*2^j) = p-1
    { .p = "41", .b = "2f", .r = 1 }, // b^(d*2^j) = p-1
    { .p = "41", .b = "39", .r = 1 }, // b^(d*2^j) = p-1
    { .p = "41", .b = "40", .r = 1 }, // b^d = p-1

    // 0x55 = 85
    { .p = "55", .b = "01", .r = 1 }, // b^d = 1
    { .p = "55", .b = "0d", .r = 1 }, // b^(d*2^j) = p-1
    { .p = "55", .b = "26", .r = 1 }, // b^(d*2^j) = p-1
    { .p = "55", .b = "2f", .r = 1 }, // b^(d*2^j) = p-1
    { .p = "55", .b = "48", .r = 1 }, // b^(d*2^j) = p-1
    { .p = "55", .b = "54", .r = 1 }, // b^d = p-1

    // Witnesses for 65.
    { .p = "41", .b = "2c", .r = 0 },
    { .p = "41", .b = "16", .r = 0 },
    { .p = "41", .b = "14", .r = 0 },
    { .p = "41", .b = "02", .r = 0 },
    { .p = "41", .b = "3a", .r = 0 },

    // Witnesses for 85.
    { .p = "55", .b = "40", .r = 0 },
    { .p = "55", .b = "07", .r = 0 },
    { .p = "55", .b = "23", .r = 0 },
    { .p = "55", .b = "2e", .r = 0 },
    { .p = "55", .b = "2a", .r = 0 },
};

const size_t vectors_n = CC_ARRAY_LEN(vectors);

static void test_ccprime_rabin_miller_vectors(void)
{
    for (unsigned i = 0; i < vectors_n; i++) {
        struct vector *tv = &vectors[i];
        ccnBuffer p = hexStringToCcn(tv->p);
        ccnBuffer b = hexStringToCcn(tv->b);
        cc_assert(p->len == b->len);
        cc_size n = p->len;

        CC_DECL_WORKSPACE_TEST(ws);

        ccprime_mr_decl_n(n, mr);
        is(ccprime_rabin_miller_init_ws(ws, mr, n, p->units), CCERR_OK, "MR init failed");
        is(ccprime_rabin_miller_iteration_ws(ws, mr, b->units, global_test_rng), tv->r, "MR iteration failed");

        free(p);
        free(b);

        CC_FREE_WORKSPACE(ws);
    }
}

int ccprime_rabin_miller_tests(TM_UNUSED int argc, TM_UNUSED char *const *argv)
{
    plan_tests(14 + vectors_n * 2);

    test_ccprime_rabin_miller_small();
    test_ccprime_rabin_miller_zero_rounds();
    test_ccprime_rabin_miller_known_primes();
    test_ccprime_rabin_miller_vectors();

    return 0;
}

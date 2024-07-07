/* Copyright (c) (2012,2015,2019,2021) Apple Inc. All rights reserved.
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
#include <corecrypto/ccrc4.h>
#include "cc_runtime_config.h"
#include "crypto_test_rc4.h"

// static int verbose = 1;

#if (CCRC4_CIPHER == 0)
entryPoint(ccrc4_cipher_tests,"ccrc4 cipher")
#else

typedef struct stream_test_vector_t {
    char *keyStr;
    char *plainStr;
    char *cipherStr;
} stream_test_vector_s, *stream_test_vector;

/* some simple test vectors from wikipedia... */

stream_test_vector_s rc4_test_vectors[] = {
    { "Key", "Plaintext", "bbf316e8d940af0ad3" },
    { "Wiki", "pedia", "1021bf0420" },
    { "Secret", "Attack at dawn", "45a01f645fc35b383552544b9bf5" },
    { NULL, NULL, NULL },
};


static int test_ccrc4(const struct ccrc4_info *rc4, stream_test_vector v)
{
    ccrc4_ctx_decl(rc4->size, skey);
    size_t keylen = strlen(v->keyStr);
    size_t ptlen = strlen(v->plainStr);
    byteBuffer ct = hexStringToBytes(v->cipherStr);
    byteBuffer r = mallocByteBuffer(ptlen);
    char retStr[ptlen+1];
    
    rc4->init(skey, keylen, v->keyStr);
    rc4->crypt(skey, ptlen, v->plainStr, r->bytes);
    ok_or_fail(bytesAreEqual(ct, r), "Encrypt Results == CipherText");
    
    retStr[ptlen] = 0;
    rc4->init(skey, keylen, v->keyStr);
    rc4->crypt(skey, ct->len, ct->bytes, retStr);
    ok_or_fail(strncmp(v->plainStr, retStr, ptlen) == 0, "Decrypt Results == PlainText");
    
    free(ct);
    free(r);
    return 1;
}

static const int kTestTestCount = 9;

int ccrc4_cipher_tests(TM_UNUSED int argc, TM_UNUSED char *const *argv)
{
	plan_tests(kTestTestCount);
    
    for(int i=0; rc4_test_vectors[i].keyStr != NULL; i++) {
        ok(test_ccrc4(ccrc4(), &rc4_test_vectors[i]), "RC4 Tests OK");
    }
    return 0;
}
#endif


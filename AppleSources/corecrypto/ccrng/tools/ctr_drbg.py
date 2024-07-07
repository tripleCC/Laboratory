# Copyright (c) (2020) Apple Inc. All rights reserved.
#
# corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
# is contained in the License.txt file distributed with corecrypto) and only to
# people who accept that license. IMPORTANT:  Any license rights granted to you by
# Apple Inc. (if any) are limited to internal use within your organization only on
# devices and computers you own or control, for the sole purpose of verifying the
# security characteristics and correct functioning of the Apple Software.  You may
# not, directly or indirectly, redistribute the Apple Software or any portions thereof.

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import hashlib
import binascii
import struct

RESEED_INTERVAL = 1 << 48

dec64 = lambda s: struct.unpack('>Q', s)[0]
enc64 = lambda i: struct.pack('>Q', i)

dec32 = lambda s: struct.unpack('>L', s)[0]
enc32 = lambda i: struct.pack('>L', i)

xor = lambda a,b: bytes([x^y for (x,y) in zip(a,b)])

class CTR_DRBG:
    _OUTLEN = 16
    _KEYLEN = 32

    def _block_encrypt(self, key, value):
        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
        encryptor = cipher.encryptor()
        return encryptor.update(value) + encryptor.finalize()

    def _bcc(self, K, data):
        chaining_value = bytes(self._OUTLEN)
        n = len(data) // self._OUTLEN

        for i in range(0, n):
            input_block = xor(chaining_value, data[i * self._OUTLEN:(i + 1) * self._OUTLEN])
            chaining_value = self._block_encrypt(K, input_block)

        return chaining_value

    def _df(self, input_string, nbytes):
        L = enc32(len(input_string))
        N = enc32(nbytes)
        S = L + N + input_string + b"\x80"

        while len(S) % self._OUTLEN != 0:
            S += b"\x00"

        i = 0
        temp = b""
        K = bytes([x for x in range(0, self._KEYLEN)])

        while len(temp) < self._KEYLEN + self._OUTLEN:
            IV = enc32(i) + bytes(12)
            temp = temp + self._bcc(K, IV + S)
            i += 1

        K = temp[:self._KEYLEN]
        X = temp[self._KEYLEN:self._KEYLEN + self._OUTLEN]

        temp = b""
        while len(temp) < nbytes:
            X = self._block_encrypt(K, X)
            temp = temp + X
        return temp[:nbytes]

    def __init__(self, entropy, nonce, ps):
        seed_material = entropy + nonce + ps
        seed_material = self._df(seed_material, self._OUTLEN + self._KEYLEN)
        self.V = bytes(self._OUTLEN)
        self.K = bytes(self._KEYLEN)

        self._update(seed_material)
        self.reseed_counter = 1

    def _update(self, provided_data):
        temp = b""
        seedlen = self._OUTLEN + self._KEYLEN

        while len(temp) < seedlen:
            nc = dec64(self.V[8:]) + 1
            self.V = self.V[:8] + enc64(nc)
            temp += self._block_encrypt(self.K, self.V)

        temp = xor(temp[:seedlen], provided_data)
        self.K = temp[:self._KEYLEN]
        self.V = temp[-self._OUTLEN:]


    def reseed(self, entropy, ai = b""):
        seedlen = self._OUTLEN + self._KEYLEN
        seed_material = entropy + ai
        seed_material = self._df(seed_material, seedlen)
        self._update(seed_material)
        self.reseed_counter = 1

    def generate(self, n, ai = b""):
        seedlen = self._OUTLEN + self._KEYLEN
        if not (self.reseed_counter <= RESEED_INTERVAL):
            return None

        if len(ai) != 0:
            ai = self._df(ai, seedlen)
            self._update(ai)
        else:
            ai = bytes(seedlen)

        temp = b""
        while len(temp) < n:
            nc = dec64(self.V[8:]) + 1
            self.V = self.V[:8] + enc64(nc)
            temp += self._block_encrypt(self.K, self.V)

        self._update(ai)
        self.reseed_counter += 1
        return temp[:n]

'''
struct ccdrbg_vector {
    size_t entropyLen;
    const void *entropy;
    size_t nonceLen;
    const void *nonce;
    size_t psLen;
    const void *ps; /* Personalization String */
    size_t ai1Len;
    const void *ai1; /* Additional Input */
    size_t entropyReseedLen;
    const void *entropyReseed;
    size_t aiReseedLen;
    const void *aiReseed; /* Additional Input */
    size_t ai2Len;
    const void *ai2; /* Additional Input */
    size_t randomLen;
    const void *random; /* Returned bytes */
};
'''

if __name__ == "__main__":
    entropy = b"\xec\x01\x97\xa5\x5b\x0c\x99\x62\xd5\x49\xb1\x61\xe9\x6e\x73\x2a\x0e\xe3\xe1\x77\x00\x4f\xe9\x5f\x5d\x61\x20\xbf\x82\xe2\xc0\xea"
    nonce = b"\x9b\x13\x1c\x60\x1e\xfd\x6a\x7c\xc2\xa2\x1c\xd0\x53\x4d\xe8\xd8"
    ps =bytes([0x78, 0x6e, 0x75, 0x70, 0x72, 0x6e, 0x67, 0x04])
    ai1 = b""
    entropy_reseed = b"\x61\x81\x0b\x74\xd2\xed\x76\x36\x5a\xe7\x0e\xe6\x77\x2b\xba\x49\x38\xee\x38\xd8\x19\xec\x1a\x74\x1f\xb3\xff\x4c\x35\x2f\x14\x0c"
    ai_reseed = b""
    ai2 = b""
    random = b"\x7e\xa8\x9c\xe6\x13\xe1\x1b\x5d\xe7\xf9\x79\xe1\x4e\xb0\xda\x4d"
    
    drbg = CTR_DRBG(entropy, nonce, ps)
    r1 = drbg.generate(16, ai = ai1)
    drbg.reseed(entropy_reseed, ai = ai_reseed)
    r2 = drbg.generate(16, ai = ai2)
    #assert r2 == random
    print(binascii.hexlify(r1))



    entropy = b"\xa3\xa0\x68\x3a\x84\x12\x51\x36\x11\x3c\x1e\x68\x0a\x18\x4c\x0d\x57\x3d\x24\x1d\x9f\xae\x74\xb7\x28\xe5\x8e\xd1\xf0\x1d\x85\x20"
    nonce = b"\x8d\xb5\x71\x0e\xd2\x87\xd7\x1d\xd2\xf0\x51\x64\x8e\xd5\x63\xc5"
    ps = b""
    ai1 = b""
    entropy_reseed = b"\x2f\xfa\x80\x67\x39\xc0\x10\x06\x62\x8b\x60\x5e\x18\x73\xe3\x02\x23\xc4\x50\x1b\xc6\x4d\xdb\x53\x18\xed\xb6\xfd\xa4\x59\xc8\x88"
    ai_reseed = b""
    ai2 = b"\x51\xa9\x24\x03\x30\xed\x0f\x1e\x8b\x18\x70\xb5\x31\x75\xfc\xf1\x0f\x45\x6e\x4e\x4b\x0b\xbf\x89\xa2\x19\xa5\xcb\x00\x5a\x4c\x14"
    random = b"\x64\x69\x47\x4a\xf0\x67\x02\x13\x44\xb4\x12\xc8\x9d\xa4\x4f\x97"

    drbg = CTR_DRBG(entropy, nonce, ps)
    r1 = drbg.generate(16, ai = ai1)
    drbg.reseed(entropy_reseed, ai = ai_reseed)
    r2 = drbg.generate(16, ai = ai2)
    #assert r2 == random

    entropy = binascii.unhexlify("ec0197a55b0c9962d549b161e96e732a0ee3e177004fe95f5d6120bf82e2c0ea")
    nonce = binascii.unhexlify("9b131c601efd6a7cc2a21cd0534de8d8")
    ps = bytes([0x78, 0x6e, 0x75, 0x70, 0x72, 0x6e, 0x67, 0x04])
    reseed = binascii.unhexlify("61810b74d2ed76365ae70ee6772bba4938ee38d819ec1a741fb3ff4c352f140c")
    drbg = CTR_DRBG(entropy, nonce, ps)
    r1 = drbg.generate(16)
    drbg.reseed(reseed)
    r2 = drbg.generate(16)
    print("==========")
    print(binascii.hexlify(r1))
    print(binascii.hexlify(r2))



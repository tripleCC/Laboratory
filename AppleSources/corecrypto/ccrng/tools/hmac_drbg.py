# Copyright (c) (2020) Apple Inc. All rights reserved.
#
# corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
# is contained in the License.txt file distributed with corecrypto) and only to
# people who accept that license. IMPORTANT:  Any license rights granted to you by
# Apple Inc. (if any) are limited to internal use within your organization only on
# devices and computers you own or control, for the sole purpose of verifying the
# security characteristics and correct functioning of the Apple Software.  You may
# not, directly or indirectly, redistribute the Apple Software or any portions thereof.

import hashlib
import binascii
import hmac

RESEED_INTERVAL = 1 << 48

class HMAC_DRBG:
    def __init__(self, ihash, entropy, nonce, ps, fips = True):
        self.hash = ihash
        self.hash_len = self.hash().digest_size
        self.fips = fips

        if not len(entropy) > (self.hash_len // 2):
            raise Exception("Not enough input entropy")

        seed_material = entropy + nonce + ps
        self.K = b"\x00" * self.hash_len
        self.V = b"\x01" * self.hash_len

        self._update(seed_material)

        self.reseed_counter = 1

    def reseed(self, entropy, ai = b""):
        seed_material = entropy + ai
        self._update(seed_material)
        self.reseed_counter = 1

    def generate(self, n, ai = b""):
        if not ((self.reseed_counter <= RESEED_INTERVAL) or (not self.fips)):
            return None

        if len(ai) != 0:
            self._update(ai)

        temp = b""
        while len(temp) < n:
            self.V = hmac.digest(self.K, self.V, self.hash)
            temp += self.V

        self._update(ai)
        self.reseed_counter += 1
        return temp[:n]

    def _update(self, data):
        self.K = hmac.digest(self.K, self.V + b"\x00" + data, self.hash)
        self.V = hmac.digest(self.K, self.V, self.hash)
        if len(data) != 0:
            self.K = hmac.digest(self.K, self.V + b"\x01" + data, self.hash)
            self.V = hmac.digest(self.K, self.V, self.hash)

if __name__ == "__main__":
    entropy = b"\x06\x03\x2c\xd5\xee\xd3\x3f\x39\x26\x5f\x49\xec\xb1\x42\xc5\x11\xda\x9a\xff\x2a\xf7\x12\x03\xbf\xfa\xf3\x4a\x9c\xa5\xbd\x9c\x0d"
    nonce = b"\x0e\x66\xf7\x1e\xdc\x43\xe4\x2a\x45\xad\x3c\x6f\xc6\xcd\xc4\xdf"
    ps = b""
    ai1 = b""
    entropy_reseed = b"\x01\x92\x0a\x4e\x66\x9e\xd3\xa8\x5a\xe8\xa3\x3b\x35\xa7\x4a\xd7\xfb\x2a\x6b\xb4\xcf\x39\x5c\xe0\x03\x34\xa9\xc9\xa5\xa5\xd5\x52"
    ai_reseed = b""
    ai2 = b""
    random = b"\x76\xfc\x79\xfe\x9b\x50\xbe\xcc\xc9\x91\xa1\x1b\x56\x35\x78\x3a\x83\x53\x6a\xdd\x03\xc1\x57\xfb\x30\x64\x5e\x61\x1c\x28\x98\xbb\x2b\x1b\xc2\x15\x00\x02\x09\x20\x8c\xd5\x06\xcb\x28\xda\x2a\x51\xbd\xb0\x38\x26\xaa\xf2\xbd\x23\x35\xd5\x76\xd5\x19\x16\x08\x42\xe7\x15\x8a\xd0\x94\x9d\x1a\x9e\xc3\xe6\x6e\xa1\xb1\xa0\x64\xb0\x05\xde\x91\x4e\xac\x2e\x9d\x4f\x2d\x72\xa8\x61\x6a\x80\x22\x54\x22\x91\x82\x50\xff\x66\xa4\x1b\xd2\xf8\x64\xa6\xa3\x8c\xc5\xb6\x49\x9d\xc4\x3f\x7f\x2b\xd0\x9e\x1e\x0f\x8f\x58\x85\x93\x51\x24"
    
    drbg = HMAC_DRBG(hashlib.sha256, entropy, nonce, ps, fips = True)
    drbg.reseed(entropy_reseed, ai = ai_reseed)
    r1 = drbg.generate(128, ai = ai1)
    r2 = drbg.generate(128, ai = ai2)
    assert r2 == random

# Copyright (c) (2020-2022) Apple Inc. All rights reserved.
#
# corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
# is contained in the License.txt file distributed with corecrypto) and only to
# people who accept that license. IMPORTANT:  Any license rights granted to you by
# Apple Inc. (if any) are limited to internal use within your organization only on
# devices and computers you own or control, for the sole purpose of verifying the
# security characteristics and correct functioning of the Apple Software.  You may
# not, directly or indirectly, redistribute the Apple Software or any portions thereof.

from hmac_drbg import HMAC_DRBG
import binascii
import hashlib

FIPS_REQUEST_SIZE_THRESHOLD = 12

class RNG:
    ENTROPY_SIZE = 64
    def __init__(self, drbg, seed, nonce, ps):
        self.drbg = drbg # HMAC_DRBG(ihash, seed, nonce, ps, fips = True)

        self.cache_size = 256
        self.cache_pos = 256
        self.cache = bytes(self.cache_size)
        
        self.predictionbreak = False

    def reseed(self, seed, nonce = b""):
        self.drbg.reseed(seed, ai = nonce)
        self.cache_pos = 256

    def force_reseed_with_getentropy(self, nonce):
        entropy = self.getentropy(self.ENTROPY_SIZE)
        self.reseed(entropy, nonce = nonce)

    def generate(self, n):
        random = b""
        bypass_cache = n >= FIPS_REQUEST_SIZE_THRESHOLD
        while n > 0:
            status = True
            if self.needreseed():
                status = self.getentropy_and_reseed()
            if not status:
                raise Exception("Uh oh...")

            if (not bypass_cache) and (n <= self.cache_size):
                take_n = min(n, len(self.cache[self.cache_pos:]))
                random += self.cache[self.cache_pos:self.cache_pos + take_n]

                self.cache_pos += take_n
                n -= take_n

                if n > 0:
                    self.cache = self.drbg.generate(self.cache_size)
                    random += self.cache[:n]
                    self.cache_pos = n
                    n = 0
                    
            else:
                req_size = min(n, 4096)
                random += self.drbg.generate(req_size)
                n -= req_size
        return random

    # Internal Functions

    def getentropy_and_reseed(self):
        got_entropy = False
        for retry in range(0, 100):
            entropy = self.getentropy(self.ENTROPY_SIZE)
            if entropy is None:
                continue
            self.reseed(entropy)
            got_entropy = True
            break
        return got_entropy
    

    def needreseed(self, *args, **kwargs):
        if self.predictionbreak:
            return True
        return False

    # Plugable functions
    def getentropy(self, entropy_len):
        return b"\x01" * entropy_len

if __name__ == "__main__":
    seed = bytes(64)
    ps = bytes(32)
    nonce = bytes(8)
    drbg = HMAC_DRBG(hashlib.sha256, seed, nonce, ps, fips = True)
    rng = RNG(drbg, seed, nonce, ps)

    print(f"seed = {binascii.hexlify(seed)}")
    print(f"ps = {binascii.hexlify(ps)}")
    for x in range(0, 8):
        gen = rng.generate(64)
        print(f"gen{x} = {binascii.hexlify(gen)}")

    rng.force_reseed_with_getentropy(bytes(8))
    print("----------------------------------")

    for x in range(0, 8):
        gen = rng.generate(64)
        print(f"gen{x} = {binascii.hexlify(gen)}")






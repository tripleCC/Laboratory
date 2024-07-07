# Copyright (c) (2020,2021,2023) Apple Inc. All rights reserved.
#
# corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
# is contained in the License.txt file distributed with corecrypto) and only to
# people who accept that license. IMPORTANT:  Any license rights granted to you by
# Apple Inc. (if any) are limited to internal use within your organization only on
# devices and computers you own or control, for the sole purpose of verifying the
# security characteristics and correct functioning of the Apple Software.  You may
# not, directly or indirectly, redistribute the Apple Software or any portions thereof.

from ccrng_crypto import RNG as CSPRNG
from ccrng_fortuna import RNG as Fortuna
from ctr_drbg import CTR_DRBG
import binascii
import random
import hashlib
import struct
import enum
import types
import functools

swap64 = lambda i: struct.unpack("<Q", struct.pack(">Q", i))[0]
dec64 = lambda s: struct.unpack('>Q', s)[0]
enc64 = lambda i: struct.pack('>Q', i)
enc64_le = lambda i: struct.pack("<Q", i)

class CCKPRNG_OP(enum.Enum):
    INIT = 0
    USERRESEED = 1
    SCHEDRESEED = 2
    ADDENTROPY = 3
    INIT_CSPRNG = 4

class CCKPRNG:
    def _label(self, op):
        return bytes([0x78, 0x6e, 0x75, 0x70, 0x72, 0x6e, 0x67, op.value])

    def _fortuna_getentropy(self, n):
        nsamples, entropy = self.getentropy(n)

        if nsamples < 0:
            self.entropy_digest_nsamples = 0
            self.first_seed_done = False
            return nsamples, entropy

        if self.first_seed_done:
            return nsamples, entropy

        self.entropy_digest.update(entropy)
        self.entropy_digest_nsamples += nsamples
        if self.entropy_digest_nsamples >= self.entropy_digest_nsamples_needed:
            self.first_seed_done = True
            self.needreseed = True
        return 0, None

    def __init__(self, seed, nonce, getentropy):
        self.needreseed = False
        self.getentropy = getentropy
        self.first_seed_done = False
        self.entropy_digest = hashlib.sha512()
        self.entropy_digest_nsamples_needed = 512
        self.entropy_digest_nsamples = 0
        self.fortuna = Fortuna(self._fortuna_getentropy)

        drbg = CTR_DRBG(seed, nonce, self._label(CCKPRNG_OP.INIT_CSPRNG))
        self.csprng = CSPRNG(drbg, seed, nonce, self._label(CCKPRNG_OP.INIT_CSPRNG))
        setattr(self.csprng, "kprng", self)

        def csprng_needreseed_func(self, kprng):
            needreseed = kprng.needreseed
            kprng.needreseed = False
            return needreseed
        csprng_needreseed = types.MethodType(csprng_needreseed_func, CSPRNG)
        self.csprng.needreseed = functools.partial(csprng_needreseed, self)

        def csprng_getentropy_func(self, kprng, fortuna, entropy_len):
            if kprng.entropy_digest_nsamples >= kprng.entropy_digest_nsamples_needed:
                kprng.entropy_digest_nsamples = 0
                return kprng.entropy_digest.digest()
            else:
                return fortuna.generate(entropy_len)
        csprng_getentropy = types.MethodType(csprng_getentropy_func, CSPRNG)
        self.csprng.getentropy = functools.partial(csprng_getentropy, self, self.fortuna)

    def reseed(self, seed):
        nonce = random.randint(0, (1 << 64) - 1)
        self.csprng.reseed(seed, nonce = enc64_le(nonce))
        return nonce

    def refresh(self):
        success, rdrand = self.fortuna.refresh()
        if success:
            self.needreseed = True
        return (success, rdrand)

    def generate(self, n):
        return self.csprng.generate(n)

def getentropy_all_ones(n):
    return (1024, b"\x01" * n)

if __name__ == "__main__":
    seed = binascii.unhexlify("ec0197a55b0c9962d549b161e96e732a0ee3e177004fe95f5d6120bf82e2c0ea")
    nonce = binascii.unhexlify("9b131c601efd6a7cc2a21cd0534de8d8")
    kprng = CCKPRNG(seed, nonce, getentropy_all_ones)

    g1 = kprng.generate(16)
    print(f"g1 = {binascii.hexlify(g1)}")

    s1 = bytes(16)
    n1 = kprng.reseed(s1)
    print(f"n1 = {swap64(n1)}")

    g2 = kprng.generate(16)
    print(f"g2 = {binascii.hexlify(g2)}")

    print(f"Need reseed ? {kprng.needreseed}")
    refreshed, rdrand1 = kprng.refresh()
    print(f"refreshed ? = {refreshed}")
    print(f"rdrand1 = {rdrand1}")
    print(f"Need reseed ? {kprng.needreseed}")

    g3 = kprng.generate(16)
    print(f"g3 = {binascii.hexlify(g3)}")

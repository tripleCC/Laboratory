# Copyright (c) (2019,2020,2023) Apple Inc. All rights reserved.
#
# corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
# is contained in the License.txt file distributed with corecrypto) and only to
# people who accept that license. IMPORTANT:  Any license rights granted to you by
# Apple Inc. (if any) are limited to internal use within your organization only on
# devices and computers you own or control, for the sole purpose of verifying the
# security characteristics and correct functioning of the Apple Software.  You may
# not, directly or indirectly, redistribute the Apple Software or any portions thereof.

import enum
import struct
import hashlib
import inspect
import random
from functools import wraps
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

dec64 = lambda s: struct.unpack('>Q', s)[0]
enc64 = lambda i: struct.pack('>Q', i)

dec32 = lambda s: struct.unpack('>L', s)[0]
enc32 = lambda i: struct.pack('>L', i)

# least significant set bit of x (indexed from one)
def ffs(x):
    assert x > 0
    i = 1
    while x & 1 == 0:
        i += 1
        x >>= 1
    return i

def enforce_byte_args(f):
    @wraps(f)
    def wrapper(*args, **kwds):
        for i, (param_name, param_input) in enumerate(zip(inspect.signature(f).parameters.keys(), args)):
            if param_name.endswith("_b"):
                if not type(param_input) is bytes:
                    raise Exception("Arg %d is of type %s, not bytes!" % (i, type(param_input)))
        return f(*args, **kwds)
    return wrapper

@enforce_byte_args
def F(ctx, outlen):
    cipher = Cipher(algorithms.AES(ctx.key), modes.CTR(ctx.ctr), backend=default_backend())
    encryptor = cipher.encryptor()
    ctx.key = encryptor.update(b"\x00" * len(ctx.key))
    new_ctr = dec64(ctx.ctr[4:12]) + 1
    ctx.ctr = b"%b%b%b" % (ctx.ctr[:4], enc64(new_ctr), bytes(4))
    return encryptor.update(b"\x00" * outlen) + encryptor.finalize()

_NPOOLS = 32

_REFRESH_MIN_NSAMPLES = 32

class Diagnostics(object):
    def __init__(self):
        self.nreseeds = 0
        self.userreseed_nreseeds = 0
        self.schedreseed_nreseeds = 0
        self.schedreseed_nsamples_max = 0
        self.addentropy_nsamples_max = 0
        self.pools = [PoolDiagnostics() for _ in range(_NPOOLS)]

class PoolDiagnostics(object):
    def __init__(self):
        self.nsamples = 0
        self.ndrains = 0
        self.nsamples_max = 0


class Generator(object):
    pass

class Pool(object):
    pass

class EntropyBuffer(object):
    def __init__(self, nbytes):
        self.buf = bytearray(nbytes)
        self.nsamples = 0

class RNGError(Exception):
    class Kind(enum.IntEnum):
        initgen_range = 1
        initgen_init = 2
        generate_range = 3
        generate_init = 4
        generate_reqsize = 5

    def __init__(self, kind, note):
        self.kind = kind
        self.note = note

class RNG(object):
    _PRNG_NAME    = b"xnuprng"
    _INIT         = _PRNG_NAME + b"\x00"
    _USER_RESEED  = _PRNG_NAME + b"\x01"
    _SCHED_RESEED = _PRNG_NAME + b"\x02"
    _ADD_ENTROPY  = _PRNG_NAME + b"\x03"

    _NPOOLS = _NPOOLS

    @enforce_byte_args
    def _hash(ctx, personalization_str_b, data_b):
        assert(ctx.H)
        to_hash = b"%b%b" % (personalization_str_b, data_b)
        hasher = ctx.H()
        hasher.update(to_hash)
        return hasher.digest()

    @enforce_byte_args
    def __init__(ctx, getentropy, H=hashlib.sha256, F=F):
        ctx.H = H
        ctx.F = F
        ctx.seeded = False
        ctx.getentropy = getentropy
        ctx.key = b"%b" % (bytes(32))
        ctx.ctr = b"%b" % (bytes(16))
        ctx.pools = []
        for i in range(0, ctx._NPOOLS):
            pool = Pool()
            pool.data = bytes(32)
            ctx.pools.append(pool)

        ctx.schedule = 0
        ctx.reseed_last = 0
        ctx.reseed_ready = False
        ctx.pool_i = 0

        ctx.diag = Diagnostics()

    def _schedule(ctx):
        pool_in = ctx.pool_i
        ctx.pool_i = (ctx.pool_i + 1) % ctx._NPOOLS

        pool_out = -1
        if pool_in == 0:
            ctx.schedule += 1
            pool_out = ffs(ctx.schedule)

        return pool_in, pool_out

    def _addentropy(ctx, pool_i, rdrand, entropy, nsamples):
        if pool_i == -1:
            return 0

        pool = ctx.pools[pool_i]
        pool.data = ctx._hash(
            ctx._ADD_ENTROPY,
            b"%b%b%b%b" % (enc32(pool_i), pool.data, enc64(rdrand), entropy)
        )

        pool_diag = ctx.diag.pools[pool_i]
        pool_diag.nsamples += nsamples
        pool_diag.nsamples_max = max(pool_diag.nsamples_max, pool_diag.nsamples)
        ctx.diag.addentropy_nsamples_max = max(ctx.diag.addentropy_nsamples_max, nsamples)

        return rdrand

    def _schedreseed(ctx, pool_i):
        if pool_i == -1:
            return

        h = ctx.H()
        h.update(b"%b%b%b" % (ctx._SCHED_RESEED, enc64(ctx.schedule), ctx.key))

        i = 0
        nsamples = 0
        while i < pool_i:
            pool = ctx.pools[i]
            h.update(pool.data)
            pool.data = bytes(32)
            pool_diag = ctx.diag.pools[i]
            nsamples += pool_diag.nsamples
            pool_diag.nsamples = 0
            pool_diag.ndrains += 1
            i += 1

        ctx.key = h.digest()
        ctx.diag.nreseeds += 1
        ctx.diag.schedreseed_nreseeds += 1
        ctx.diag.schedreseed_nsamples_max = max(ctx.diag.schedreseed_nsamples_max, nsamples)
        ctx.reseed_ready = False

        if nsamples >= 1024:
            ctx.seeded = True

    def _reset(ctx):
        ctx.seeded = False
        ctx.diag.nreseeds = 0
        ctx.diag.schedreseed_nsamples_max = 0
        ctx.diag.addentropy_nsamples_max = 0

        for i in range(0, len(ctx.pools)):
            pool_diag = ctx.diag.pools[i]
            pool_diag.nsamples = 0
            pool_diag.ndrains = 0
            pool_diag.nsamples_max = 0

        ctx.schedule = 0
        ctx.pool_i = 0

    def refresh(ctx):
        nsamples, entropy = ctx.getentropy(64)
        rdrand = random.randint(0, (1 << 64) - 1)
        pool_out = -1

        if nsamples > 0:
            pool_in, pool_out = ctx._schedule()
            ctx._addentropy(pool_in, rdrand, entropy, nsamples)
            ctx._schedreseed(pool_out)
        elif nsamples < 0:
            ctx._reset()

        return (pool_out != -1), rdrand

    def generate(ctx, outlen):
        if outlen > 256:
            raise RNGError(RNGError.Kind.generate_reqsize, 'generate: request size out of range')
        if not ctx.seeded:
            return None

        return ctx.F(ctx, outlen)

def getentropy_all_ones(n):
    return (1024, b"\x01" * n)

if __name__ == "__main__":
    rng = RNG(getentropy_all_ones)
    rng.refresh()

    try:
        output = rng.generate(420)
    except RNGError as e:
        assert e.kind is RNGError.Kind.generate_reqsize, "Expecting a generate_reqsize error"

    output1 = rng.generate(32)
    assert len(output1) == 32
    output2 = rng.generate(32)
    assert output1 != output2
    output3 = rng.generate(32)
    assert output2 != output3

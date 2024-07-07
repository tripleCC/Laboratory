# Copyright (c) (2020,2021) Apple Inc. All rights reserved.
#
# corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
# is contained in the License.txt file distributed with corecrypto) and only to
# people who accept that license. IMPORTANT:  Any license rights granted to you by
# Apple Inc. (if any) are limited to internal use within your organization only on
# devices and computers you own or control, for the sole purpose of verifying the
# security characteristics and correct functioning of the Apple Software.  You may
# not, directly or indirectly, redistribute the Apple Software or any portions thereof.

import os
import json
import binascii
import argparse
from ccrng_crypto import RNG
from hmac_drbg import HMAC_DRBG
import hashlib
import random
import math
import types

class Compiler(object):
    def __init__(self):
        self.syms = []
        self.decls = []
        self.symid = 0
        self.prefix = binascii.hexlify(os.urandom(6)).decode("utf-8")
        self.c_struct_data = ""
        self.test_vector_structs = []
        self.STRUCT = None

    def gen_sym(self, name):
        self.symid += 1
        return "cctest_{}_{}_{}".format(self.prefix, name, self.symid)

    def convert_hex_uint8t_list(self, name, data):
        try:
            _ = binascii.unhexlify(data) # Make sure it's hex
            data = data.decode("utf-8")
        except:
            data = binascii.hexlify(data)
            data = data.decode("utf-8")
            if len(data) % 2 != 0:
                data = "0" + data
        data = ["0x{}".format(data[x:x+2]) for x in range(0, len(data), 2)]
        sym = self.gen_sym(name)
        self.c_struct_data += 'static const uint8_t {}[] = {{ {} }};\n'.format(sym, ', '.join(data))
        return (sym, len(data))

    def convert_struct(self, struct_name, name, data):
        sym = self.gen_sym(name)

        fields = []
        for k,v in data.items():
            fields.append('.{} = {}'.format(k, v))

        self.c_struct_data += 'static const struct {} {} = {{ {} }};\n'.format(
            self.STRUCT,
            sym,
            ', '.join(fields)
        )
        return sym


    def add_test_vector(self, name, data):
        assert self.STRUCT is not None
        
        sym = self.convert_struct(self.STRUCT, name, data)
        self.test_vector_structs.append("&{}".format(sym))
        return sym

    def finish_vectors(self, name):
        assert self.STRUCT is not None

        self.c_struct_data += 'static const struct {} *{}[] = {{ {} }};\n\n'.format(
            self.STRUCT,
            name,
            ', '.join(self.test_vector_structs)
        )
        return self.c_struct_data

class CSPRNGV(Compiler):
    '''
    struct ccrng_crypto_hmac_drbg_test_vector {
        unsigned tcId;
        const struct ccdigest_info *(*di)(void);
        const uint8_t *init_seed;
        size_t init_seed_len;
        const uint8_t *init_nonce;
        size_t init_nonce_len;
        const uint8_t *init_ps;
        size_t init_ps_len;
        const uint8_t *gen1;
        size_t gen1_len;
        size_t ngens; // Number of generations
        const uint8_t *genn;
        size_t genn_len;
        const uint8_t *reseed_nonce;
        size_t reseed_nonce_len;
        const uint8_t *gen_after_reseed;
        size_t gen_after_reseed_len;
    }
    '''

    def __init__(self):
        super(CSPRNGV, self).__init__()
        self.STRUCT = "ccrng_crypto_hmac_drbg_test_vector"
        self.UINT8T_BLOBS = ["init_seed", "init_nonce", "init_ps", "gen1", "genn", "reseed_nonce", "gen_after_reseed"]

    def process(self, **kwargs):
        test_vector = {}

        for blob_name in self.UINT8T_BLOBS:
            blob_value = kwargs.get(blob_name, None)
            assert blob_name is not None

            sym, data_len = self.convert_hex_uint8t_list(blob_name, blob_value)
            test_vector[blob_name] = sym
            test_vector["{}_len".format(blob_name)] = data_len
        test_vector["tcId"] = kwargs["tcId"]
        test_vector["di"] = kwargs["di"]
        test_vector["ngens"] = kwargs["ngens"]

        self.add_test_vector("test_vector", test_vector)


if __name__ == "__main__":
    compiler = CSPRNGV()
    tcId = 0
    for ihash, di in [(hashlib.sha256, "ccsha256_di")]:
        for tv in range(0, 11):
            init_seed_len = random.randint(32, 64)
            init_seed = os.urandom(init_seed_len)
            init_nonce_len = random.randint(8, 32)
            init_nonce = os.urandom(init_nonce_len)
            init_ps_len = tv
            init_ps = os.urandom(init_ps_len)

            drbg = HMAC_DRBG(ihash, init_seed, init_nonce, init_ps, fips = True)
            rng = RNG(drbg, init_seed, init_nonce, init_ps)

            gen_amnt = math.floor(tv * 25.5 + 1)
            gen1 = rng.generate(gen_amnt)

            n = (tv + 1) * 10
            for _ in range(0, n):
                _ = rng.generate(gen_amnt)
            genn = rng.generate(gen_amnt)

            reseed_nonce = os.urandom(init_seed_len)

            #print(f"Key Before: {binascii.hexlify(rng.drbg.K)}")
            #print(f"V Before: {binascii.hexlify(rng.drbg.V)}")
            rng.force_reseed_with_getentropy(reseed_nonce)
            #print(f"Key After: {binascii.hexlify(rng.drbg.K)}")
            #print(f"V After: {binascii.hexlify(rng.drbg.V)}")

            gen_after_reseed = rng.generate(gen_amnt)
            compiler.process(init_seed = init_seed, init_nonce = init_nonce, 
                init_ps = init_ps, gen1 = gen1, 
                tcId = tcId, di = di, ngens = n, genn = genn,
                reseed_nonce = reseed_nonce, gen_after_reseed = gen_after_reseed)
            tcId += 1
    with open("../test_vectors/ccrng_crypto_hmac_tvs.kat", "w") as fout:
        fout.write(compiler.finish_vectors("ccrng_crypto_hmac_tvs"))

    # AGGRESSIVE RESEEDS
    def always_needreseed(self):
        return True
    new_needreseed = types.MethodType(always_needreseed, RNG)

    #print("-=-------00-0--------\n\n\n")

    compiler = CSPRNGV()
    tcId = 0
    for ihash, di in [(hashlib.sha256, "ccsha256_di")]:
        for tv in range(0, 11):
            init_seed_len = random.randint(32, 64)
            init_seed = os.urandom(init_seed_len)
            init_nonce_len = random.randint(8, 32)
            init_nonce = os.urandom(init_nonce_len)
            init_ps_len = tv
            init_ps = os.urandom(init_ps_len)

            drbg = HMAC_DRBG(ihash, init_seed, init_nonce, init_ps, fips = True)
            rng = RNG(drbg, init_seed, init_nonce, init_ps)
            rng.needreseed = new_needreseed

            gen_amnt = math.floor(tv * 25.5 + 1)
            #print(f"Key Before: {binascii.hexlify(rng.drbg.K)}")
            #print(f"V Before: {binascii.hexlify(rng.drbg.V)}")
            gen1 = rng.generate(gen_amnt)
            #print(f"Key After: {binascii.hexlify(rng.drbg.K)}")
            #print(f"V After: {binascii.hexlify(rng.drbg.V)}")

            n = (tv + 1) * 10
            for _ in range(0, n):
                _ = rng.generate(gen_amnt)
            genn = rng.generate(gen_amnt)

            reseed_nonce = os.urandom(init_seed_len)
            rng.force_reseed_with_getentropy(reseed_nonce)

            gen_after_reseed = rng.generate(gen_amnt)
            compiler.process(init_seed = init_seed, init_nonce = init_nonce, 
                init_ps = init_ps, gen1 = gen1, 
                tcId = tcId, di = di, ngens = n, genn = genn,
                reseed_nonce = reseed_nonce, gen_after_reseed = gen_after_reseed)
            tcId += 1
    with open("../test_vectors/ccrng_crypto_hmac_always_reseed_tvs.kat", "w") as fout:
        fout.write(compiler.finish_vectors("ccrng_crypto_hmac_always_reseed_tvs"))

    compiler = CSPRNGV()
    tcId = 0
    for ihash, di in [(hashlib.sha256, "ccsha256_di")]:
        for tv in range(0, 1):
            init_seed_len = 64
            init_seed = os.urandom(init_seed_len)
            init_nonce_len = 32
            init_nonce = os.urandom(init_nonce_len)
            init_ps_len = 8
            init_ps = os.urandom(init_ps_len)

            drbg = HMAC_DRBG(ihash, init_seed, init_nonce, init_ps, fips = True)
            rng = RNG(drbg, init_seed, init_nonce, init_ps)
            gen_amnt = 256
            gen1 = rng.generate(gen_amnt)

            n = 32
            for _ in range(0, n):
                _ = rng.generate(gen_amnt)
            genn = rng.generate(gen_amnt)

            reseed_nonce = b"" # Doesn't matter for us...
            rng.getentropy_and_reseed()

            gen_after_reseed = rng.generate(gen_amnt)
            compiler.process(init_seed = init_seed, init_nonce = init_nonce, 
                init_ps = init_ps, gen1 = gen1, 
                tcId = tcId, di = di, ngens = n, genn = genn,
                reseed_nonce = reseed_nonce, gen_after_reseed = gen_after_reseed)
    with open("../test_vectors/ccrng_crypto_hmac_timer_tvs.kat", "w") as fout:
        fout.write(compiler.finish_vectors("ccrng_crypto_hmac_timer_tvs"))

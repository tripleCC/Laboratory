# Copyright (c) (2019,2020) Apple Inc. All rights reserved.
#
# corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
# is contained in the License.txt file distributed with corecrypto) and only to 
# people who accept that license. IMPORTANT:  Any license rights granted to you by 
# Apple Inc. (if any) are limited to internal use within your organization only on 
# devices and computers you own or control, for the sole purpose of verifying the 
# security characteristics and correct functioning of the Apple Software.  You may 
# not, directly or indirectly, redistribute the Apple Software or any portions thereof.

import pdb
from ccrng_fortuna import *
import argparse
import sys
import hashlib
import random
from enum import Enum
from copy import deepcopy
from codegen import *
from os import urandom
from random import choice
from sys import float_info

gen_entropy_nsamples = 0
def get_entropy_all_ones(n):
    global gen_entropy_nsamples
    return (gen_entropy_nsamples, b"\x01" * n)

class TestGenerator(CodeGenerator):
    def __init__(self):
        super().__init__()
        self.errkinds = list(RNGError.Kind)
        self.tid = 0
        self.vecs = []

    def gentid(self):
        self.tid += 1
        return self.tid

    def genop_init(self, getentropy, prng):
        return self.gendecl('struct fortuna_op_init {}', 'op_init', {
            'hd': {
                'id': self.gentid(),
                'kind': symbol('OP_INIT'),
            },
            'getentropy': symbol(getentropy),
        })

    def genop_refresh(self, entropy_nsamples, reseed, rand, prng):
        pool_idx_prev = (prng.pool_i - 1) % prng._NPOOLS
        pool = prng.pools[pool_idx_prev]
        return self.gendecl('struct fortuna_op_refresh {}', 'op_refresh', {
            'hd': {
                'id': self.gentid(),
                'kind': symbol('OP_REFRESH')
            },
            'entropy_nsamples': entropy_nsamples,
            'rand': uint64(rand),
            'out': {
                'reseed': reseed,
                'sched': prng.schedule,
                'key': prng.key,
                'pool_idx': prng.pool_i,
                'pools': [dict(data=p.data, nsamples=d.nsamples) for p, d in zip(prng.pools, prng.diag.pools)]
            }
        })

    def genop_generate(self, rand, prng):
        if rand is None:
            rand_bytes = b""
            rand_nbytes = 0
            err = -162
        else:
            rand_bytes = rand
            rand_nbytes = len(rand)
            err = 0

        return self.gendecl('struct fortuna_op_generate {}', 'op_generate', {
            'hd': {
                'id': self.gentid(),
                'kind': symbol('OP_GENERATE')
            },
            'err': err,
            'rand_nbytes': rand_nbytes,
            'out': {
                'rand': rand_bytes,
                'key': prng.key,
                'ctr': prng.ctr
            }
        })

    def genop_generate_abort(self, rand_nbytes):
        return self.gendecl('struct fortuna_op_generate {}', 'op_generate', {
            'hd': {
                'id': self.gentid(),
                'kind': symbol('OP_GENERATE'),
                'abort': True
            },
            'rand_nbytes': rand_nbytes
        })

    def genvector(self, name, note, ops, diag):
        ops_sym = self.gendecl('struct fortuna_op *{}[]', 'ops', [('const struct fortuna_op *', ref(op)) for op in ops])
        return self.gendecl('struct fortuna_vector {}', name, {
            'id': self.gentid(),
            'note': note,
            'nops': len(ops),
            'nreseeds': diag.nreseeds,
            'schedreseed_nsamples_max': diag.schedreseed_nsamples_max,
            'addentropy_nsamples_max': diag.addentropy_nsamples_max,
            'ops': ops_sym,
            'pools': [
                {
                    'nsamples': p.nsamples,
                    'ndrains': p.ndrains,
                    'nsamples_max': p.nsamples_max
                }
                for p in diag.pools
            ],
        })

    def gentest(self, nops):
        getentropy_functions = [(get_entropy_all_ones, "get_entropy_all_ones")]
        getentropy_func, getentropy_name = random.choice(getentropy_functions)
        prng = RNG(getentropy_func)
        ops = [self.genop_init(getentropy_name, prng)]
        kinds = ['REFRESH', 'GENERATE']
        note = None

        while len(ops) < nops:
            prngcopy = deepcopy(prng)
            kind = choice(kinds)

            try:
                if kind == 'REFRESH':
                    global gen_entropy_nsamples
                    if nops > 16:
                        gen_entropy_nsamples = random.choice([512])
                    else:
                        gen_entropy_nsamples = random.choice([-1,1024])
                    reseed, rand = prng.refresh()
                    ops.append(self.genop_refresh(gen_entropy_nsamples, reseed, rand, prng))
                elif kind == 'GENERATE':
                    rand_nbytes = choice(range(288))
                    rand = prng.generate(rand_nbytes)
                    ops.append(self.genop_generate(rand, prng))

            except RNGError as err:
                if err.kind not in self.errkinds:
                    prng = prngcopy
                    continue

                self.errkinds.remove(err.kind)

                if err.kind in [RNGError.Kind.initgen_range, RNGError.Kind.initgen_init]:
                    ops.append(self.genop_initgen_abort(genid))
                elif err.kind in [RNGError.Kind.generate_range, RNGError.Kind.generate_init, RNGError.Kind.generate_reqsize]:
                    ops.append(self.genop_generate_abort(rand_nbytes))

                note = err.note
                break

        vec = self.genvector('vec', note, ops, prng.diag)
        self.vecs.append(vec)
        return vec

    def finalize(self):
        return self.gendecl('struct fortuna_vector *{}[]', symbol('test_vectors'), [ref(v) for v in self.vecs])


def gentests(outfile):
    testgen = TestGenerator()
    for _ in range(256):
        print('generating test', len(testgen.vecs))
        testgen.gentest(16)
    for _ in range(2):
        print('generating test', len(testgen.vecs))
        testgen.gentest(1024)
    testgen.finalize()
    with open(outfile, 'w') as f:
        f.write('\n\n'.join(testgen.decls))
        f.write('\n')


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("command", help = "'generate' or 'run' test cases")
    parser.add_argument("-o", "--output", help = "C output file")
    args = parser.parse_args()

    if args.command not in ["generate"]:
        print("Invalid command: %s! Must be 'generate' or 'run'" % args.command)
        sys.exit(-1)
    elif args.command == "generate":
        gentests(args.output)

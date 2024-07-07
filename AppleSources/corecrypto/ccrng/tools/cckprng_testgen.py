# Copyright (c) (2020,2023) Apple Inc. All rights reserved.
#
# corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
# is contained in the License.txt file distributed with corecrypto) and only to
# people who accept that license. IMPORTANT:  Any license rights granted to you by
# Apple Inc. (if any) are limited to internal use within your organization only on
# devices and computers you own or control, for the sole purpose of verifying the
# security characteristics and correct functioning of the Apple Software.  You may
# not, directly or indirectly, redistribute the Apple Software or any portions thereof.

from cckprng import CCKPRNG
from copy import deepcopy
from random import choice
from codegen import *
import argparse
import os

SEED_LEN = 32
NONCE_LEN = 8

get_entropy_nsamples = 0
def fortuna_get_entropy_ones(n):
    global get_entropy_nsamples
    return (get_entropy_nsamples, b"\x01" * n)

class TestGenerator(CodeGenerator):
    def __init__(self):
        super().__init__()
        self.tid = 0
        self.vecs = []

    def gentid(self):
        self.tid += 1
        return self.tid

    def genop_init(self, seed, nonce, getentropy, kprng):
        return self.gendecl('struct cckprng_op_init {}', 'op_init', {
            'hd': {
                'id': self.gentid(),
                'kind': symbol('OP_INIT'),
            },
            'seed': seed,
            'nonce': nonce,
            'getentropy': symbol(getentropy),
        })

    def genop_reseed(self, seed, nonce, kprng):
        # TKTK: drbg validate_inputs() aborts
        return self.gendecl('struct cckprng_op_reseed {}', 'op_reseed', {
            'hd': {
                'id': self.gentid(),
                'kind': symbol('OP_RESEED'),
            },
            'nonce': uint64(nonce),
            'seed_nbytes': len(seed),
            'seed': seed,
        })

    def genop_refresh(self, rand, nsamples, kprng):
        return self.gendecl('struct cckprng_op_refresh {}', 'op_refresh', {
            'hd': {
                'id': self.gentid(),
                'kind': symbol('OP_REFRESH'),
            },
            'rand': uint64(rand),
            'nsamples': nsamples,
            'needreseed': kprng.needreseed,
        })

    def genop_generate(self, rand, kprng):
        return self.gendecl('struct cckprng_op_generate {}', 'op_init', {
            'hd': {
                'id': self.gentid(),
                'kind': symbol('OP_GENERATE'),
            },
            'rand_nbytes': len(rand),
            'out': {
                'rand': rand,
            }
        })

    def genvector(self, name, note, ops, kprng):
        ops_sym = self.gendecl('struct cckprng_op *{}[]', 'ops', [('const struct cckprng_op *', ref(op)) for op in ops])
        return self.gendecl('struct cckprng_vector {}', name, {
            'id': self.gentid(),
            'note': note,
            'nops': len(ops),
            'ops': ops_sym,
        })

    def gentest(self, nops):
        getentropy_functions = [(fortuna_get_entropy_ones, "fortuna_get_entropy_ones")]
        getentropy_func, getentropy_name = choice(getentropy_functions)

        seed = os.urandom(SEED_LEN)
        nonce = os.urandom(NONCE_LEN)
        kprng = CCKPRNG(seed, nonce, getentropy_func)
        ops = [self.genop_init(seed, nonce, getentropy_name, kprng)]
        kinds = ['GENERATE', 'RESEED', 'REFRESH']
        note = None

        while len(ops) < nops:
            kind = choice(kinds)

            try:
                if kind == 'GENERATE':
                    rand_nbytes = choice(range(288))
                    rand = kprng.generate(rand_nbytes)
                    ops.append(self.genop_generate(rand, kprng))
                elif kind == "RESEED":
                    seed_nbytes = choice(range(16, 288))
                    seed = os.urandom(seed_nbytes)
                    nonce = kprng.reseed(seed)
                    ops.append(self.genop_reseed(seed, nonce, kprng))
                elif kind == "REFRESH":
                    global get_entropy_nsamples
                    get_entropy_nsamples = 1024
                    success, rand = kprng.refresh()
                    ops.append(self.genop_refresh(rand, get_entropy_nsamples, kprng))
            except Exception as e:
                raise Exception(f"Wut? {e}")

        vec = self.genvector('vec', note, ops, kprng)
        self.vecs.append(vec)
        return vec

    def finalize(self):
        return self.gendecl('struct cckprng_vector *{}[]', symbol('test_vectors'), [ref(v) for v in self.vecs])

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
    parser.add_argument("command", help = "'generate'")
    parser.add_argument("-o", "--output", help = "C output file")
    args = parser.parse_args()

    if args.command not in ["generate"]:
        print("Invalid command: %s! Must be 'generate' or 'run'" % args.command)
        sys.exit(-1)
    elif args.command == "generate":
        gentests(args.output)

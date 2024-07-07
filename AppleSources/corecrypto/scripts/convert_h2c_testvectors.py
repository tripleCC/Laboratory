#!/usr/bin/python3
# -*- coding: utf-8 -*-

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
import string
import random
import filecmp
import argparse
import binascii
import tempfile

from shutil import move

random.seed(0) # Make the generation deterministic

class Compiler(object):
    def __init__(self):
        self.syms = []
        self.decls = []
        self.symid = 0
        self.prefix = "".join(random.choice(string.ascii_uppercase) for _ in range(6))
        self.c_struct_data = ""
        self.test_vector_structs = []
        self.STRUCT = None

    def gen_sym(self, name):
        self.symid += 1
        return "cctest_{}_{}_{}".format(self.prefix, name, self.symid)

    def convert_hex_uint8t_list(self, name, data):
        _ = binascii.unhexlify(data) # Make sure it's hex
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
    
class SSWU(Compiler):
    '''
    struct cch2c_sswu_test_vector {
        unsigned tcId;
        unsigned curve;
        unsigned hkdf;
        const uint8_t *alpha;
        size_t alpha_len;
        const uint8_t *DST;
        size_t DST_len;
        const uint8_t *NUx;
        size_t NUx_len;
        const uint8_t *NUy;
        size_t NUy_len;
        const uint8_t *ROx;
        size_t ROx_len;
        const uint8_t *ROy;
        size_t ROy_len;
        const uint8_t u_nu;
        size_t u_nu_len;
        const uint8_t u_ro0;
        size_t u_ro0_len;
        const uint8_t u_ro1;
        size_t u_ro1_len;
    };
    '''

    def __init__(self):
        super(SSWU, self).__init__()
        self.STRUCT = "cch2c_sswu_test_vector"
        self.UINT8T_BLOBS = ["alpha", "DST", "NUx", "NUy", "ROx", "ROy", "u_nu", "u_ro0", "u_ro1", "Q0x", "Q0y", "Q1x", "Q1y"]

    def process(self, json_data):
        for test_group in json_data["testGroups"]:
            for test in test_group["tests"]:

                test_vector = {}

                for blob_name in self.UINT8T_BLOBS:
                    blob_value = test.get(blob_name, None)
                    if blob_value is not None:
                        sym, data_len = self.convert_hex_uint8t_list(blob_name, blob_value)
                        test_vector[blob_name] = sym
                        test_vector["{}_len".format(blob_name)] = data_len

                test_vector["tcId"] = test.get("tcId", -1)
                test_vector["curve"] = test_group.get("curve", -1)
                test_vector["hkdf"] = test_group.get("hkdf", -1)

                self.add_test_vector("test_vector", test_vector)

TEST_VECTORS = {
    "h2c_sswu" : {
        "compiler": SSWU,
        "files": ["h2c/sswu.json"],
        "output_dir": "cch2c/test_vectors",
        "test_vectors_name": "h2c_sswu_vectors"
    }
}

def convert(srcroot):
    for test_name, test_struct in TEST_VECTORS.items():
        compiler = test_struct["compiler"]()
        input_files = list(map(lambda file: os.path.join(srcroot, "corecrypto_test/test_vectors", file), test_struct["files"]))
        output_file = os.path.join(srcroot, test_struct["output_dir"], '{}.kat'.format(test_name))

        tmp_file = None
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as fout:
            tmp_file = fout.name
            for input_file in input_files:
                with open(input_file) as fin:
                    json_data = json.load(fin)
                    compiler.process(json_data)
            fout.write(compiler.finish_vectors(test_struct["test_vectors_name"]))
        
        # Only replace the output file if the content changed.
        if os.path.exists(output_file) and filecmp.cmp(output_file, tmp_file, shallow = False):
            print("No need to regenerate file {}".format(output_file))
            os.remove(tmp_file)
        else:
            print("Generating file {}".format(output_file))
            move(tmp_file, output_file)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description = "Convert Wycheproof test vectors into C structs")
    parser.add_argument("srcroot", help = "Repository srcroot")
    args = parser.parse_args()
    convert(args.srcroot)

#!/usr/bin/env python3
# Copyright (c) (2023) Apple Inc. All rights reserved.
#
# corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
# is contained in the License.txt file distributed with corecrypto) and only to 
# people who accept that license. IMPORTANT:  Any license rights granted to you by 
# Apple Inc. (if any) are limited to internal use within your organization only on 
# devices and computers you own or control, for the sole purpose of verifying the 
# security characteristics and correct functioning of the Apple Software.  You may 
# not, directly or indirectly, redistribute the Apple Software or any portions thereof.

from pathlib import Path
from os import environ
from enum import Enum
from shlex import split
from subprocess import run

corecrypto_submodules = {
	"asn1":          ["ccasn1.h"],
	"blowfish":      ["ccblowfish.h"],
	"cast":          ["cccast.h"],
	"h2c":           ["cch2c.h", "cch2c_priv.h"],
	"der":           ["ccder_decode_eckey.h", "ccder_encode_eckey.h", "ccder.h"],
	"des":           ["ccdes.h"],
	"ecies":         ["ccecies.h", "ccecies_priv.h"],
	"md2":           ["ccmd2.h"],
	"md4":           ["ccmd4.h"],
	"md5":           ["ccmd5.h"],
	"rc2":           ["ccrc2.h"],
	"rc4":           ["ccrc4.h"],
	"scrypt":        ["ccscrypt.h"],
	"sha1":          ["ccsha1.h"],
	"sha3":          ["ccsha3.h"],
	"srp":           ["ccsrp.h", "ccsrp_gp.h"],
	"spake2":        ["ccspake.h"],
	"rsabssa":       ["ccrsabssa.h"],
	"kem":           ["cckem.h", "cckyber.h"],
	"bfv":           ["ccbfv_priv.h"],
	"he":            ["cche_priv.h"],
	"curve448":      ["ccec448.h", "ccec448_priv.h"],
}

class Attribute(str, Enum):
	system = "system"
	extern_c = "extern_c"

class Qualifier(str, Enum):
	explicit = "explicit"

class ModuleMap:
	def __init__(self, name, attributes = [], qualifiers = [], export = True):
		self.name = name
		self.qualifiers = qualifiers
		self.attributes = attributes
		self.export = export

		self.submodules = {}
		self.headers = []

	def add_header(self, header):
		self.headers.append(header)

	def add_submodule(self, submodule):
		self.submodules[submodule.name] = submodule

	def to_str(self, indent = 0):
		# Module name
		tr = "\t" * indent
		for qualifier in self.qualifiers:
			tr += f"{qualifier} "
		tr += "module "
		tr += f"{self.name} "
		for attribute in self.attributes:
			tr += f"[{attribute}] "
		tr += "{\n"

		# Headers
		for header in sorted(self.headers):
			tr += "\t" * (indent + 1)
			tr += f'header "{header}"'
			tr += "\n"

		# Submodules
		for submodule_name in sorted(self.submodules.keys()):
			submodule = self.submodules[submodule_name]
			tr += submodule.to_str(indent = indent + 1)

		if self.export:
			tr += "\t" * (indent + 1)
			tr += "export *\n"
		tr += "\t" * (indent)
		tr += "}\n"

		return tr

	def __str__(self):
		return self.to_str()

def generate_module_map():
	module_map = ModuleMap("corecrypto", attributes = [Attribute.system, Attribute.extern_c])

	# We'll only search over the `PUBLIC_HEADERS_FOLDER_PATH`
	# since it is equivalent to `PRIVATE_HEADERS_FOLDER_PATH`
	# in corecrypto
	dstroot_path = Path(environ["DSTROOT"])
	public_headers_folder_path = Path(environ["PUBLIC_HEADERS_FOLDER_PATH"])
	header_path = dstroot_path / public_headers_folder_path.relative_to(public_headers_folder_path.anchor)
	assert header_path.exists()
	assert header_path.is_dir()

	headers = set([header.name for header in header_path.glob("*.h")])
	# First process the submodules
	for submodule_name, submodule_headers in corecrypto_submodules.items():
		if all([submodule_header in headers for submodule_header in submodule_headers]):
			submodule = ModuleMap(submodule_name, qualifiers = [Qualifier.explicit])
			for submodule_header in submodule_headers:
				submodule.add_header(submodule_header)
				headers.remove(submodule_header)
				module_map.add_submodule(submodule)
		else:
			print(f"Warning: Not all headers exist for {submodule_name}")

	# Now add the remaining headers to the base object
	for header in headers:
		module_map.add_header(header)

	return module_map

if __name__ == "__main__":
	# Generate the map
	module_map = generate_module_map()

	# Write the map to BUILT_PRODUCTS_DIR
	module_map_file = Path(environ["BUILT_PRODUCTS_DIR"], "corecrypto.modulemap.tmp")
	with open(module_map_file, "w") as fout:
		fout.write(str(module_map))

	DSTDIR_PRIV= f"{environ['DSTROOT']}/{environ['PRIVATE_HEADERS_FOLDER_PATH']}"

	# Finally invoke the install commands
	install_cmd_1 = f"install -d -g {environ['INSTALL_GROUP']} -o {environ['INSTALL_OWNER']} {DSTDIR_PRIV}"
	run(split(install_cmd_1))
	
	install_cmd_2 = f"install -g {environ['INSTALL_GROUP']} -m {environ['INSTALL_MODE_FLAG']} -o {environ['INSTALL_OWNER']} {module_map_file} {DSTDIR_PRIV}/module.modulemap"
	run(split(install_cmd_2))


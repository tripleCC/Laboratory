<!-- Copyright (c) (2010,2012,2014-2023) Apple Inc. All rights reserved.

 corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 is contained in the License.txt file distributed with corecrypto) and only to
 people who accept that license. IMPORTANT:  Any license rights granted to you by
 Apple Inc. (if any) are limited to internal use within your organization only on
 devices and computers you own or control, for the sole purpose of verifying the
 security characteristics and correct functioning of the Apple Software.  You may
 not, directly or indirectly, redistribute the Apple Software or any portions thereof.
-->

The corecrypto (cc) project
===========================

The main goal is to provide low level fast math routines and crypto APIs which
can be used in various environments (Kernel, bootloader, userspace, etc.).  It
is an explicit goal to minimize dependancies between modules and functions so
that clients of this library only end up with the routines they need and
nothing more.

Corecrypto compiles under all Apple OSs, Windows and Linux.

Corecrypto Modules
------------------

Current corecrypto consists of the following submodules:

* `cc`:              Headers and code common to all of the modules
* `ccasn1`:          ASN.1 typeid constants and ccoid definition.
* `ccbfv`:           BFV homomorphic encryption scheme
* `ccder`:           DER encoding decoding support
* `ccn`:             Math on vectors of n cc_units
* `cczp`:            Modular arithmetic mod integer p, on vectors of n cc_units
* `ccpolyzp_po2cyc`: Modular arithmetic on polynomials in finite quotient ring with power-of-two cyclotomic polynomial
* `ccz`:             Variable sized signed integer math routines
* `ccdrbg`:          Deterministic Random Byte Generators
* `ccrng`:           Random Bytes Generators
* `ccdh`:            Diffie-Hellman routines.
* `ccec25519`:       Elliptic curve signature and Diffie-Hellman routines using the Edward's 25519 curve
* `ccrsa`:           RSA routines.
* `ccec`:            Eliptic Curve Curves, ec specific math and APIs
* `ccdigest`:        Digest abstraction layer.
* `cche`:            Homomorphic encryption, supporting the BFV and BGV schemes
* `cchmac`:          HMAC using any ccdigest.
* `ccpbkdf2`:        PBKDF2 using any ccdigest.
* `ccmd2`:           MD2 digest implementations.
* `ccmd4`:           MD4 digest implementations.
* `ccmd5`:           MD5 digest implementations.
* `ccripemd`:        RIPE-MD digest implementations.
* `ccsha1`:          SHA-1 digest implementations.
* `ccsha2`:          SHA-2 digest implementations.
* `ccmode`:          Symmetric cipher chaining mode interfaces.
* `ccpad`:           Symmetric cipher padding code.
* `ccaes`:           AES symmetric cipher implementations.
* `ccblowfish`:      Blowfish symmetric cipher implementations.
* `cccast`:          Cast symmetric cipher implementations.
* `ccdes`:           DES and 3DES symmetric cipher implementations.
* `ccrc2`:           RC2 symmetric cipher implementations.
* `ccrc4`:           RC4 symmetric cipher implementations.
* `ccperf`:          Performance testing harness.
* `cctest`:          Common utilities for creating self tests and XCunit tests.
* `ccprime`:         Functions for generating large prime numbers. Mostly used in RSA key generation.
* `ccspake`:         SPAKE2+ password-based key exchange implementation.

### Module Subdirectories

Each module has the following subdirectories:

* `corecrypto`:     headers for this module
* `src`:            sources for this module
* `doc`:            documentation, references, etc.
* `crypto_tests`:   sources for executable tests for this module
* `test_vectors`:   test vectors for this module
* `tools`:          sources for random helper tools.

The following subdirections don't follow the module layout yet:

* `corecrypto_kext`:   Supporting files for kernel extension build and fips support.
* `corecrypto_dylib`:  Supporting files for userspace shared lib build and fips support.

ARMV6m
------
The ARMV6m is not on corecrypto project target list. To compile corecrypto under ARMV6m use the following command:
`$xcodebuild -target "corecrypto_static" OTHER_CFLAGS="-Qunused-arguments" -sdk iphoneos.internal -arch armv6m`


Windows
-------
corecrypto compiles under Windows using Visual Studio 2015 and Clang with Microsoft CodeGen. The corecrypto Solution contains three projects:

1. `corecrypto`: This projects compiles corecrypto, and produces a static library in 32 and 64 bit modes.
2. `corecrypto_test`: This project compiles corecrypto test files and links statically with the corecrypto debug library.
3. `corecrypto_perf`: This project compiles corecrypto performance measurement files and links statically with the corecrypto release library.
4. `corecrypto_wintest`: This project contains a simple code that links to the corecrypto.lib and complies in c++ using the Visul C++ compiler. This project created to
   make sure corecrypto library can linked to c++ software that are compiled with the Microsoft Compiler.

Linux
-----
The corecrypto library, `corecrypto_test` and `corecrypto_perf` compile under Linux and are built using cmake. See Cmake section for more details.
The Linux implementation does not use ASM implementations due to differences between assemblers on Darwin and Linux.

CMake
-----
The corecrypto library, 'corecrypto_test' and 'corecrypto_perf' can also be built using cmake in macOS and Linux.

To compile using cmake, run the usual cmake commands:
```
  $ cd <srcdir>
  $ mkdir build && cd build
  $ CC=clang CXX=clang++ cmake ..
  $ make
```
where `<srcdir>` is the path to the directory containing the sources.

To install, type `make install` from the build directory (will require root privileges).

Docker file for the Linux build is available here:

```
    $ cd docker
    $ docker build -t corecryptobuild
    $ sh setup.sh
```
This will get you a Linux prompt.

Prototypes changes:
-------------------
From time to time, corecrypto needs to change the prototypes of functions.
In this case, we use a macro defined as:
CC_CHANGEFUNCTION_<radar>_<function name>
and the header will document instructions to migrate from the old to new function prototype.




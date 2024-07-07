# Copyright (c) (2021) Apple Inc. All rights reserved.
#
# corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
# is contained in the License.txt file distributed with corecrypto) and only to
# people who accept that license. IMPORTANT:  Any license rights granted to you by
# Apple Inc. (if any) are limited to internal use within your organization only on
# devices and computers you own or control, for the sole purpose of verifying the
# security characteristics and correct functioning of the Apple Software.  You may
# not, directly or indirectly, redistribute the Apple Software or any portions thereof.

#!/bin/sh

set -x

# Why not just install these libraries under the link names to begin
# with?
#
# The issue is that we need to build two sets of libraries with the
# same names but different install paths. This should be fine, but the
# build system puts intermediate build artifacts in flat directories
# and complains if there are name collisions.
#
# As a workaround, we build the libraries under unique names and
# create symlinks after the fact.

linkdir="${TARGET_BUILD_DIR}/${CORECRYPTO_SEP_INSTALL_SUBPATH}"
mkdir -p "${linkdir}"

for libpath in ${TARGET_BUILD_DIR}/*${PRODUCT_NAME}*.a; do
    linkname=$(basename "${libpath}" | sed "s/${CORECRYPTO_SEP_PRODUCT_NAME_SUFFIX}//")
    srcpath=$(python3 -c 'import os.path, sys; print(os.path.relpath(sys.argv[1], sys.argv[2]))' ${libpath} ${linkdir})
    ln -sf "${srcpath}" "${linkdir}/${linkname}"
done

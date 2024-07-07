# Copyright (c) (2022) Apple Inc. All rights reserved.
#
# corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
# is contained in the License.txt file distributed with corecrypto) and only to
# people who accept that license. IMPORTANT:  Any license rights granted to you by
# Apple Inc. (if any) are limited to internal use within your organization only on
# devices and computers you own or control, for the sole purpose of verifying the
# security characteristics and correct functioning of the Apple Software.  You may
# not, directly or indirectly, redistribute the Apple Software or any portions thereof.

#!/bin/bash

set -x

# Why not just install these libraries under the link names to begin
# with?
#
# There are a couple issues.

# First, all these links have the same file name but different install
# paths. This should be fine, but the build system puts intermediate
# build artifacts in flat directories and complains if there are name
# collisions.
#
# Second, we build all these libraries as build variants of a single
# target. Xcode's build system only evaluates ${INSTALL_PATH} once and
# not per-variant. This means you can't have different install paths
# for each one.
#
# As a workaround, we build the libraries under unique names and
# create links after the fact.

linkdir="${DSTROOT}/${RTKIT_ROOT}/usr/lib/${CONFIGURATION}"
libprefix="${EXECUTABLE_PREFIX}${PRODUCT_NAME}_"
libsuffix="${EXECUTABLE_SUFFIX}"

# This unfortunately looks a bit obscure, but it just prints the
# relative path from the second argument to the first. With no second
# argument, print the relative path from the working directory.
function relpath() {
    python3 -c "import os, sys; print(os.path.relpath(*sys.argv[1:]))" ${@}
}

for libpath in "${TARGET_BUILD_DIR}/${libprefix}"*; do
    libname=$(basename -s "${libsuffix}" "${libpath}")
    variantname=$(echo "${libname}" | sed -E "s/${libprefix}(.*)/\1/")
    slicename=$(eval "printf '%s' \${RTKIT_SLICE_NAME_${variantname}}")
    slicedir="${linkdir}/${slicename}"
    librelpath=$(relpath "${libpath}" "${slicedir}")
    mkdir -p "${slicedir}"
    ln -f -s "${librelpath}" "${slicedir}/${FULL_PRODUCT_NAME}"
done

# Copyright (c) (2020) Apple Inc. All rights reserved.
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

# Install corecrypto header files for the DriverKit SDK

if [ -z "${DRIVERKIT}" ]; then
	echo "\$DRIVERKIT is not set"
	exit 0
fi

for HEADER in $(cd "${DSTROOT}/${SDK_INSTALL_HEADERS_ROOT}"; find . -name "*.h"); do
	DIR="$(dirname ${HEADER})"
	mkdir -p "${DSTROOT}/${SDK_INSTALL_ROOT}/${DIR}"
	ditto "${DSTROOT}/${SDK_INSTALL_HEADERS_ROOT}/${HEADER}" "${DSTROOT}/${SDK_INSTALL_ROOT}/${HEADER}"
done


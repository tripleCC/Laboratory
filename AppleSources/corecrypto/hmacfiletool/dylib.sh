# Copyright (c) (2017,2019,2022) Apple Inc. All rights reserved.
#
# corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
# is contained in the License.txt file distributed with corecrypto) and only to
# people who accept that license. IMPORTANT:  Any license rights granted to you by
# Apple Inc. (if any) are limited to internal use within your organization only on
# devices and computers you own or control, for the sole purpose of verifying the
# security characteristics and correct functioning of the Apple Software.  You may
# not, directly or indirectly, redistribute the Apple Software or any portions thereof.

#/bin/bash -e -x

# Support building with macOS SDKs older than ones
# that include a binary-patch capable hmacfiletool.
if [ -f "${BUILT_PRODUCTS_DIR}/hmacfiletool" ]; then
    HFT_BIN=`echo ${BUILT_PRODUCTS_DIR}/hmacfiletool | sed 's/-iphoneos//'`
else
    HFT_BIN=`xcrun -sdk ${SDK_NAME} -n -f hmacfiletool`
    HMAC_USAGE=`${HFT_BIN} -v` || echo "checking usage"

    if [[ ! "${HMAC_USAGE}" =~ "binary" ]]; then
        echo "Failed to have a hmacfiletool with binary support; compile the hmacfiletool from this repository."
        exit 255
    fi
fi

# Run the binary touchup over each variant; alas, naming is
# not consistent.
for variant in ${BUILD_VARIANTS}; do
    if [ "${variant}" == "normal" ]; then
        TGT=${BUILT_PRODUCTS_DIR}/${EXECUTABLE_PATH}
    else
        TGT=${BUILT_PRODUCTS_DIR}/${EXECUTABLE_PREFIX}${PRODUCT_NAME}_${variant}${EXECUTABLE_SUFFIX}
    fi
    ${HFT_BIN} -v -i ${TGT} -f ${TGT} -b
done

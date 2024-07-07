# Copyright (c) (2018-2022) Apple Inc. All rights reserved.
#
# corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
# is contained in the License.txt file distributed with corecrypto) and only to
# people who accept that license. IMPORTANT:  Any license rights granted to you by
# Apple Inc. (if any) are limited to internal use within your organization only on
# devices and computers you own or control, for the sole purpose of verifying the
# security characteristics and correct functioning of the Apple Software.  You may
# not, directly or indirectly, redistribute the Apple Software or any portions thereof.

#!/bin/bash

OUTFILE=$1
INPUT_DIR=$2

NAMES=()
STRUCTURES=()
LENGTHS=()

# Caching: we store in an hidden file the content of the directory when OUTFILE was created.
[ -n "${SRCROOT}" ] && CACHEFILE="${SRCROOT}/.convert_testvectors.sh.log"
HASH_INPUT_DIRECTORY=$(shasum ${INPUT_DIR}/* | shasum)
if [ -f "${CACHEFILE}" ] && [ "${HASH_INPUT_DIRECTORY}" == "$(cat ${CACHEFILE})" ]; then 
    echo "No need to regenerate file ${OUTFILE}"
    exit # No need to regenerate the file
fi

echo "Generating file ${OUTFILE} (directory hash: ${HASH_INPUT_DIRECTORY})"
[ -n "${CACHEFILE}" ] && echo "${HASH_INPUT_DIRECTORY}" > "${CACHEFILE}"

# Concatenate each struct to a single file
echo "#ifndef CC_GENERATED_TEST_VECTORS_H" > "${OUTFILE}"
echo "#define CC_GENERATED_TEST_VECTORS_H" >> "${OUTFILE}"
echo "" >> "${OUTFILE}"

for FNAME in $(find ${INPUT_DIR} -name *.json)
do
    PARSER=$(basename $(dirname "${FNAME}"))
    LENGTH=$(wc -c "${FNAME}" | awk '{print $1}')
    NAME=`basename -s ".json" "${FNAME}"`

    echo "static const uint8_t ${NAME}[] =" >> "${OUTFILE}"
    xxd --include -c 16 "${FNAME}" | grep '^  0x' | sed 's/^  0x/    "\\x/g; s/,$//g; s/\([^"]\)$/\1"/g; s/, 0x/\\x/g' >> "${OUTFILE}"
    echo ";" >> "${OUTFILE}"

    NAMES+=("${PARSER}")
    STRUCTURES+=("${NAME}")
    LENGTHS+=("${LENGTH}")
done

echo "" >> "${OUTFILE}"
echo "struct ccgenerated_test_vector {" >> "${OUTFILE}"
echo "    const char *name;" >> "${OUTFILE}"
echo "    const char *parser;" >> "${OUTFILE}"
echo "    const uint8_t *buffer;" >> "${OUTFILE}"
echo "    size_t buffer_len;" >> "${OUTFILE}"
echo "};" >> "${OUTFILE}"

echo "" >> "${OUTFILE}"
echo "const struct ccgenerated_test_vector ccgenerated_test_vectors[] = {" >> "${OUTFILE}"
for i in "${!STRUCTURES[@]}"
do
    STRUCTNAME=${STRUCTURES[$i]}
    LENGTH=${LENGTHS[$i]}
    PARSER=${NAMES[$i]}
    echo "    { .name = \"${STRUCTNAME}\", .parser = \"${PARSER}\", .buffer = ${STRUCTNAME}, .buffer_len = ${LENGTH} }," >> "${OUTFILE}"
done
echo "};" >> "${OUTFILE}"

echo "" >> "${OUTFILE}"
echo "const size_t ccgenerated_test_vectors_count = ${#STRUCTURES[@]};" >> "${OUTFILE}"
echo "" >> "${OUTFILE}"

echo "#endif // CC_GENERATED_TEST_VECTORS_H" >> "${OUTFILE}"

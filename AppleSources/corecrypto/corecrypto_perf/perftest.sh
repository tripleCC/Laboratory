# Copyright (c) (2010,2011,2015,2016,2019) Apple Inc. All rights reserved.
#
# corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
# is contained in the License.txt file distributed with corecrypto) and only to 
# people who accept that license. IMPORTANT:  Any license rights granted to you by 
# Apple Inc. (if any) are limited to internal use within your organization only on 
# devices and computers you own or control, for the sole purpose of verifying the 
# security characteristics and correct functioning of the Apple Software.  You may 
# not, directly or indirectly, redistribute the Apple Software or any portions thereof.
#!/bin/sh

perftests_all() {
    $ccperf
}

usage() {
    echo "Usage: `basename $0` [-a] [-n|-H] [-d|-i] [-u] [-b] [-s sdk] [-p]" 
    echo "    -a    Build native and device and run perf tests on both."
    echo "    -b    Build (and run unit tests)"
    echo "    -u    Run unit test (useful when not building)"
    echo "    -p    Run perf tests"
    echo "    -n    Native host"
    echo "    -i    iOS device"
    echo "    -s    sdk for ios device (implies -b -i)"
    echo "    -P devicePassword  - defaults to 'alpine'"
    echo "    -F passwordFile    - file containing device password"
    exit 2
}

# initialize default option values
do_build=0
do_ios=0
do_native=0
do_unit=0
do_perf=0
do_verbose=0
device_password_file=~/.devicepass
device_password=alpine
ios_sdk=iphoneos.internal
# now parse command line options
test $# -eq 0 && usage
args=`getopt abdHinps:t:uv $*`
test $? != 0 && usage
set -- $args
for i
do
    case "$i"
    in
    -a)
        do_ios=1
        do_native=1
        do_build=1
        do_perf=1
        shift;;
    -b)
        do_build=1
        shift;;
    -d|-i)
        do_ios=1
        shift;;
    -H|-n)
        do_native=1
        shift;;
    -p)
        do_perf=1
	shift;;
    -s)
        ios_sdk="$2"; shift;
        do_ios=1
        do_build=1
        shift;;
    -t)
        target="--target $2"
	shift;;
    -u)
        do_unit=1
        shift;;
    -v)
        do_verbose=1
        shift;;
    -P)
	device_password=$2;
	device_password_file="";
	shift 2;;
    -F)
	device_password_file="$2";
	device_password="";
	shift 2;;
    --)
        shift; break;;
    esac
done

device_password_file_option="";
if [ -r "$device_password_file" ]; then
    RSYNC_OPTS="--password-file $device_password_file"
    device_password="";
fi

if [ "$device_password" != "" ]; then
    export RSYNC_PASSWORD="$device_password"
fi

# Build phase
if [ $do_build -ne 0 -a $do_native -ne 0 ]; then
    echo "******** Native host build ******** "
    xcodebuild -configuration Release -target world build > /dev/null
fi

if [ $do_build -ne 0 -a $do_ios -ne 0 ]; then
    echo "******** iOS Internal build ******** "
    xcodebuild -configuration Release -sdk "$ios_sdk" -target world build > /dev/null
fi

# Get build dirs
ios_build_dir="`xcodebuild '@@@@$(BUILT_PRODUCTS_DIR)' -configuration Release -sdk "$ios_sdk" 2>&1 | grep '@@@@' | sed 's/^.*@@@@\(.*\).$/\1/' | uniq`"
ios_build_dir="`eval cd \"$ios_build_dir\" && pwd`"
echo "ios_build dir is \"$ios_build_dir\""

native_build_dir="`xcodebuild '@@@@$(BUILT_PRODUCTS_DIR)' -configuration Release 2>&1 | grep '@@@@' | sed 's/^.*@@@@\(.*\).$/\1/' | uniq`"
native_build_dir="`eval cd \"$native_build_dir\" && pwd`"
echo "native_build dir is \"$native_build_dir\""

print_size()
{
	size -m "$1" | awk '/\(for architecture (.*)\)/ { printf("(%s ", $4); } /Segment __(DATA|TEXT)/ { label=$2; } /^\ttotal/ { printf("%s %s ", label, $2); } END { printf("\n"); }'
}
# Size phase
if [ $do_build -ne 0 -a $do_native -ne 0 ]; then
    echo "ec_verify  only sizes \c"
    print_size "$native_build_dir/ec_verify"
    echo "rsa_verify only sizes \c"
    print_size "$native_build_dir/rsa_verify"
fi

if [ $do_build -ne 0 -a $do_ios -ne 0 ]; then
    echo "ec_verify  only sizes \c"
    print_size "$ios_build_dir/ec_verify"
    echo "rsa_verify only sizes \c"
    print_size "$ios_build_dir/rsa_verify"
fi

# Validation phase
if [ $do_unit -ne 0 -a $do_native -ne 0 ]; then
    echo "******** Native host unit tests ******** "
    arch=`arch`
    lipo -extract $arch -output /tmp/otest-$arch /Developer/Tools/otest
    DYLD_FRAMEWORK_PATH=/Developer/Library/Frameworks  OBJC_DISABLE_GC=YES /tmp/otest-$arch "$native_build_dir/validation.octest"
    #"$native_build_dir/CoreCrypto.app/Contents/MacOS/CoreCrypto"
    rm /tmp/otest-$arch
fi

if [ $do_unit -ne 0 -a $do_ios -ne 0 ]; then
    rsync $RSYNC_OPTS -rlpt "$ios_build_dir/validation.octest" rsync://root@localhost:10873/root/tmp > /dev/null
    echo "******** iOS Internal unit tests ******** "
    pe="`xcrun -sdk \"$ios_sdk\" -find PurpleExec`"
    $pe $target --stream --cmd /Developer/Tools/otest /tmp/validation.octest
fi

# Perf test phase
if [ $do_perf -ne 0 -a $do_native -ne 0 ]; then
    echo "******** Native host perf tests ******** "
    ccperf="$native_build_dir/ccperf"
    perftests_all
fi

if [ $do_perf -ne 0 -a $do_ios -ne 0 ]; then
    rsync $RSYNC_OPTS -rlpt "$ios_build_dir/ccperf" rsync://root@localhost:10873/root/tmp > /dev/null
    echo "******** iOS \"$ios_sdk\" Internal perf tests ******** "
    pe="`xcrun -sdk \"$ios_sdk\" -find PurpleExec`"
    ccperf="$pe $target --stream --cmd /tmp/ccperf"
    perftests_all
fi

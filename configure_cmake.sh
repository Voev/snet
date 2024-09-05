#!/bin/sh
# Convenience wrapper for easily viewing/setting options that
# the project's CMake scripts will recognize

set -e
command="$0 $*"

# check for `cmake` command
type cmake > /dev/null 2>&1 || {
    echo "\
This package requires CMake, please install it first, then you may
use this configure script to access CMake equivalent functionality.\
" >&2;
    exit 1;
}

usage="\
Usage: $0 [OPTION]... [VAR=VALUE]...

    --builddir=                  the build directory
    --generator=                 run cmake --help for a list of generators
    --prefix=                    installation prefix
    --verbose                    makefile verbose output

Optional Features:
    --build-type=[Debug|Release] set cmake build type
    --enable-address-sanitizer   enable address sanitizer support
    --enable-ub-sanitizer        enable undefined behavior sanitizer support
    --enable-thread-sanitizer    enable thread sanitizer support
"

sourcedir="$( cd "$( dirname "$0" )" && pwd )"

# Function to append a CMake cache entry definition to the
# CMakeCacheEntries variable
#   $1 is the cache entry variable name
#   $2 is the cache entry variable type
#   $3 is the cache entry variable value
append_cache_entry () {
    CMakeCacheEntries="$CMakeCacheEntries -D $1:$2=$3"
}

# set defaults
builddir=build
prefix=/opt/snet
build_type="Release"
verbose_option=OFF
coverage_enabled=no
CMakeCacheEntries=""
append_cache_entry CMAKE_INSTALL_PREFIX PATH   $prefix

# parse arguments
while [ $# -ne 0 ]; do
    case "$1" in
        *=*) optarg=`echo "$1" | sed 's/[-_a-zA-Z0-9]*=//'` ;;
        *) optarg= ;;
    esac

    case "$1" in
        --help|-h)
            echo "${usage}" 1>&2
            exit 1
            ;;
        --builddir=*)
            builddir=$optarg
            ;;
        --define=*)
            CMakeCacheEntries="$CMakeCacheEntries -D$optarg"
            ;;
        --generator=*)
            CMakeGenerator="$optarg"
            ;;
        --prefix=*)
            prefix=$optarg
            append_cache_entry CMAKE_INSTALL_PREFIX PATH $optarg
            ;;
        --verbose)
            verbose_option=ON
            ;;
        --enable-address-sanitizer)
            append_cache_entry ENABLE_ADDRESS_SANITIZER BOOL true
            ;;
        --disable-address-sanitizer)
            append_cache_entry ENABLE_ADDRESS_SANITIZER BOOL false
            ;;
        --enable-thread-sanitizer)
            append_cache_entry ENABLE_THREAD_SANITIZER  BOOL true
            ;;
        --disable-thread-sanitizer)
            append_cache_entry ENABLE_THREAD_SANITIZER  BOOL false
            ;;
        --enable-ub-sanitizer)
            append_cache_entry ENABLE_UB_SANITIZER      BOOL true
            ;;
        --disable-ub-sanitizer)
            append_cache_entry ENABLE_UB_SANITIZER      BOOL false
            ;;
        --build-type=*)
            if [ $optarg = "Debug" ] || [ $optarg = "Release" ]; then
                build_type=$optarg
            else
                echo "Invalid build type '$optarg'. Try $0 --help to see available build types."
                exit 1
            fi
            ;;
        *)
            echo "Invalid option '$1'.  Try $0 --help to see available options."
            exit 1
            ;;
    esac
    shift
done

if [ -d $builddir ]; then
    # If build directory exists, check if it has a CMake cache
    if [ -f $builddir/CMakeCache.txt ]; then
        # If the CMake cache exists, delete it so that this configuration
        # is not tainted by a previous one
        rm -f $builddir/CMakeCache.txt
    fi
else
    # Create build directory
    mkdir -p $builddir
fi

if [ "$coverage_enabled" = "yes" ]; then
    if [ "$verbose_option" = "ON" ]; then
        append_cache_entry CTEST_VERBOSE_FLAG      STRING "-VV"
    else
        append_cache_entry CTEST_VERBOSE_FLAG      STRING "--output-on-failure"
    fi
fi

echo "Build Directory : $builddir"
echo "Source Directory: $sourcedir"
cd $builddir

[ "$CMakeGenerator" ] && gen="-G $CMakeGenerator"

cmake $gen \
    -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
    -DCMAKE_VERBOSE_MAKEFILE="$verbose_option" \
    -DCMAKE_BUILD_TYPE:STRING="$build_type" \
    $CMakeCacheEntries $sourcedir

echo "# This is the command used to configure this build" > config.status
echo $command >> config.status
chmod u+x config.status

echo "Project configured"

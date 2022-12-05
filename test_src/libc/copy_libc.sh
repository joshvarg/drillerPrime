#!/bin/sh

# Initial copy script for libc files before modifying them
GLIBC_233=~/glibc-2.33/posix/
GLIBC_234=~/glibc-2.34/posix/
SRC_DIR=~/drillerPrime/test_src/libc/
cp "${GLIBC_233}fnmatch.c" "${SRC_DIR}fnmatch_233.c"
cp "${GLIBC_234}fnmatch.c" "${SRC_DIR}fnmatch_234.c"
cp "${GLIBC_234}fnmatch_loop.c" "${SRC_DIR}fnmatch_loop.c" # same for both versions
cp "${GLIBC_234}fnmatch.h" "${SRC_DIR}fnmatch.h" # same for both versions
#!/usr/bin/env bash

set -ex

UNICORN_VERSION="2.0.1.post1"
BASE="$PWD"
rm -rf vendor
pip download unicorn==$UNICORN_VERSION
mkdir -p tmp
trap 'cd "$BASE"; rm -rf tmp' EXIT
pushd tmp
unzip ../unicorn-$UNICORN_VERSION*
cp -r unicorn/include "$BASE/vendor"
popd

grep -A1 ^UNICORN_EXPORT vendor/unicorn/unicorn.h | grep -Ev 'UNICORN_EXPORT|--' | grep -Eo '(uc_\w*)\(' | sed -E -e 's/(uc_\w*)\(/XX(\1)/' >uc_macro.h
sed -z -E -i -e 's/\nUNICORN_EXPORT\n/\nUNICORN_EXPORT /g' -e 's/\nUNICORN_EXPORT([^(]*)(uc_\w*)\(/\nANGR_UNICORN_API\1(*\2)(/g' vendor/unicorn/unicorn.h
mv vendor/unicorn/unicorn.h tmp/tmp.h
cat - tmp/tmp.h >vendor/unicorn/unicorn.h <<EOF
#ifndef ANGR_UNICORN_API
#define ANGR_UNICORN_API extern
#endif
EOF

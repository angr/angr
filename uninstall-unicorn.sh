#!/bin/bash -e

find $VIRTUAL_ENV -iname unicorn | xargs rm -vrf
find $VIRTUAL_ENV -iname libunicorn.so | xargs rm -v

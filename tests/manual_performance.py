#!/usr/bin/env python

import time
#import nose
import logging
l = logging.getLogger("angr_tests.counter")

try:
    # pylint: disable=W0611,F0401
    import standard_logging
    import angr_debug
except ImportError:
    pass

l.setLevel(logging.INFO)


addresses_counter = {
    'armel': None,
    'armhf': None,  # addr+1 to force thumb
    'i386': None,
    'mips': None,
    'mipsel': None,
    'ppc': None,
    'ppc64': None,
    'x86_64': None
}

import angr

import os
location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries/tests'))

def run_counter(arch):
    p = angr.Project(location + '/' + arch + '/counter')

    pg = p.factory.path_group()

    start = time.time()
    pg.step(n=1000)
    end = time.time()

    l.info("Time passed: %f seconds", end-start)

def test_counter():
    for arch in addresses_counter:
        yield run_counter, arch

if __name__ == "__main__":
    import sys
    if len(sys.argv) == 1:
        for func, march in test_counter():
            print 'testing ' + march
            func(march)
    else:
        run_counter(sys.argv[1])

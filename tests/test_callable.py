#!/usr/bin/env python

import nose
import logging
l = logging.getLogger("angr_tests")

try:
    # pylint: disable=W0611,F0401
    import standard_logging
    import angr_debug
except ImportError:
    pass


addresses_fauxware = {
    'armel': 0x8524,
    'armhf': 0x104c9,   # addr+1 to force thumb
    'i386': 0x8048524,
    'mips': 0x400710,
    'mipsel': 0x4006d0,
    'ppc': 0x1000054c,
    'ppc64': 0x10000698,
    'x86_64': 0x400664
}

addresses_manysum = {
    'armel': 0x1041c,
    'armhf': 0x103bd,
    'i386': 0x80483d8,
    'mips': 0x400704,
    'mipsel': 0x400704,
    'ppc': 0x10000418,
    'ppc64': 0x10000500,
    'x86_64': 0x4004ca
}

import angr
from simuvex.s_type import SimTypePointer, SimTypeFunction, SimTypeChar, SimTypeInt
from angr.surveyors.caller import Callable
from angr.errors import AngrCallableMultistateError

import os
location = str(os.path.dirname(os.path.realpath(__file__)))

def run_fauxware(arch):
    addr = addresses_fauxware[arch]
    p = angr.Project(location + '/blob/' + arch + '/fauxware')
    charstar = SimTypePointer(p.arch, SimTypeChar())
    prototype = SimTypeFunction((charstar, charstar), SimTypeInt(p.arch.bits, False))
    authenticate = Callable(p, addr, prototype, toc=0x10018E80 if arch == 'ppc64' else None)
    nose.tools.assert_equal(authenticate("asdf", "SOSNEAKY").model.value, 1)
    nose.tools.assert_raises(AngrCallableMultistateError, authenticate, "asdf", "NOSNEAKY")

def run_manysum(arch):
    addr = addresses_manysum[arch]
    p = angr.Project(location + '/blob/' + arch + '/manysum')
    inttype = SimTypeInt(p.arch.bits, False)
    prototype = SimTypeFunction([inttype]*11, inttype)
    sumlots = Callable(p, addr, prototype)
    result = sumlots(1,2,3,4,5,6,7,8,9,10,11)
    nose.tools.assert_false(result.symbolic)
    nose.tools.assert_equal(result.model.value, sum(xrange(12)))

def test_fauxware():
    for arch in addresses_fauxware:
        yield run_fauxware, arch

def test_manysum():
    for arch in addresses_manysum:
        yield run_manysum, arch

if __name__ == "__main__":
    for func, march in test_fauxware():
        print 'testing ' + march
        func(march)
    for func, march in test_manysum():
        print 'testing ' + march
        func(march)

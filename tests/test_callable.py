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


# $ for arch in blob/*; do; echo $arch; objdump -d $arch/fauxware | grep '<authenticate>:'; echo; done
# blob/armel
# 00008524 <authenticate>:
#
# blob/i386
# 08048524 <authenticate>:
#
# blob/mips
# 00400710 <authenticate>:
#
# blob/mipsel
# 004006d0 <authenticate>:
#
# blob/ppc
# 1000054c <authenticate>:
#
# blob/x86_64
# 0000000000400664 <authenticate>:

addresses = {
    'armel': 0x8524,
    'i386': 0x48524,
    'mips': 0x400710,
    'mipsel': 0x4006d0,
    'ppc': 0x1000054c,
    'x86_64': 0x400664
}

stub = lambda: None
test_armel = stub
test_i386 = stub
test_mips = stub
test_mipsel = stub
test_ppc = stub
test_x86_64 = stub

import angr
from simuvex.s_type import SimTypePointer, SimTypeFunction, SimTypeChar, SimTypeInt
from angr.surveyors.caller import Callable

import os, sys
test_location = str(os.path.dirname(os.path.realpath(__file__)))

def run_single(arch, addr):
    p = angr.Project(test_location + '/blob/' + arch + '/fauxware')
    charstar = SimTypePointer(p.arch, SimTypeChar())
    prototype = SimTypeFunction((charstar, charstar), SimTypeInt(p.arch.bits, False))
    authenticate = Callable(p, addr, prototype)
    nose.tools.assert_equal(authenticate("/etc/passwd", "SOSNEAKY").model.value, 1)
    nose.tools.assert_equal(authenticate("/etc/passwd", "NOSNEAKY").model.value, 0)

def make_tester(arch, addr):
    return lambda: run_single(arch, addr)

thismodule = sys.modules[__name__]
for march, maddr in addresses.iteritems():
    setattr(thismodule, 'test_' + march, make_tester(march, maddr))

if __name__ == "__main__":
    test_mips()
    test_mipsel()
    test_armel()
    test_i386()
    test_x86_64()
    test_ppc()

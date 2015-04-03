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

import angr

# load the tests
import os
test_location = str(os.path.dirname(os.path.realpath(__file__)))
brancher_amd64 = None
brancher_ppc32 = None
brancher_arm = None
brancher_mipsel = None

def setup_ppc32():
    global brancher_ppc32
    brancher_ppc32 = angr.Project(test_location + "/blob/ppc/brancher",  arch="PPC32")

def setup_module():
    setup_ppc32()

def test_ppc32():
    #import simuvex
    #import symexec as se
    #def suave_checker(state):
    #   for c in state.inspect.added_constraints:
    #       for v in se.variable_constituents(c):
    #           if "merge" in v:
    #               return True
    #   return False

    e = brancher_ppc32.initial_exit()
    #e.state.inspect.add_breakpoint('constraints', simuvex.BP(simuvex.BP_BEFORE, condition=suave_checker))

    results = angr.surveyors.Explorer(brancher_ppc32, find=0x10000540, num_find=None, max_repeats=10).run()
    nose.tools.assert_equals(len(results.found), 5)
    #for f in results.found:
    #   print f.state.posix.dumps(0)

    hg = angr.surveyors.HappyGraph(paths=results.found)
    hg._merge_points = [ 0x10000540, 0x10000500 ]
    slc = angr.surveyors.Slicecutor(brancher_ppc32, hg, start=e)
    slc.run()

    u = slc.deadended[1].unmerge()
    s = [ ]

    s.append(u[0].state.posix.dumps(1))
    s.append(u[1].state.posix.dumps(1))
    s.append(u[2].state.posix.dumps(1))
    s.append(u[3].state.posix.dumps(1))
    s = sorted(s)

    nose.tools.assert_equals(s[0], '>10\n<20\n\x00even\n')
    nose.tools.assert_equals(s[1], '>10\n<20\n\x00odd\n\x00')
    nose.tools.assert_equals(s[2], '>10\n>=20\neven\n')
    nose.tools.assert_equals(s[3], '>10\n>=20\nodd\n\x00')

if __name__ == "__main__":
    logging.getLogger("angr.surveyors.Slicecutor").setLevel(logging.DEBUG)
    logging.getLogger("angr.surveyors.Explorer").setLevel(logging.DEBUG)
    setup_ppc32()
    test_ppc32()

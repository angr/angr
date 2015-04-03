#!/usr/bin/env python

import nose
import logging
l = logging.getLogger("angr.tests")

try:
    # pylint: disable=W0611,F0401
    import standard_logging
    import angr_debug
except ImportError:
    pass

import angr, simuvex

# load the tests
import os
test_location = str(os.path.dirname(os.path.realpath(__file__)))
fauxware_x86 = None
fauxware_amd64 = None
fauxware_ppc32 = None
fauxware_arm = None
fauxware_mipsel = None

def setup_x86():
    global fauxware_x86
    fauxware_x86 = angr.Project(test_location + "/blob/i386/fauxware",  arch="X86")
def setup_amd64():
    global fauxware_amd64
    fauxware_amd64 = angr.Project(test_location + "/blob/x86_64/fauxware",  arch="AMD64")
def setup_ppc32():
    global fauxware_ppc32
    fauxware_ppc32 = angr.Project(test_location + "/blob/ppc/fauxware",  arch="PPC32")
def setup_mipsel():
    global fauxware_mipsel
    fauxware_mipsel = angr.Project(test_location + "/blob/mipsel/fauxware",  arch=simuvex.SimMIPS32(endness="Iend_LE"))
def setup_arm():
    global fauxware_arm
    fauxware_arm = angr.Project(test_location + "/blob/armel/fauxware/fauxware-arm",  arch=simuvex.SimARM(endness="Iend_LE"))

def setup_module():
    #setup_x86()
    setup_amd64()
    #setup_arm()
    #setup_ppc32()
    #setup_mipsel()

def test_amd64():
    EXPECTED_FUNCTIONS = set([4195712, 4195616, 4195632, 4195940, 4196077, 4196093, 4195600, 4195680, 4195648, 4195696, 4195664, 4196125])
    EXPECTED_BLOCKS = set([0x40071D, 0x40073E, 0x400754, 0x40076A, 0x400774, 0x40078A, 0x4007A0, 0x4007B3, 0x4007C7, 0x4007C9, 0x4007BD, 0x4007D3])
    EXPECTED_CALLSITES = set([0x40071D, 0x40073E, 0x400754, 0x40076A, 0x400774, 0x40078A, 0x4007A0, 0x4007BD, 0x4007C9])
    EXPECTED_CALLSITE_TARGETS = set([4195600L, 4195632L, 4195632L, 4195600L, 4195632L, 4195632L, 4195940L, 4196077L, 4196093L])
    EXPECTED_CALLSITE_RETURNS = set([4196158L, 4196180L, 4196202L, 4196212L, 4196234L, 4196256L, 4196275L, 4196295L, 4196307L])

    cfg = fauxware_amd64.analyses.CFG()
    func_man = cfg.function_manager
    functions = func_man.functions
    nose.tools.assert_equal(set(functions.keys()), EXPECTED_FUNCTIONS)

    main = func_man.function(0x40071D)
    nose.tools.assert_equal(main.startpoint, 0x40071D)
    nose.tools.assert_equal(set(main.basic_blocks), EXPECTED_BLOCKS)
    nose.tools.assert_equal([0x4007D3], main.endpoints)
    nose.tools.assert_equal(set(main.get_call_sites()), EXPECTED_CALLSITES)
    nose.tools.assert_equal(set(map(main.get_call_target, main.get_call_sites())), EXPECTED_CALLSITE_TARGETS)
    nose.tools.assert_equal(set(map(main.get_call_return, main.get_call_sites())), EXPECTED_CALLSITE_RETURNS)
    nose.tools.assert_true(main.has_return)

    # These tests fail for reasons of fastpath, probably
    #nose.tools.assert_true(main.bp_on_stack)
    #nose.tools.assert_equal(main.name, 'main')
    #nose.tools.assert_true(main.retaddr_on_stack)
    #nose.tools.assert_equal(0x50, main.sp_difference)

    #l.info(functions)
    # TODO: Check the result returned
    #func_man.dbg_draw()
    #l.info("PNG files generated.")

def test_call_to():
    class dummy(object):
        '''
        This is a mock object.
        '''

        def __init__(self):
            self._attrs = { }

        def __getattr__(self, item):
            if item not in self._attrs:
                self._attrs[item] = dummy()

            return self._attrs[item]

        def find_symbol_name(self, *args, **kwargs):
            return 'unknown'

    project = dummy()
    project.arch = simuvex.SimAMD64()

    fm = angr.FunctionManager(project, None)
    fm.call_to(0x400000, 0x400410, 0x400420, 0x400414)

    nose.tools.assert_in(0x400000, fm.functions.keys())
    nose.tools.assert_in(0x400420, fm.functions.keys())

if __name__ == "__main__":
    test_call_to()

    setup_amd64()
    l.info("LOADED")
    test_amd64()
    l.info("DONE")

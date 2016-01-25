import nose
import angr
from archinfo import ArchAMD64

import logging
l = logging.getLogger("angr.tests")

import os
test_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries/tests'))

def test_amd64():
    logging.getLogger('angr.analyses.cfg').setLevel(logging.DEBUG)

    fauxware_amd64 = angr.Project(test_location + "/x86_64/fauxware")
    EXPECTED_FUNCTIONS = { 0x400580, 0x400540, 0x400520, 0x4006ed, 0x400664, 0x4007e0, 0x40071d, 0x400880,
                           0x4005ac, 0x4004e0, 0x400530, 0x400510, 0x400560, 0x400550, 0x4006fd, 0x400570,
                           0x400640 }
    EXPECTED_BLOCKS = { 0x40071D, 0x40073E, 0x400754, 0x40076A, 0x400774, 0x40078A, 0x4007A0, 0x4007B3, 0x4007C7,
                        0x4007C9, 0x4007BD, 0x4007D3 }
    EXPECTED_CALLSITES = { 0x40071D, 0x40073E, 0x400754, 0x40076A, 0x400774, 0x40078A, 0x4007A0, 0x4007BD, 0x4007C9 }
    EXPECTED_CALLSITE_TARGETS = { 4195600L, 4195632L, 4195632L, 4195600L, 4195632L, 4195632L, 4195940L, 4196077L,
                                  4196093L }
    EXPECTED_CALLSITE_RETURNS = { 4196158L, 4196180L, 4196202L, 4196212L, 4196234L, 4196256L, 4196275L, 4196295L,
                                  None }

    cfg = fauxware_amd64.analyses.CFG()
    func_man = cfg.function_manager
    functions = func_man.functions
    nose.tools.assert_equal(set([ k for k in functions.keys() if k < 0x500000 ]), EXPECTED_FUNCTIONS)

    main = func_man.function(name='main')
    nose.tools.assert_equal(main.startpoint, 0x40071D)
    nose.tools.assert_equal(set(main.basic_blocks), EXPECTED_BLOCKS)
    nose.tools.assert_equal([0x4007D3], main.endpoints)
    nose.tools.assert_equal(set(main.get_call_sites()), EXPECTED_CALLSITES)
    nose.tools.assert_equal(set(map(main.get_call_target, main.get_call_sites())), EXPECTED_CALLSITE_TARGETS)
    nose.tools.assert_equal(set(map(main.get_call_return, main.get_call_sites())), EXPECTED_CALLSITE_RETURNS)
    nose.tools.assert_true(main.has_return)

    rejected = func_man.function(name='rejected')
    nose.tools.assert_equal(rejected.returning, False)

    # transition graph
    main_g = main.transition_graph
    main_g_edges = main_g.edges(data=True)
    nose.tools.assert_true((0x40071d, 0x400510, {'type': 'call'}) in main_g_edges)
    nose.tools.assert_true((0x40071d, 0x40073e, {'type': 'fake_return'}) in main_g_edges)
    nose.tools.assert_true((0x40073e, 0x400530, {'type': 'call'}) in main_g_edges)
    nose.tools.assert_true((0x40073e, 0x400754, {'type': 'fake_return'}) in main_g_edges)

    # rejected() does not return
    nose.tools.assert_true((0x4007c9, 0x4006fd, {'type': 'call'}) in main_g_edges)
    nose.tools.assert_false((0x4007c9, 0x4007d3, {'type': 'fake_return'}) in main_g_edges)

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
    # pylint: disable=unused-argument,no-self-use,attribute-defined-outside-init
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

        def is_hooked(self, addr):
            return False

    project = dummy()
    project.arch = ArchAMD64()

    fm = angr.artifacts.FunctionManager(project, None)
    fm.call_to(0x400000, 0x400410, 0x400420, 0x400414)

    nose.tools.assert_in(0x400000, fm.functions.keys())
    nose.tools.assert_in(0x400420, fm.functions.keys())

if __name__ == "__main__":
    test_call_to()
    test_amd64()

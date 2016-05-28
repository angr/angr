import os
import logging

import nose.tools

import angr

from angr.analyses.cfg_fast import Segment, SegmentList

l = logging.getLogger("angr.tests.test_cfgfast")

test_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries/tests'))

def cfg_fast(arch, binary_path, func_addrs):
    """
    Generate a CFGFast analysis result on the given binary, and test if all specified functions are found

    :param arch: the architecture, will be prepended to `binary_path`
    :param binary_path: path to the binary under the architecture directory
    :param func_addrs: A collection of function addresses that should be recovered
    :return: None
    """

    path = os.path.join(test_location, arch, binary_path)
    proj = angr.Project(path, load_options={'auto_load_libs': False})

    cfg = proj.analyses.CFGFast()
    nose.tools.assert_true(set(cfg.kb.functions.keys()).issuperset(func_addrs))

    # Segment only
    cfg = proj.analyses.CFGFast(force_segment=True)
    nose.tools.assert_true(set(cfg.kb.functions.keys()).issuperset(func_addrs))

def test_cfg_0():
    filename = 'cfg_0'
    functions = {
        'x86_64': {
            0x400410,
            0x400420,
            0x400430,
            0x400440,
            0x400470,
            0x40052c,
            0x40053c,
        }
    }
    arches = functions.keys()

    for arch in arches:
        yield cfg_fast, arch, filename, functions[arch]

def test_cfg_0_pe():
    filename = 'cfg_0_pe'
    functions = {
        'x86_64': {
            # 0x40150a,  # currently angr identifies 0x40150e due to the way _func_addrs_from_prologues() is
                         # implemented. this issue can be resolved with a properly implemented approach like Byte-Weight
            0x4014f0,
        }
    }
    arches = functions.keys()

    for arch in arches:
        yield cfg_fast, arch, filename, functions[arch]

def test_segment_list_0():
    seg_list = SegmentList()
    seg_list.occupy(0, 1, "code")
    seg_list.occupy(2, 3, "code")

    nose.tools.assert_equal(len(seg_list), 2)
    nose.tools.assert_equal(seg_list._list[0].end, 1)
    nose.tools.assert_equal(seg_list._list[1].end, 5)
    nose.tools.assert_equal(seg_list.is_occupied(4), True)
    nose.tools.assert_equal(seg_list.is_occupied(5), False)

def test_segment_list_1():
    seg_list = SegmentList()

    # They should be merged
    seg_list.occupy(0, 1, "code")
    seg_list.occupy(1, 2, "code")

    nose.tools.assert_equal(len(seg_list), 1)
    nose.tools.assert_equal(seg_list._list[0].start, 0)
    nose.tools.assert_equal(seg_list._list[0].end, 3)

def test_segment_list_2():
    seg_list = SegmentList()

    # They should not be merged
    seg_list.occupy(0, 1, "code")
    seg_list.occupy(1, 2, "data")

    nose.tools.assert_equal(len(seg_list), 2)
    nose.tools.assert_equal(seg_list._list[0].start, 0)
    nose.tools.assert_equal(seg_list._list[0].end, 1)
    nose.tools.assert_equal(seg_list._list[1].start, 1)
    nose.tools.assert_equal(seg_list._list[1].end, 3)

def test_segment_list_3():
    seg_list = SegmentList()

    # They should be merged, and create three different segments
    seg_list.occupy(0, 5, "code")
    seg_list.occupy(5, 5, "code")
    seg_list.occupy(1, 2, "data")

    nose.tools.assert_equal(len(seg_list), 3)

    nose.tools.assert_equal(seg_list._list[0].start, 0)
    nose.tools.assert_equal(seg_list._list[0].end, 1)
    nose.tools.assert_equal(seg_list._list[0].sort, "code")

    nose.tools.assert_equal(seg_list._list[1].start, 1)
    nose.tools.assert_equal(seg_list._list[1].end, 3)
    nose.tools.assert_equal(seg_list._list[1].sort, "data")

    nose.tools.assert_equal(seg_list._list[2].start, 3)
    nose.tools.assert_equal(seg_list._list[2].end, 10)
    nose.tools.assert_equal(seg_list._list[2].sort, "code")

def test_segment_list_4():
    seg_list = SegmentList()

    seg_list.occupy(5, 5, "code")
    seg_list.occupy(4, 1, "code")
    seg_list.occupy(2, 2, "code")

    nose.tools.assert_equal(len(seg_list), 1)
    nose.tools.assert_equal(seg_list._list[0].start, 2)
    nose.tools.assert_equal(seg_list._list[0].end, 10)

def test_segment_list_5():
    seg_list = SegmentList()

    seg_list.occupy(5, 5, "data")
    seg_list.occupy(4, 1, "code")
    seg_list.occupy(2, 2, "data")

    nose.tools.assert_equal(len(seg_list), 3)
    nose.tools.assert_equal(seg_list._list[0].start, 2)
    nose.tools.assert_equal(seg_list._list[2].end, 10)

    seg_list.occupy(3, 2, "data")

    nose.tools.assert_equal(len(seg_list), 1)
    nose.tools.assert_equal(seg_list._list[0].start, 2)
    nose.tools.assert_equal(seg_list._list[0].end, 10)

def main():

    g = globals()
    segmentlist_tests = [ v for k, v in g.iteritems() if k.startswith("test_segment_list_") and hasattr(v, "__call__")]

    for func in segmentlist_tests:
        func()

    for func, arch, filename, functions in test_cfg_0():
        func(arch, filename, functions)

    for func, arch, filename, functions in test_cfg_0_pe():
        func(arch, filename, functions)

if __name__ == "__main__":
    main()

import os
import logging
import sys

import nose.tools

import angr

from angr.analyses.cfg.cfg_fast import SegmentList

l = logging.getLogger("angr.tests.test_cfgfast")

test_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries/tests'))

def cfg_fast_functions_check(arch, binary_path, func_addrs, func_features):
    """
    Generate a fast CFG on the given binary, and test if all specified functions are found

    :param str arch: the architecture, will be prepended to `binary_path`
    :param str binary_path: path to the binary under the architecture directory
    :param dict func_addrs: A collection of function addresses that should be recovered
    :param dict func_features: A collection of features for some of the functions
    :return: None
    """

    path = os.path.join(test_location, arch, binary_path)
    proj = angr.Project(path, load_options={'auto_load_libs': False})

    cfg = proj.analyses.CFGFast()
    nose.tools.assert_true(set([ k for k in cfg.kb.functions.keys() ]).issuperset(func_addrs))

    for func_addr, feature_dict in func_features.iteritems():
        returning = feature_dict.get("returning", "undefined")
        if returning != "undefined":
            nose.tools.assert_is(cfg.kb.functions.function(addr=func_addr).returning, returning)

    # Segment only
    cfg = proj.analyses.CFGFast(force_segment=True)
    nose.tools.assert_true(set([ k for k in cfg.kb.functions.keys() ]).issuperset(func_addrs))

    for func_addr, feature_dict in func_features.iteritems():
        returning = feature_dict.get("returning", "undefined")
        if returning != "undefined":
            nose.tools.assert_is(cfg.kb.functions.function(addr=func_addr).returning, returning)

    # with normalization enabled
    cfg = proj.analyses.CFGFast(force_segment=True, normalize=True)
    nose.tools.assert_true(set([k for k in cfg.kb.functions.keys()]).issuperset(func_addrs))

    for func_addr, feature_dict in func_features.iteritems():
        returning = feature_dict.get("returning", "undefined")
        if returning != "undefined":
            nose.tools.assert_is(cfg.kb.functions.function(addr=func_addr).returning, returning)

def cfg_fast_edges_check(arch, binary_path, edges):
    """
    Generate a fast CFG on the given binary, and test if all edges are found.

    :param str arch: the architecture, will be prepended to `binary_path`
    :param str binary_path: path to the binary under the architecture directory
    :param list edges: a list of edges
    :return: None
    """

    path = os.path.join(test_location, arch, binary_path)
    proj = angr.Project(path, load_options={'auto_load_libs': False})

    cfg = proj.analyses.CFGFast()

    for src, dst in edges:
        src_node = cfg.get_any_node(src)
        dst_node = cfg.get_any_node(dst)
        nose.tools.assert_in(dst_node, src_node.successors,
                             msg="CFG edge %s-%s is not found." % (src_node, dst_node)
                             )

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

    function_features = {
        'x86_64': {}
    }

    for arch in arches:
        yield cfg_fast_functions_check, arch, filename, functions[arch], function_features[arch]

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

    function_features = {
        'x86_64': {}
    }

    for arch in arches:
        yield cfg_fast_functions_check, arch, filename, functions[arch], function_features[arch]

def test_fauxware():
    filename = "fauxware"
    functions = {
        'x86_64': {
            0x4004e0,
            0x400510,
            0x400520,
            0x400530,
            0x400540,
            0x400550,
            0x400560,
            0x400570,  # .plt._exit
            0x400580,  # _start
            0x4005ac,
            0x4005d0,
            0x400640,
            0x400664,
            0x4006ed,
            0x4006fd,
            0x40071d,  # main
            0x4007e0,
            0x400870,
            0x400880,
            0x4008b8,
        },
        'mips': {
            0x400534,  # _init
            0x400574,
            0x400598,
            0x4005d0,  # _ftext
            0x4005dc,
            0x400630,  # __do_global_dtors_aux
            0x4006d4,  # frame_dummy
            0x400708,
            0x400710,  # authenticate
            0x400814,
            0x400814,  # accepted
            0x400868,  # rejected
            0x4008c0,  # main
            0x400a34,
            0x400a48,  # __libc_csu_init
            0x400af8,
            0x400b00,  # __do_global_ctors_aux
            0x400b58,
            ### plt entries
            0x400b60,  # strcmp
            0x400b70,  # read
            0x400b80,  # printf
            0x400b90,  # puts
            0x400ba0,  # exit
            0x400bb0,  # open
            0x400bc0,  # __libc_start_main
        },
    }

    function_features = {
        'x86_64':
            {
                0x400570: # plt.exit
                    {
                        "returning": False
                    },
                0x4006fd: # rejected
                    {
                        "returning": False
                    }
            },
        'mips':
            {
                0x400868:  # rejected
                    {
                        "returning": False,
                    }
            },
    }

    return_edges = {
        'x86_64':
            [
                (0x4006fb, 0x4007c7)  # return from accepted to main
            ],
        'mips':
            [
                (0x40084c, 0x400a04)  # returning edge from accepted to main
            ],
    }

    arches = functions.keys()

    for arch in arches:
        yield cfg_fast_functions_check, arch, filename, functions[arch], function_features[arch]
        yield cfg_fast_edges_check, arch, filename, return_edges[arch]

def test_cfg_loop_unrolling():
    filename = "cfg_loop_unrolling"
    edges = {
        'x86_64': {
            (0x400658, 0x400636),
            (0x400658, 0x400661),
            (0x400651, 0x400636),
            (0x400651, 0x400661),
        }
    }

    arches = edges.keys()

    for arch in arches:
        yield cfg_fast_edges_check, arch, filename, edges[arch]

def test_cfg_switches():

    #logging.getLogger('angr.analyses.cfg.cfg_fast').setLevel(logging.INFO)
    #logging.getLogger('angr.analyses.cfg.indirect_jump_resolvers.jumptable').setLevel(logging.DEBUG)

    filename = "cfg_switches"

    edges = {
        'x86_64': {
            # jump table 0 in func_0
            (0x40053a, 0x400547),
            (0x40053a, 0x400552),
            (0x40053a, 0x40055d),
            (0x40053a, 0x400568),
            (0x40053a, 0x400573),
            (0x40053a, 0x400580),
            (0x40053a, 0x40058d),
            # jump table 0 in func_1
            (0x4005bc, 0x4005c9),
            (0x4005bc, 0x4005d8),
            (0x4005bc, 0x4005e7),
            (0x4005bc, 0x4005f6),
            (0x4005bc, 0x400605),
            (0x4005bc, 0x400614),
            (0x4005bc, 0x400623),
            (0x4005bc, 0x400632),
            (0x4005bc, 0x40063e),
            (0x4005bc, 0x40064a),
            (0x4005bc, 0x4006b0),
            # jump table 1 in func_1
            (0x40065a, 0x400667),
            (0x40065a, 0x400673),
            (0x40065a, 0x40067f),
            (0x40065a, 0x40068b),
            (0x40065a, 0x400697),
            (0x40065a, 0x4006a3),
            # jump table 0 in main
            (0x4006e1, 0x4006ee),
            (0x4006e1, 0x4006fa),
            (0x4006e1, 0x40070b),
            (0x4006e1, 0x40071c),
            (0x4006e1, 0x40072d),
            (0x4006e1, 0x40073e),
            (0x4006e1, 0x40074f),
            (0x4006e1, 0x40075b),
        }
    }

    arches = edges.keys()

    for arch in arches:
        yield cfg_fast_edges_check, arch, filename, edges[arch]

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

def test_segment_list_6():
    seg_list = SegmentList()

    seg_list.occupy(10, 20, "code")
    seg_list.occupy(9, 2, "data")

    nose.tools.assert_equal(len(seg_list), 2)
    nose.tools.assert_equal(seg_list._list[0].start, 9)
    nose.tools.assert_equal(seg_list._list[0].end, 11)
    nose.tools.assert_equal(seg_list._list[0].sort, 'data')

    nose.tools.assert_equal(seg_list._list[1].start, 11)
    nose.tools.assert_equal(seg_list._list[1].end, 30)
    nose.tools.assert_equal(seg_list._list[1].sort, 'code')

#
# Indirect jump resolvers
#

def test_resolve_x86_elf_pic_plt():
    path = os.path.join(test_location, 'i386', 'fauxware_pie')
    proj = angr.Project(path, load_options={'auto_load_libs': False})

    cfg = proj.analyses.CFGFast()

    # puts
    puts_node = cfg.get_any_node(0x4005b0)
    nose.tools.assert_is_not_none(puts_node)

    # there should be only one successor, which jumps to SimProcedure puts
    nose.tools.assert_equal(len(puts_node.successors), 1)
    puts_successor = puts_node.successors[0]
    nose.tools.assert_equal(puts_successor.addr, proj.loader.find_symbol('puts').rebased_addr)

    # the SimProcedure puts should have more than one successors, which are all return targets
    nose.tools.assert_equal(len(puts_successor.successors), 3)
    simputs_successor = puts_successor.successors
    return_targets = set(a.addr for a in simputs_successor)
    nose.tools.assert_equal(return_targets, { 0x400800, 0x40087e, 0x4008b6 })

#
# Function names
#

def test_function_names_for_unloaded_libraries():
    path = os.path.join(test_location, 'i386', 'fauxware_pie')
    proj = angr.Project(path, load_options={'auto_load_libs': False})

    cfg = proj.analyses.CFGFast()

    function_names = [ f.name if not f.is_plt else 'plt_' + f.name for f in cfg.functions.values() ]

    nose.tools.assert_in('plt_puts', function_names)
    nose.tools.assert_in('plt_read', function_names)
    nose.tools.assert_in('plt___stack_chk_fail', function_names)
    nose.tools.assert_in('plt_exit', function_names)
    nose.tools.assert_in('puts', function_names)
    nose.tools.assert_in('read', function_names)
    nose.tools.assert_in('__stack_chk_fail', function_names)
    nose.tools.assert_in('exit', function_names)

#
# Basic blocks
#

def test_block_instruction_addresses_armhf():
    path = os.path.join(test_location, 'armhf', 'fauxware')
    proj = angr.Project(path, auto_load_libs=False)

    cfg = proj.analyses.CFGFast()

    main_func = cfg.kb.functions['main']

    # all instruction addresses of the block must be odd
    block = next((b for b in main_func.blocks if b.addr == main_func.addr))

    nose.tools.assert_equal(len(block.instruction_addrs), 12)
    for instr_addr in block.instruction_addrs:
        nose.tools.assert_true(instr_addr % 2 == 1)

    main_node = cfg.get_any_node(main_func.addr)
    nose.tools.assert_is_not_none(main_node)
    nose.tools.assert_equal(len(main_node.instruction_addrs), 12)
    for instr_addr in main_node.instruction_addrs:
        nose.tools.assert_true(instr_addr % 2 == 1)

#
# Blanket
#

def test_blanket_fauxware():

    path = os.path.join(test_location, 'x86_64', 'fauxware')
    proj = angr.Project(path, auto_load_libs=False)

    cfg = proj.analyses.CFGFast()

    cfb = proj.analyses.CFBlanket(cfg=cfg)

    # it should raise a key error when calling floor_addr on address 0 because nothing is mapped there
    nose.tools.assert_raises(KeyError, cfb.floor_addr, 0)
    # an instruction (or a block) starts at 0x400580
    nose.tools.assert_equal(cfb.floor_addr(0x400581), 0x400580)
    # a block ends at 0x4005a9 (exclusive)
    nose.tools.assert_equal(cfb.ceiling_addr(0x400581), 0x4005a9)


def run_all():

    g = globals()
    segmentlist_tests = [ v for k, v in g.iteritems() if k.startswith("test_segment_list_") and hasattr(v, "__call__")]

    for func in segmentlist_tests:
        print func.__name__
        func()

    for args in test_cfg_0():
        print args[0].__name__
        args[0](*args[1:])

    for args in test_cfg_0_pe():
        print args[0].__name__
        args[0](*args[1:])

    for args in test_fauxware():
        print args[0].__name__
        args[0](*args[1:])

    for args in test_cfg_loop_unrolling():
        print args[0].__name__
        args[0](*args[1:])

    for args in test_cfg_switches():
        args[0](*args[1:])

    test_resolve_x86_elf_pic_plt()
    test_function_names_for_unloaded_libraries()
    test_block_instruction_addresses_armhf()


def main():
    if len(sys.argv) > 1:
        g = globals().copy()
        for func_and_args in g['test_' + sys.argv[1]]():
            func, args = func_and_args[0], func_and_args[1:]
            func(*args)
    else:
        run_all()

if __name__ == "__main__":
    logging.getLogger('angr.analyses.cfg.cfg_fast').setLevel(logging.DEBUG)

    main()

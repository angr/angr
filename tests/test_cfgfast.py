import os
import logging
import sys

from nose.plugins.attrib import attr
import nose.tools

import archinfo
import angr

from angr.analyses.cfg.cfg_fast import SegmentList
from angr.knowledge_plugins.cfg import CFGNode, CFGModel, MemoryDataSort

l = logging.getLogger("angr.tests.test_cfgfast")

test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..', 'binaries', 'tests')

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
    nose.tools.assert_true(set(cfg.kb.functions.keys()).issuperset(func_addrs))

    for func_addr, feature_dict in func_features.items():
        returning = feature_dict.get("returning", "undefined")
        if returning != "undefined":
            nose.tools.assert_is(cfg.kb.functions.function(addr=func_addr).returning, returning)

    # Segment only
    cfg = proj.analyses.CFGFast(force_segment=True)
    nose.tools.assert_true(set(cfg.kb.functions.keys()).issuperset(func_addrs))

    for func_addr, feature_dict in func_features.items():
        returning = feature_dict.get("returning", "undefined")
        if returning != "undefined":
            nose.tools.assert_is(cfg.kb.functions.function(addr=func_addr).returning, returning)

    # with normalization enabled
    cfg = proj.analyses.CFGFast(force_segment=True, normalize=True)
    nose.tools.assert_true(set(cfg.kb.functions.keys()).issuperset(func_addrs))

    for func_addr, feature_dict in func_features.items():
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
        src_node = cfg.model.get_any_node(src)
        dst_node = cfg.model.get_any_node(dst)
        nose.tools.assert_is_not_none(src_node, msg="CFG node 0x%x is not found." % src)
        nose.tools.assert_is_not_none(dst_node, msg="CFG node 0x%x is not found." % dst)
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


@attr(speed='slow')
def test_busybox():
    filename = "busybox"
    edges = {
        "mipsel": {
            (0x4091ec, 0x408de0),
            (0x449acc, 0x5003b8),  # call to putenv. address of putenv may change in the future
            (0x467cfc, 0x500014),  # call to free. address of free may change in the future
        }
    }

    for arch, edges_ in edges.items():
        yield cfg_fast_edges_check, arch, filename, edges_


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
        },
        'armel': {
            # jump table 0 in func_0
            (0x10434, 0x10488),
            (0x10434, 0x104e8),
            (0x10434, 0x10498),
            (0x10434, 0x104a8),
            (0x10434, 0x104b8),
            (0x10434, 0x104c8),
            (0x10434, 0x104d8),
            (0x10454, 0x104e8), # default case
            # jump table 0 in func_1
            (0x10524, 0x105cc),
            (0x10524, 0x106b4),
            (0x10524, 0x105d8),
            (0x10524, 0x105e4),
            (0x10524, 0x105f0),
            (0x10524, 0x105fc),
            (0x10524, 0x10608),
            (0x10524, 0x10614),
            (0x10524, 0x10620),
            (0x10524, 0x1062c),
            (0x10524, 0x10638),
            (0x10534, 0x106b4),  # default case
            # jump table 1 in func_1
            (0x10650, 0x106a4),  # default case
            (0x10640, 0x10668),
            (0x10640, 0x10674),
            (0x10640, 0x10680),
            (0x10640, 0x1068c),
            (0x10640, 0x10698),
            # jump table 0 in main
            (0x10734, 0x107fc),
            (0x10734, 0x10808),
            (0x10734, 0x10818),
            (0x10734, 0x10828),
            (0x10734, 0x10838),
            (0x10734, 0x10848),
            (0x10734, 0x10858),
            (0x10734, 0x10864),
            (0x10744, 0x10864),  # default case
        },
        's390x': {
            # jump table 0 in func_0
            (0x4007d4, 0x4007ea),  # case 1
            (0x4007d4, 0x4007f4),  # case 3
            (0x4007d4, 0x4007fe),  # case 5
            (0x4007d4, 0x400808),  # case 7
            (0x4007d4, 0x400812),  # case 9
            (0x4007d4, 0x40081c),  # case 12
            (0x4007c0, 0x4007ca),  # default case
            # jump table 0 in func_1
            (0x400872, 0x4008ae),  # case 2
            (0x400872, 0x4008be),  # case 10
            (0x400872, 0x4008ce),  # case 12
            (0x400872, 0x4008de),  # case 14
            (0x400872, 0x4008ee),  # case 15
            (0x400872, 0x4008fe),  # case 16
            (0x400872, 0x40090e),  # case 22
            (0x400872, 0x40091e),  # case 24
            (0x400872, 0x40092e),  # case 28
            (0x400872, 0x400888),  # case 38
            (0x400848, 0x400854),  # default case (1)
            (0x400872, 0x400854),  # default case (2)
            # jump table 1 in func_1
            (0x40093e, 0x400984),  # case 1
            (0x40093e, 0x400974),  # case 2
            (0x40093e, 0x400964),  # case 3
            (0x40093e, 0x400954),  # case 4
            (0x40093e, 0x400994),  # case 5
            (0x400898, 0x40089e),  # default case (1)
            # jump table 0 in main
            # case 1, 3, 5, 7, 9: optimized out
            (0x400638, 0x40064e),  # case 2
            (0x400638, 0x400692),  # case 4
            (0x400638, 0x4006a4),  # case 6
            (0x400638, 0x40066e),  # case 8
            (0x400638, 0x400680),  # case 10
            # case 45: optimized out
            (0x40062c, 0x40065c),  # default case
        }
    }

    arches = edges.keys()

    for arch in arches:
        yield cfg_fast_edges_check, arch, filename, edges[arch]


def test_cfg_about_time():

    # This is to test the correctness of the PLT stub removal in CFGBase
    proj = angr.Project(os.path.join(test_location, "x86_64", "about_time"), auto_load_libs=False)
    cfg = proj.analyses.CFG()

    # a PLT stub that should be removed
    nose.tools.assert_not_in(0x401026, cfg.kb.functions)
    # a PLT stub that should be removed
    nose.tools.assert_not_in(0x4010a6, cfg.kb.functions)
    # a PLT stub that should be removed
    nose.tools.assert_not_in(0x40115e, cfg.kb.functions)
    # the start function that should not be removed
    nose.tools.assert_in(proj.entry, cfg.kb.functions)


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
# Serialization
#

def test_serialization_cfgnode():
    path = os.path.join(test_location, "x86_64", "fauxware")
    proj = angr.Project(path, auto_load_libs=False)

    cfg = proj.analyses.CFGFast()
    # the first node
    node = cfg.model.get_any_node(proj.entry)
    nose.tools.assert_is_not_none(node)

    b = node.serialize()
    nose.tools.assert_greater(len(b), 0)
    new_node = CFGNode.parse(b)
    nose.tools.assert_equal(new_node.addr, node.addr)
    nose.tools.assert_equal(new_node.size, node.size)
    nose.tools.assert_equal(new_node.block_id, node.block_id)


def test_serialization_cfgfast():
    path = os.path.join(test_location, "x86_64", "fauxware")
    proj1 = angr.Project(path, auto_load_libs=False)
    proj2 = angr.Project(path, auto_load_libs=False)

    cfg = proj1.analyses.CFGFast()
    # parse the entire graph
    b = cfg.model.serialize()
    nose.tools.assert_greater(len(b), 0)

    # simulate importing a cfg from another tool
    cfg_model = CFGModel.parse(b, cfg_manager=proj2.kb.cfgs)

    nose.tools.assert_equal(len(cfg_model.graph.nodes), len(cfg.graph.nodes))
    nose.tools.assert_equal(len(cfg_model.graph.edges), len(cfg.graph.edges))

    n1 = cfg.model.get_any_node(proj1.entry)
    n2 = cfg_model.get_any_node(proj1.entry)
    nose.tools.assert_equal(n1, n2)


#
# CFG instance copy
#

def test_cfg_copy():
    path = os.path.join(test_location, "cgc", "CADET_00002")
    proj = angr.Project(path)

    cfg = proj.analyses.CFGFast()
    cfg_copy = cfg.copy()
    for attribute in cfg_copy.__dict__:
        if attribute in ['_graph', '_seg_list', '_model']:
            continue
        nose.tools.assert_equal(getattr(cfg, attribute), getattr(cfg_copy, attribute))

    nose.tools.assert_not_equal(id(cfg.model), id(cfg_copy.model))
    nose.tools.assert_not_equal(id(cfg.model.graph), id(cfg_copy.model.graph))
    nose.tools.assert_not_equal(id(cfg._seg_list), id(cfg_copy._seg_list))

#
# Alignment bytes
#

def test_cfg_0_pe_msvc_debug_nocc():
    filename = os.path.join('windows', 'msvc_cfg_0_debug.exe')
    proj = angr.Project(os.path.join(test_location, 'x86_64', filename), auto_load_libs=False)
    cfg = proj.analyses.CFGFast()

    # make sure 0x140015683 is marked as alignments
    sort = cfg._seg_list.occupied_by_sort(0x140016583)
    nose.tools.assert_equal(sort, "alignment", "Address 0x140016583 is not marked as alignment. The CC detection is "
                                               "probably failing.")

    nose.tools.assert_not_in(0x140015683, cfg.kb.functions)

#
# Indirect jump resolvers
#

# For test cases for jump table resolver, please refer to test_jumptables.py

def test_resolve_x86_elf_pic_plt():
    path = os.path.join(test_location, 'i386', 'fauxware_pie')
    proj = angr.Project(path, load_options={'auto_load_libs': False})

    cfg = proj.analyses.CFGFast()

    # puts
    puts_node = cfg.model.get_any_node(0x4005b0)
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

    main_node = cfg.model.get_any_node(main_func.addr)
    nose.tools.assert_is_not_none(main_node)
    nose.tools.assert_equal(len(main_node.instruction_addrs), 12)
    for instr_addr in main_node.instruction_addrs:
        nose.tools.assert_true(instr_addr % 2 == 1)

#
# Tail-call optimization detection
#

def test_tail_call_optimization_detection_armel():

    # GitHub issue #1286

    path = os.path.join(test_location, 'armel', 'Nucleo_read_hyperterminal-stripped.elf')
    proj = angr.Project(path, auto_load_libs=False)

    cfg = proj.analyses.CFGFast(resolve_indirect_jumps=True,
                                force_complete_scan=False,
                                normalize=True,
                                symbols=False,
                                detect_tail_calls=True
                                )

    all_func_addrs = set(cfg.functions.keys())
    nose.tools.assert_not_in(0x80010b5, all_func_addrs, "0x80010b5 is inside Reset_Handler().")
    nose.tools.assert_not_in(0x8003ef9, all_func_addrs, "0x8003ef9 is inside memcpy().")
    nose.tools.assert_not_in(0x8008419, all_func_addrs, "0x8008419 is inside __mulsf3().")

    # Functions that are jumped to from tail-calls
    tail_call_funcs = [ 0x8002bc1, 0x80046c1, 0x8000281, 0x8001bdb, 0x8002839, 0x80037ad, 0x8002c09, 0x8004165,
                        0x8004be1, 0x8002eb1 ]
    for member in tail_call_funcs:
        nose.tools.assert_in(member, all_func_addrs)

    # also test for tailcall return addresses

    # mapping of return blocks to return addrs that are the actual callers of certain tail-calls endpoints
    tail_call_return_addrs = {0x8002bd9: [0x800275f],   # 0x8002bc1
                              0x80046d7: [0x800275f],   # 0x80046c1
                              0x80046ed: [0x800275f],   # 0x80046c1
                              0x8001be7: [0x800068d, 0x8000695],   # 0x8001bdb ??
                              0x800284d: [0x800028b, 0x80006e1, 0x80006e7],   # 0x8002839
                              0x80037f5: [0x800270b, 0x8002733, 0x8002759, 0x800098f, 0x8000997], # 0x80037ad
                              0x80037ef: [0x800270b, 0x8002733, 0x8002759, 0x800098f, 0x8000997], # 0x80037ad
                              0x8002cc9: [0x8002d3b, 0x8002b99, 0x8002e9f, 0x80041ad,
                                          0x8004c87, 0x8004d35, 0x8002efb, 0x8002be9,
                                          0x80046eb, 0x800464f, 0x8002a09, 0x800325f,
                                          0x80047c1],    # 0x8002c09
                              0x8004183: [0x8002713],    # 0x8004165
                              0x8004c31: [0x8002713],    # 0x8004be1
                              0x8004c69: [0x8002713],    # 0x8004be1
                              0x8002ef1: [0x800273b]}    # 0x8002eb1

    # check all expected return addrs are present
    for returning_block_addr, expected_return_addrs in tail_call_return_addrs.items():
        returning_block = cfg.model.get_any_node(returning_block_addr)
        return_block_addrs = [rb.addr for rb in cfg.model.get_successors(returning_block)]
        msg = "%x: unequal sizes of expected_addrs [%d] and return_block_addrs [%d]" % \
                            (returning_block_addr, len(expected_return_addrs), len(return_block_addrs))
        nose.tools.assert_equal(len(return_block_addrs), len(expected_return_addrs), msg)
        for expected_addr in expected_return_addrs:
                msg = "expected retaddr %x not found for returning_block %x" % \
                                        (expected_addr, returning_block_addr)
                nose.tools.assert_in(expected_addr, return_block_addrs, msg)

#
# Incorrect function-leading blocks merging
#

def test_function_leading_blocks_merging():

    # GitHub issue #1312

    path = os.path.join(test_location, 'armel', 'Nucleo_read_hyperterminal-stripped.elf')
    proj = angr.Project(path, arch=archinfo.ArchARMCortexM(), auto_load_libs=False)

    cfg = proj.analyses.CFGFast(resolve_indirect_jumps=True,
                                force_complete_scan=True,
                                normalize=True,
                                symbols=False,
                                detect_tail_calls=True
                                )

    nose.tools.assert_in(0x8000799, cfg.kb.functions, "Function 0x8000799 does not exist.")
    nose.tools.assert_not_in(0x800079b, cfg.kb.functions, "Function 0x800079b does not exist.")
    nose.tools.assert_not_in(0x800079b, cfg.kb.functions[0x8000799].block_addrs_set,
                             "Block 0x800079b is found, but it should not exist.")
    nose.tools.assert_in(0x8000799, cfg.kb.functions[0x8000799].block_addrs_set,
                         "Block 0x8000799 is not found inside function 0x8000799.")
    nose.tools.assert_equal(next(iter(b for b in cfg.kb.functions[0x8000799].blocks if b.addr == 0x8000799)).size, 6,
                            "Block 0x800079b has an incorrect size.")


#
# Blanket
#

def test_blanket_fauxware():

    path = os.path.join(test_location, 'x86_64', 'fauxware')
    proj = angr.Project(path, auto_load_libs=False)

    cfg = proj.analyses.CFGFast()

    cfb = proj.analyses.CFBlanket(kb=cfg.kb)

    # it should raise a key error when calling floor_addr on address 0 because nothing is mapped there
    nose.tools.assert_raises(KeyError, cfb.floor_addr, 0)
    # an instruction (or a block) starts at 0x400580
    nose.tools.assert_equal(cfb.floor_addr(0x400581), 0x400580)
    # a block ends at 0x4005a9 (exclusive)
    nose.tools.assert_equal(cfb.ceiling_addr(0x400581), 0x4005a9)

#
# Data references
#

def test_data_references():

    path = os.path.join(test_location, 'x86_64', 'fauxware')
    proj = angr.Project(path, auto_load_libs=False)

    cfg = proj.analyses.CFGFast(data_references=True)

    memory_data = cfg.memory_data
    # There is no code reference
    code_ref_count = len([d for d in memory_data.values() if d.sort == MemoryDataSort.CodeReference])
    nose.tools.assert_greater_equal(code_ref_count, 0, msg="There should be no code reference.")

    # There are at least 2 pointer arrays
    ptr_array_count = len([d for d in memory_data.values() if d.sort == MemoryDataSort.PointerArray])
    nose.tools.assert_greater(ptr_array_count, 2, msg="Missing some pointer arrays.")

    nose.tools.assert_in(0x4008d0, memory_data)
    sneaky_str = memory_data[0x4008d0]
    nose.tools.assert_equal(sneaky_str.sort, "string")
    nose.tools.assert_equal(sneaky_str.content, b"SOSNEAKY")


#
# CFG with patches
#

def test_cfg_with_patches():

    path = os.path.join(test_location, 'x86_64', 'fauxware')
    proj = angr.Project(path, auto_load_libs=False)

    cfg = proj.analyses.CFGFast()
    auth_func = cfg.functions['authenticate']
    auth_func_addr = auth_func.addr

    # Take the authenticate function and add a retn patch for its very first block
    kb = angr.KnowledgeBase(proj)
    kb.patches.add_patch(auth_func_addr, b"\xc3")

    # with this patch, there should only be one block with one instruction in authenticate()
    _ = proj.analyses.CFGFast(kb=kb, use_patches=True)
    patched_func = kb.functions['authenticate']
    nose.tools.assert_equal(len(patched_func.block_addrs_set), 1)
    block = patched_func._get_block(auth_func_addr)
    nose.tools.assert_equal(len(block.instruction_addrs), 1)

    # let's try to patch the second instruction of that function to ret
    kb = angr.KnowledgeBase(proj)
    kb.patches.add_patch(auth_func._get_block(auth_func_addr).instruction_addrs[1], b"\xc3")

    # with this patch, there should only be one block with two instructions in authenticate()
    _ = proj.analyses.CFGFast(kb=kb, use_patches=True)
    patched_func = kb.functions['authenticate']
    nose.tools.assert_equal(len(patched_func.block_addrs_set), 1)
    block = patched_func._get_block(auth_func_addr)
    nose.tools.assert_equal(len(block.instruction_addrs), 2)

    # finally, if we generate a new CFG on a KB without any patch, we should still see the normal function (with 10
    # blocks)
    kb = angr.KnowledgeBase(proj)
    _ = proj.analyses.CFGFast(kb=kb, use_patches=True)
    not_patched_func = kb.functions['authenticate']
    nose.tools.assert_equal(len(not_patched_func.block_addrs_set), 10)


def test_unresolvable_targets():

    path = os.path.join(test_location, 'cgc', 'CADET_00002')
    proj = angr.Project(path)

    proj.analyses.CFGFast(normalize=True)
    func = proj.kb.functions[0x080489E0]

    true_endpoint_addrs = {0x8048bbc, 0x8048af5, 0x8048b5c, 0x8048a41, 0x8048aa8}
    endpoint_addrs = {node.addr for node in func.endpoints}
    nose.tools.assert_equal(len(endpoint_addrs.symmetric_difference(true_endpoint_addrs)), 0)


def test_indirect_jump_to_outside():

    # an indirect jump might be jumping to outside as well
    path = os.path.join(test_location, "mipsel", "libndpi.so.4.0.0")
    proj = angr.Project(path, auto_load_libs=False)

    cfg = proj.analyses.CFGFast()

    nose.tools.assert_equal(len(list(cfg.functions[0x404ee4].blocks)), 3)
    nose.tools.assert_equal(set(ep.addr for ep in cfg.functions[0x404ee4].endpoints), { 0x404f00, 0x404f08 })


def run_all():

    g = globals()
    segmentlist_tests = [ v for k, v in g.items() if k.startswith("test_segment_list_") and hasattr(v, "__call__")]

    for func in segmentlist_tests:
        print(func.__name__)
        func()

    test_serialization_cfgnode()
    test_serialization_cfgfast()

    for args in test_cfg_0():
        print(args[0].__name__)
        args[0](*args[1:])

    for args in test_cfg_0_pe():
        print(args[0].__name__)
        args[0](*args[1:])

    for args in test_fauxware():
        print(args[0].__name__)
        args[0](*args[1:])

    for args in test_cfg_loop_unrolling():
        print(args[0].__name__)
        args[0](*args[1:])

    for args in test_cfg_switches():
        args[0](*args[1:])

    test_resolve_x86_elf_pic_plt()
    test_function_names_for_unloaded_libraries()
    test_block_instruction_addresses_armhf()
    test_tail_call_optimization_detection_armel()
    test_blanket_fauxware()
    test_data_references()
    test_function_leading_blocks_merging()
    test_cfg_with_patches()
    test_indirect_jump_to_outside()


def main():
    if len(sys.argv) > 1:
        g = globals().copy()

        r = g['test_' + sys.argv[1]]()

        if r is not None:
            for func_and_args in r:
                func, args = func_and_args[0], func_and_args[1:]
                func(*args)
    else:
        run_all()

if __name__ == "__main__":
    # logging.getLogger('angr.analyses.cfg.cfg_fast').setLevel(logging.DEBUG)
    main()

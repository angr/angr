# pylint:disable=missing-class-docstring,no-self-use,wrong-import-order
import os
import logging
import unittest

import archinfo
import angr
from angr.analyses.cfg.cfg_fast import SegmentList
from angr.knowledge_plugins.cfg import CFGNode, CFGModel, MemoryDataSort

from common import slow_test

l = logging.getLogger("angr.tests.test_cfgfast")

test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries", "tests")


class TestCfgfast(unittest.TestCase):
    def cfg_fast_functions_check(self, arch, binary_path, func_addrs, func_features):
        """
        Generate a fast CFG on the given binary, and test if all specified functions are found

        :param str arch: the architecture, will be prepended to `binary_path`
        :param str binary_path: path to the binary under the architecture directory
        :param dict func_addrs: A collection of function addresses that should be recovered
        :param dict func_features: A collection of features for some of the functions
        :return: None
        """

        path = os.path.join(test_location, arch, binary_path)
        proj = angr.Project(path, load_options={"auto_load_libs": False})

        cfg = proj.analyses.CFGFast()
        assert set(cfg.kb.functions.keys()).issuperset(func_addrs)

        for func_addr, feature_dict in func_features.items():
            returning = feature_dict.get("returning", "undefined")
            if returning != "undefined":
                assert cfg.kb.functions.function(addr=func_addr).returning is returning

        # Segment only
        cfg = proj.analyses.CFGFast(force_segment=True)
        assert set(cfg.kb.functions.keys()).issuperset(func_addrs)

        for func_addr, feature_dict in func_features.items():
            returning = feature_dict.get("returning", "undefined")
            if returning != "undefined":
                assert cfg.kb.functions.function(addr=func_addr).returning is returning

        # with normalization enabled
        cfg = proj.analyses.CFGFast(force_segment=True, normalize=True)
        assert set(cfg.kb.functions.keys()).issuperset(func_addrs)

        for func_addr, feature_dict in func_features.items():
            returning = feature_dict.get("returning", "undefined")
            if returning != "undefined":
                assert cfg.kb.functions.function(addr=func_addr).returning is returning

    def cfg_fast_edges_check(self, arch, binary_path, edges):
        """
        Generate a fast CFG on the given binary, and test if all edges are found.

        :param str arch: the architecture, will be prepended to `binary_path`
        :param str binary_path: path to the binary under the architecture directory
        :param list edges: a list of edges
        :return: None
        """

        path = os.path.join(test_location, arch, binary_path)
        proj = angr.Project(path, load_options={"auto_load_libs": False})

        cfg = proj.analyses.CFGFast()

        for src, dst in edges:
            src_node = cfg.model.get_any_node(src)
            dst_node = cfg.model.get_any_node(dst)
            assert src_node is not None, "CFG node 0x%x is not found." % src
            assert dst_node is not None, "CFG node 0x%x is not found." % dst
            assert dst_node in src_node.successors, "CFG edge {}-{} is not found.".format(
                src_node,
                dst_node,
            )

    def test_cfg_0(self):
        functions = {
            0x400410,
            0x400420,
            0x400430,
            0x400440,
            0x400470,
            0x40052C,
            0x40053C,
        }

        function_features = {}

        self.cfg_fast_functions_check("x86_64", "cfg_0", functions, function_features)

    def test_cfg_0_pe(self):
        functions = {
            # 0x40150a,  # currently angr identifies 0x40150e due to the way _func_addrs_from_prologues() is
            # implemented. this issue can be resolved with a properly implemented approach like Byte-Weight
            0x4014F0,
        }

        function_features = {}

        self.cfg_fast_functions_check("x86_64", "cfg_0_pe", functions, function_features)

    @slow_test
    def test_busybox(self):
        edges = {
            (0x4091EC, 0x408DE0),
            # call to putenv. address of putenv may change in the future
            (
                0x449ACC,
                0x5003B8,
            ),
            # call to free. address of free may change in the future
            (
                0x467CFC,
                0x500014,
            ),
        }

        self.cfg_fast_edges_check("mipsel", "busybox", edges)

    @slow_test
    @unittest.skipUnless(
        os.path.isfile("C:\\Windows\\System32\\ntoskrnl.exe"),
        "ntoskrnl.exe does not exist on this system.",
    )
    def test_ntoskrnl(self):
        # we cannot distribute ntoskrnl.exe. as a result, this test case is manual
        path = "C:\\Windows\\System32\\ntoskrnl.exe"
        proj = angr.Project(path, auto_load_libs=False)
        _ = proj.analyses.CFG(data_references=True, normalize=True, show_progressbar=True)

        # nothing should prevent us from finish creating the CFG

    def test_fauxware_function_feauters_x86_64(self):
        functions = {
            0x4004E0,
            0x400510,
            0x400520,
            0x400530,
            0x400540,
            0x400550,
            0x400560,
            0x400570,  # .plt._exit
            0x400580,  # _start
            0x4005AC,
            0x4005D0,
            0x400640,
            0x400664,
            0x4006ED,
            0x4006FD,
            0x40071D,  # main
            0x4007E0,
            0x400870,
            0x400880,
            0x4008B8,
        }

        function_features = {
            0x400570: {"returning": False},  # plt.exit
            0x4006FD: {"returning": False},  # rejected
        }

        return_edges = {
            (0x4006FB, 0x4007C7),
        }  # return from accepted to main

        self.cfg_fast_functions_check("x86_64", "fauxware", functions, function_features)
        self.cfg_fast_edges_check("x86_64", "fauxware", return_edges)

    def test_fauxware_function_features_mips(self):
        functions = {
            0x400534,  # _init
            0x400574,
            0x400598,
            0x4005D0,  # _ftext
            0x4005DC,
            0x400630,  # __do_global_dtors_aux
            0x4006D4,  # frame_dummy
            0x400708,
            0x400710,  # authenticate
            0x400814,  # accepted
            0x400868,  # rejected
            0x4008C0,  # main
            0x400A34,
            0x400A48,  # __libc_csu_init
            0x400AF8,
            0x400B00,  # __do_global_ctors_aux
            0x400B58,
            ### plt entries
            0x400B60,  # strcmp
            0x400B70,  # read
            0x400B80,  # printf
            0x400B90,  # puts
            0x400BA0,  # exit
            0x400BB0,  # open
            0x400BC0,  # __libc_start_main
        }

        function_features = {
            0x400868: {  # rejected
                "returning": False,
            }
        }

        return_edges = {
            (0x40084C, 0x400A04),
        }  # returning edge from accepted to main

        self.cfg_fast_functions_check("mips", "fauxware", functions, function_features)
        self.cfg_fast_edges_check("mips", "fauxware", return_edges)

    def test_cfg_loop_unrolling(self):
        edges = {
            (0x400658, 0x400636),
            (0x400658, 0x400661),
            (0x400651, 0x400636),
            (0x400651, 0x400661),
        }

        self.cfg_fast_edges_check("x86_64", "cfg_loop_unrolling", edges)

    def test_cfg_switches_x86_64(self):
        edges = {
            # jump table 0 in func_0
            (0x40053A, 0x400547),
            (0x40053A, 0x400552),
            (0x40053A, 0x40055D),
            (0x40053A, 0x400568),
            (0x40053A, 0x400573),
            (0x40053A, 0x400580),
            (0x40053A, 0x40058D),
            # jump table 0 in func_1
            (0x4005BC, 0x4005C9),
            (0x4005BC, 0x4005D8),
            (0x4005BC, 0x4005E7),
            (0x4005BC, 0x4005F6),
            (0x4005BC, 0x400605),
            (0x4005BC, 0x400614),
            (0x4005BC, 0x400623),
            (0x4005BC, 0x400632),
            (0x4005BC, 0x40063E),
            (0x4005BC, 0x40064A),
            (0x4005BC, 0x4006B0),
            # jump table 1 in func_1
            (0x40065A, 0x400667),
            (0x40065A, 0x400673),
            (0x40065A, 0x40067F),
            (0x40065A, 0x40068B),
            (0x40065A, 0x400697),
            (0x40065A, 0x4006A3),
            # jump table 0 in main
            (0x4006E1, 0x4006EE),
            (0x4006E1, 0x4006FA),
            (0x4006E1, 0x40070B),
            (0x4006E1, 0x40071C),
            (0x4006E1, 0x40072D),
            (0x4006E1, 0x40073E),
            (0x4006E1, 0x40074F),
            (0x4006E1, 0x40075B),
        }

        self.cfg_fast_edges_check("x86_64", "cfg_switches", edges)

    def test_cfg_switches_armel(self):
        edges = {
            # jump table 0 in func_0
            (0x10434, 0x10488),
            (0x10434, 0x104E8),
            (0x10434, 0x10498),
            (0x10434, 0x104A8),
            (0x10434, 0x104B8),
            (0x10434, 0x104C8),
            (0x10434, 0x104D8),
            (0x10454, 0x104E8),  # default case
            # jump table 0 in func_1
            (0x10524, 0x105CC),
            (0x10524, 0x106B4),
            (0x10524, 0x105D8),
            (0x10524, 0x105E4),
            (0x10524, 0x105F0),
            (0x10524, 0x105FC),
            (0x10524, 0x10608),
            (0x10524, 0x10614),
            (0x10524, 0x10620),
            (0x10524, 0x1062C),
            (0x10524, 0x10638),
            (0x10534, 0x106B4),  # default case
            # jump table 1 in func_1
            (0x10650, 0x106A4),  # default case
            (0x10640, 0x10668),
            (0x10640, 0x10674),
            (0x10640, 0x10680),
            (0x10640, 0x1068C),
            (0x10640, 0x10698),
            # jump table 0 in main
            (0x10734, 0x107FC),
            (0x10734, 0x10808),
            (0x10734, 0x10818),
            (0x10734, 0x10828),
            (0x10734, 0x10838),
            (0x10734, 0x10848),
            (0x10734, 0x10858),
            (0x10734, 0x10864),
            (0x10744, 0x10864),  # default case
        }

        self.cfg_fast_edges_check("armel", "cfg_switches", edges)

    def test_cfg_switches_s390x(self):
        edges = {
            # jump table 0 in func_0
            (0x4007D4, 0x4007EA),  # case 1
            (0x4007D4, 0x4007F4),  # case 3
            (0x4007D4, 0x4007FE),  # case 5
            (0x4007D4, 0x400808),  # case 7
            (0x4007D4, 0x400812),  # case 9
            (0x4007D4, 0x40081C),  # case 12
            (0x4007C0, 0x4007CA),  # default case
            # jump table 0 in func_1
            (0x400872, 0x4008AE),  # case 2
            (0x400872, 0x4008BE),  # case 10
            (0x400872, 0x4008CE),  # case 12
            (0x400872, 0x4008DE),  # case 14
            (0x400872, 0x4008EE),  # case 15
            (0x400872, 0x4008FE),  # case 16
            (0x400872, 0x40090E),  # case 22
            (0x400872, 0x40091E),  # case 24
            (0x400872, 0x40092E),  # case 28
            (0x400872, 0x400888),  # case 38
            (0x400848, 0x400854),  # default case (1)
            (0x400872, 0x400854),  # default case (2)
            # jump table 1 in func_1
            (0x40093E, 0x400984),  # case 1
            (0x40093E, 0x400974),  # case 2
            (0x40093E, 0x400964),  # case 3
            (0x40093E, 0x400954),  # case 4
            (0x40093E, 0x400994),  # case 5
            (0x400898, 0x40089E),  # default case (1)
            # jump table 0 in main
            # case 1, 3, 5, 7, 9: optimized out
            (0x400638, 0x40064E),  # case 2
            (0x400638, 0x400692),  # case 4
            (0x400638, 0x4006A4),  # case 6
            (0x400638, 0x40066E),  # case 8
            (0x400638, 0x400680),  # case 10
            # case 45: optimized out
            (0x40062C, 0x40065C),  # default case
        }

        self.cfg_fast_edges_check("s390x", "cfg_switches", edges)

    def test_cfg_about_time(self):
        # This is to test the correctness of the PLT stub removal in CFGBase
        proj = angr.Project(os.path.join(test_location, "x86_64", "about_time"), auto_load_libs=False)
        cfg = proj.analyses.CFG()

        # a PLT stub that should be removed
        assert 0x401026 not in cfg.kb.functions
        # a PLT stub that should be removed
        assert 0x4010A6 not in cfg.kb.functions
        # a PLT stub that should be removed
        assert 0x40115E not in cfg.kb.functions
        # the start function that should not be removed
        assert proj.entry in cfg.kb.functions

    def test_segment_list_0(self):
        seg_list = SegmentList()
        seg_list.occupy(0, 1, "code")
        seg_list.occupy(2, 3, "code")

        assert len(seg_list) == 2
        assert seg_list._list[0].end == 1
        assert seg_list._list[1].end == 5
        assert seg_list.is_occupied(4)
        assert seg_list.is_occupied(5) is False

    def test_segment_list_1(self):
        seg_list = SegmentList()

        # They should be merged
        seg_list.occupy(0, 1, "code")
        seg_list.occupy(1, 2, "code")

        assert len(seg_list) == 1
        assert seg_list._list[0].start == 0
        assert seg_list._list[0].end == 3

    def test_segment_list_2(self):
        seg_list = SegmentList()

        # They should not be merged
        seg_list.occupy(0, 1, "code")
        seg_list.occupy(1, 2, "data")

        assert len(seg_list) == 2
        assert seg_list._list[0].start == 0
        assert seg_list._list[0].end == 1
        assert seg_list._list[1].start == 1
        assert seg_list._list[1].end == 3

    def test_segment_list_3(self):
        seg_list = SegmentList()

        # They should be merged, and create three different segments
        seg_list.occupy(0, 5, "code")
        seg_list.occupy(5, 5, "code")
        seg_list.occupy(1, 2, "data")

        assert len(seg_list) == 3

        assert seg_list._list[0].start == 0
        assert seg_list._list[0].end == 1
        assert seg_list._list[0].sort == "code"

        assert seg_list._list[1].start == 1
        assert seg_list._list[1].end == 3
        assert seg_list._list[1].sort == "data"

        assert seg_list._list[2].start == 3
        assert seg_list._list[2].end == 10
        assert seg_list._list[2].sort == "code"

    def test_segment_list_4(self):
        seg_list = SegmentList()

        seg_list.occupy(5, 5, "code")
        seg_list.occupy(4, 1, "code")
        seg_list.occupy(2, 2, "code")

        assert len(seg_list) == 1
        assert seg_list._list[0].start == 2
        assert seg_list._list[0].end == 10

    def test_segment_list_5(self):
        seg_list = SegmentList()

        seg_list.occupy(5, 5, "data")
        seg_list.occupy(4, 1, "code")
        seg_list.occupy(2, 2, "data")

        assert len(seg_list) == 3
        assert seg_list._list[0].start == 2
        assert seg_list._list[2].end == 10

        seg_list.occupy(3, 2, "data")

        assert len(seg_list) == 1
        assert seg_list._list[0].start == 2
        assert seg_list._list[0].end == 10

    def test_segment_list_6(self):
        seg_list = SegmentList()

        seg_list.occupy(10, 20, "code")
        seg_list.occupy(9, 2, "data")

        assert len(seg_list) == 2
        assert seg_list._list[0].start == 9
        assert seg_list._list[0].end == 11
        assert seg_list._list[0].sort == "data"

        assert seg_list._list[1].start == 11
        assert seg_list._list[1].end == 30
        assert seg_list._list[1].sort == "code"

    #
    # Serialization
    #

    def test_serialization_cfgnode(self):
        path = os.path.join(test_location, "x86_64", "fauxware")
        proj = angr.Project(path, auto_load_libs=False)

        cfg = proj.analyses.CFGFast()
        # the first node
        node = cfg.model.get_any_node(proj.entry)
        assert node is not None

        b = node.serialize()
        assert len(b) > 0
        new_node = CFGNode.parse(b)
        assert new_node.addr == node.addr
        assert new_node.size == node.size
        assert new_node.block_id == node.block_id

    def test_serialization_cfgfast(self):
        path = os.path.join(test_location, "x86_64", "fauxware")
        proj1 = angr.Project(path, auto_load_libs=False)
        proj2 = angr.Project(path, auto_load_libs=False)

        cfg = proj1.analyses.CFGFast()
        # parse the entire graph
        b = cfg.model.serialize()
        assert len(b) > 0

        # simulate importing a cfg from another tool
        cfg_model = CFGModel.parse(b, cfg_manager=proj2.kb.cfgs)

        assert len(cfg_model.graph.nodes) == len(cfg.graph.nodes)
        assert len(cfg_model.graph.edges) == len(cfg.graph.edges)

        n1 = cfg.model.get_any_node(proj1.entry)
        n2 = cfg_model.get_any_node(proj1.entry)
        assert n1 == n2

    #
    # CFG instance copy
    #

    def test_cfg_copy(self):
        path = os.path.join(test_location, "cgc", "CADET_00002")
        proj = angr.Project(path, auto_load_libs=False)

        cfg = proj.analyses.CFGFast()
        cfg_copy = cfg.copy()
        for attribute in cfg_copy.__dict__:
            if attribute in ["_graph", "_seg_list", "_model"]:
                continue
            assert getattr(cfg, attribute) == getattr(cfg_copy, attribute)

        assert id(cfg.model) != id(cfg_copy.model)
        assert id(cfg.model.graph) != id(cfg_copy.model.graph)
        assert id(cfg._seg_list) != id(cfg_copy._seg_list)

    #
    # Alignment bytes
    #

    def test_cfg_0_pe_msvc_debug_nocc(self):
        filename = os.path.join("windows", "msvc_cfg_0_debug.exe")
        proj = angr.Project(os.path.join(test_location, "x86_64", filename), auto_load_libs=False)
        cfg = proj.analyses.CFGFast()

        # make sure 0x140015683 is marked as alignments
        sort = cfg._seg_list.occupied_by_sort(0x140016583)
        assert sort == "alignment"

        assert 0x140015683 not in cfg.kb.functions

    #
    # Indirect jump resolvers
    #

    # For test cases for jump table resolver, please refer to test_jumptables.py

    def test_resolve_x86_elf_pic_plt(self):
        path = os.path.join(test_location, "i386", "fauxware_pie")
        proj = angr.Project(path, load_options={"auto_load_libs": False})

        cfg = proj.analyses.CFGFast()

        # puts
        puts_node = cfg.model.get_any_node(0x4005B0)
        assert puts_node is not None

        # there should be only one successor, which jumps to SimProcedure puts
        assert len(puts_node.successors) == 1
        puts_successor = puts_node.successors[0]
        assert puts_successor.addr == proj.loader.find_symbol("puts").rebased_addr

        # the SimProcedure puts should have more than one successors, which are all return targets
        assert len(puts_successor.successors) == 3
        simputs_successor = puts_successor.successors
        return_targets = {a.addr for a in simputs_successor}
        assert return_targets == {0x400800, 0x40087E, 0x4008B6}

    #
    # Function names
    #

    def test_function_names_for_unloaded_libraries(self):
        path = os.path.join(test_location, "i386", "fauxware_pie")
        proj = angr.Project(path, load_options={"auto_load_libs": False})

        cfg = proj.analyses.CFGFast()

        function_names = [f.name if not f.is_plt else "plt_" + f.name for f in cfg.functions.values()]

        assert "plt_puts" in function_names
        assert "plt_read" in function_names
        assert "plt___stack_chk_fail" in function_names
        assert "plt_exit" in function_names
        assert "puts" in function_names
        assert "read" in function_names
        assert "__stack_chk_fail" in function_names
        assert "exit" in function_names

    #
    # Basic blocks
    #

    def test_block_instruction_addresses_armhf(self):
        path = os.path.join(test_location, "armhf", "fauxware")
        proj = angr.Project(path, auto_load_libs=False)

        cfg = proj.analyses.CFGFast()

        main_func = cfg.kb.functions["main"]

        # all instruction addresses of the block must be odd
        block = next(b for b in main_func.blocks if b.addr == main_func.addr)

        assert len(block.instruction_addrs) == 12
        for instr_addr in block.instruction_addrs:
            assert instr_addr % 2 == 1

        main_node = cfg.model.get_any_node(main_func.addr)
        assert main_node is not None
        assert len(main_node.instruction_addrs) == 12
        for instr_addr in main_node.instruction_addrs:
            assert instr_addr % 2 == 1

    #
    # Tail-call optimization detection
    #

    def test_tail_call_optimization_detection_armel(self):
        # GitHub issue #1286

        path = os.path.join(test_location, "armel", "Nucleo_read_hyperterminal-stripped.elf")
        proj = angr.Project(path, auto_load_libs=False)

        cfg = proj.analyses.CFGFast(
            resolve_indirect_jumps=True,
            force_complete_scan=False,
            normalize=True,
            symbols=False,
            detect_tail_calls=True,
            data_references=True,
        )

        all_func_addrs = set(cfg.functions.keys())
        assert 0x80010B5 not in all_func_addrs
        assert 0x8003EF9 not in all_func_addrs
        assert 0x8008419 not in all_func_addrs

        # Functions that are jumped to from tail-calls
        tail_call_funcs = [
            0x8002BC1,
            0x80046C1,
            0x8000281,
            0x8001BDB,
            0x8002839,
            0x80037AD,
            0x8002C09,
            0x8004165,
            0x8004BE1,
            0x8002EB1,
        ]
        for member in tail_call_funcs:
            assert member in all_func_addrs

        # also test for tailcall return addresses

        # mapping of return blocks to return addrs that are the actual callers of certain tail-calls endpoints
        tail_call_return_addrs = {
            0x8002BD9: [0x800275F],  # 0x8002bc1
            0x80046D7: [0x800275F],  # 0x80046c1
            0x80046ED: [0x800275F],  # 0x80046c1
            0x8001BE7: [0x800068D, 0x8000695],  # 0x8001bdb ??
            0x800284D: [0x800028B, 0x80006E1, 0x80006E7],  # 0x8002839
            0x80037F5: [0x800270B, 0x8002733, 0x8002759, 0x800098F, 0x8000997],  # 0x80037ad
            0x80037EF: [0x800270B, 0x8002733, 0x8002759, 0x800098F, 0x8000997],  # 0x80037ad
            0x8002CC9: [
                0x8002D3B,
                0x8002B99,
                0x8002E9F,
                0x80041AD,
                0x8004C87,
                0x8004D35,
                0x8002EFB,
                0x8002BE9,
                0x80046EB,
                0x800464F,
                0x8002A09,
                0x800325F,
                0x80047C1,
            ],  # 0x8002c09
            0x8004183: [0x8002713],  # 0x8004165
            0x8004C31: [0x8002713],  # 0x8004be1
            0x8004C69: [0x8002713],  # 0x8004be1
            0x8002EF1: [0x800273B],
        }  # 0x8002eb1

        # check all expected return addrs are present
        for returning_block_addr, expected_return_addrs in tail_call_return_addrs.items():
            returning_block = cfg.model.get_any_node(returning_block_addr)
            return_block_addrs = [rb.addr for rb in cfg.model.get_successors(returning_block)]
            msg = "%x: unequal sizes of expected_addrs [%d] and return_block_addrs [%d]" % (
                returning_block_addr,
                len(expected_return_addrs),
                len(return_block_addrs),
            )
            assert len(return_block_addrs) == len(expected_return_addrs), msg
            for expected_addr in expected_return_addrs:
                msg = "expected retaddr {:x} not found for returning_block {:x}".format(
                    expected_addr,
                    returning_block_addr,
                )
                assert expected_addr in return_block_addrs, msg

    #
    # Incorrect function-leading blocks merging
    #

    def test_function_leading_blocks_merging(self):
        # GitHub issue #1312

        path = os.path.join(test_location, "armel", "Nucleo_read_hyperterminal-stripped.elf")
        proj = angr.Project(path, arch=archinfo.ArchARMCortexM(), auto_load_libs=False)

        cfg = proj.analyses.CFGFast(
            resolve_indirect_jumps=True,
            force_complete_scan=True,
            normalize=True,
            symbols=False,
            detect_tail_calls=True,
        )

        assert 0x8000799 in cfg.kb.functions
        assert 0x800079B not in cfg.kb.functions
        assert 0x800079B not in cfg.kb.functions[0x8000799].block_addrs_set
        assert 0x8000799 in cfg.kb.functions[0x8000799].block_addrs_set
        assert next(iter(b for b in cfg.kb.functions[0x8000799].blocks if b.addr == 0x8000799)).size == 6

    #
    # Blanket
    #

    def test_blanket_fauxware(self):
        path = os.path.join(test_location, "x86_64", "fauxware")
        proj = angr.Project(path, auto_load_libs=False)

        cfg = proj.analyses.CFGFast()

        cfb = proj.analyses.CFBlanket(kb=cfg.kb)

        # it should raise a key error when calling floor_addr on address 0 because nothing is mapped there
        # an instruction (or a block) starts at 0x400580
        assert cfb.floor_addr(0x400581) == 0x400580
        # a block ends at 0x4005a9 (exclusive)
        assert cfb.ceiling_addr(0x400581) == 0x4005A9

    #
    # CFG with patches
    #

    def test_cfg_with_patches(self):
        path = os.path.join(test_location, "x86_64", "fauxware")
        proj = angr.Project(path, auto_load_libs=False)

        cfg = proj.analyses.CFGFast()
        auth_func = cfg.functions["authenticate"]
        auth_func_addr = auth_func.addr

        # Take the authenticate function and add a retn patch for its very first block
        kb = angr.KnowledgeBase(proj)
        kb.patches.add_patch(auth_func_addr, b"\xc3")

        # with this patch, there should only be one block with one instruction in authenticate()
        _ = proj.analyses.CFGFast(kb=kb, use_patches=True)
        patched_func = kb.functions["authenticate"]
        assert len(patched_func.block_addrs_set) == 1
        block = patched_func._get_block(auth_func_addr)
        assert len(block.instruction_addrs) == 1

        # let's try to patch the second instruction of that function to ret
        kb = angr.KnowledgeBase(proj)
        kb.patches.add_patch(auth_func._get_block(auth_func_addr).instruction_addrs[1], b"\xc3")

        # with this patch, there should only be one block with two instructions in authenticate()
        _ = proj.analyses.CFGFast(kb=kb, use_patches=True)
        patched_func = kb.functions["authenticate"]
        assert len(patched_func.block_addrs_set) == 1
        block = patched_func._get_block(auth_func_addr)
        assert len(block.instruction_addrs) == 2

        # finally, if we generate a new CFG on a KB without any patch, we should still see the normal function (with 10
        # blocks)
        kb = angr.KnowledgeBase(proj)
        _ = proj.analyses.CFGFast(kb=kb, use_patches=True)
        not_patched_func = kb.functions["authenticate"]
        assert len(not_patched_func.block_addrs_set) == 10

    def test_unresolvable_targets(self):
        path = os.path.join(test_location, "cgc", "CADET_00002")
        proj = angr.Project(path, auto_load_libs=False)

        proj.analyses.CFGFast(normalize=True)
        func = proj.kb.functions[0x080489E0]

        true_endpoint_addrs = {0x8048BBC, 0x8048AF5, 0x8048B5C, 0x8048A41, 0x8048AA8}
        endpoint_addrs = {node.addr for node in func.endpoints}
        assert len(endpoint_addrs.symmetric_difference(true_endpoint_addrs)) == 0

    def test_indirect_jump_to_outside(self):
        # an indirect jump might be jumping to outside as well
        path = os.path.join(test_location, "mipsel", "libndpi.so.4.0.0")
        proj = angr.Project(path, auto_load_libs=False)

        cfg = proj.analyses.CFGFast()

        assert len(list(cfg.functions[0x404EE4].blocks)) == 3
        assert {ep.addr for ep in cfg.functions[0x404EE4].endpoints} == {
            0x404F00,
            0x404F08,
        }

    def test_plt_stub_has_one_jumpout_site(self):
        # each PLT stub must have exactly one jumpout site
        path = os.path.join(test_location, "x86_64", "1after909")
        proj = angr.Project(path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast()

        for func in cfg.kb.functions.values():
            if func.is_plt:
                assert len(func.jumpout_sites) == 1

    def test_generate_special_info(self):
        path = os.path.join(test_location, "mipsel", "fauxware")
        proj = angr.Project(path, auto_load_libs=False)

        cfg = proj.analyses.CFGFast()

        assert any(func.info for func in cfg.functions.values())
        assert cfg.functions["main"].info["gp"] == 0x418CA0

    def test_load_from_shellcode(self):
        proj = angr.load_shellcode("loop: dec ecx; jnz loop; ret", "x86")
        cfg = proj.analyses.CFGFast()

        assert len(cfg.model.nodes()) == 2

    def test_starting_point_ordering(self):
        # project entry should always be first
        # so edge/path to unlabeled main function from _start
        # is correctly generated

        path = os.path.join(test_location, "armel", "start_ordering")
        proj = angr.Project(path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast()

        # if ordering is incorrect, edge to function 0x103D4 will not exist
        n = cfg.model.get_any_node(proj.entry)
        assert n is not None
        assert len(n.successors) > 0
        assert len(n.successors[0].successors) > 0
        assert len(n.successors[0].successors[0].successors) == 3

        # now checking if path to the "real main" exists
        assert len(n.successors[0].successors[0].successors[1].successors) > 0
        n = n.successors[0].successors[0].successors[1].successors[0]

        assert len(n.successors) > 0
        assert len(n.successors[0].successors) > 0
        assert len(n.successors[0].successors[0].successors) > 0
        assert n.successors[0].successors[0].successors[0].addr == 0x103D4

    def test_error_returning(self):
        # error() is a great function: its returning depends on the value of the first argument...
        path = os.path.join(test_location, "x86_64", "mv_-O2")
        proj = angr.Project(path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast()

        error_not_returning = [
            0x4030D4,
            0x403100,
            0x40313C,
            0x4031F5,
            0x40348A,
        ]

        error_returning = [0x403179, 0x4031A2, 0x403981, 0x403E30, 0x40403B]

        for error_site in error_not_returning:
            node = cfg.model.get_any_node(error_site)
            assert len(list(cfg.model.get_successors(node, excluding_fakeret=False))) == 1  # only the call successor

        for error_site in error_returning:
            node = cfg.model.get_any_node(error_site)
            assert len(list(cfg.model.get_successors(node, excluding_fakeret=False))) == 2  # both a call and a fakeret

    def test_kepler_server_armhf(self):
        binary_path = os.path.join(test_location, "armhf", "kepler_server")
        proj = angr.Project(binary_path, auto_load_libs=False)
        cfg = proj.analyses.CFG(normalize=True)

        func_main = cfg.kb.functions[0x10329]
        assert func_main.returning is False

        func_0 = cfg.kb.functions[0x15EE9]
        assert func_0.returning is False
        assert len(func_0.block_addrs_set) == 1

        func_1 = cfg.kb.functions[0x15D2D]
        assert func_1.returning is False

        func_2 = cfg.kb.functions[0x228C5]
        assert func_2.returning is False

        func_3 = cfg.kb.functions[0x12631]
        assert func_3.returning is True

    def test_func_in_added_segment_by_patcherex_arm(self):
        path = os.path.join(test_location, "armel", "patcherex", "replace_function_patch_with_function_reference")
        proj = angr.Project(path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast(
            normalize=True,
            function_starts={0xA00081},
            regions=[
                (4195232, 4195244),
                (4195244, 4195324),
                (4195324, 4196016),
                (4196016, 4196024),
                (10485888, 10485950),
            ],
        )

        # Check whether the target function is in the functions list
        assert 0xA00081 in cfg.kb.functions
        # Check the number of basic blocks
        assert len(list(cfg.functions[0xA00081].blocks)) == 8

    def test_func_in_added_segment_by_patcherex_x64(self):
        path = os.path.join(test_location, "x86_64", "patchrex", "replace_function_patch_with_function_reference")
        proj = angr.Project(path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast(
            normalize=True,
            function_starts={0xA0013D},
            regions=[
                (4195568, 4195591),
                (4195600, 4195632),
                (4195632, 4195640),
                (4195648, 4196418),
                (4196420, 4196429),
                (10486064, 10486213),
            ],
        )

        # Check whether the target function is in the functions list
        assert 0xA0013D in cfg.kb.functions
        # Check the number of basic blocks
        assert len(list(cfg.functions[0xA0013D].blocks)) == 7


class TestCfgfastDataReferences(unittest.TestCase):
    def test_data_references_x86_64(self):
        path = os.path.join(test_location, "x86_64", "fauxware")
        proj = angr.Project(path, auto_load_libs=False)

        cfg = proj.analyses.CFGFast(data_references=True)

        memory_data = cfg.memory_data
        # There is no code reference
        code_ref_count = len([d for d in memory_data.values() if d.sort == MemoryDataSort.CodeReference])
        assert code_ref_count >= 0, "There should be no code reference."

        # There are at least 2 pointer arrays
        ptr_array_count = len([d for d in memory_data.values() if d.sort == MemoryDataSort.PointerArray])
        assert ptr_array_count > 2, "Missing some pointer arrays."

        assert 0x4008D0 in memory_data
        sneaky_str = memory_data[0x4008D0]
        assert sneaky_str.sort == "string"
        assert sneaky_str.content == b"SOSNEAKY"

    def test_data_references_mipsel(self):
        path = os.path.join(test_location, "mipsel", "fauxware")
        proj = angr.Project(path, auto_load_libs=False)

        cfg = proj.analyses.CFGFast(data_references=True)

        memory_data = cfg.memory_data
        # There is no code reference
        code_ref_count = len([d for d in memory_data.values() if d.sort == MemoryDataSort.CodeReference])
        assert code_ref_count >= 0, "There should be no code reference."

        # There are at least 2 pointer arrays
        ptr_array_count = len([d for d in memory_data.values() if d.sort == MemoryDataSort.PointerArray])
        assert ptr_array_count >= 1, "Missing some pointer arrays."

        assert 0x400C00 in memory_data
        sneaky_str = memory_data[0x400C00]
        assert sneaky_str.sort == "string"
        assert sneaky_str.content == b"SOSNEAKY"

        assert 0x400C0C in memory_data
        str_ = memory_data[0x400C0C]
        assert str_.sort == "string"
        assert str_.content == b"Welcome to the admin console, trusted user!"

        assert 0x400C38 in memory_data
        str_ = memory_data[0x400C38]
        assert str_.sort == "string"
        assert str_.content == b"Go away!"

        assert 0x400C44 in memory_data
        str_ = memory_data[0x400C44]
        assert str_.sort == "string"
        assert str_.content == b"Username: "

        assert 0x400C50 in memory_data
        str_ = memory_data[0x400C50]
        assert str_.sort == "string"
        assert str_.content == b"Password: "

    def test_data_references_mips64(self):
        path = os.path.join(test_location, "mips64", "true")
        proj = angr.Project(path, auto_load_libs=False)

        cfg = proj.analyses.CFGFast(data_references=True, cross_references=True)
        memory_data = cfg.memory_data

        assert 0x120007DD8 in memory_data
        assert memory_data[0x120007DD8].sort == "string"
        assert memory_data[0x120007DD8].content == b"coreutils"

        xrefs = proj.kb.xrefs
        refs = list(xrefs.get_xrefs_by_dst(0x120007DD8))
        assert len(refs) == 2
        assert {x.ins_addr for x in refs} == {0x1200020E8, 0x120002108}

    def test_data_references_i386_gcc_pie(self):
        path = os.path.join(test_location, "i386", "nl")
        proj = angr.Project(path, auto_load_libs=False)

        cfg = proj.analyses.CFGFast(data_references=True, cross_references=True)
        memory_data = cfg.memory_data

        assert 0x405BB0 in memory_data
        assert memory_data[0x405BB0].sort == "string"
        assert memory_data[0x405BB0].content == b"/usr/local/share/locale"

        xrefs = proj.kb.xrefs
        refs = list(xrefs.get_xrefs_by_dst(0x405BB0))
        assert len(refs) == 1
        assert {x.ins_addr for x in refs} == {0x4011DD}

    def test_data_references_wide_string(self):
        path = os.path.join(test_location, "x86_64", "windows", "fauxware-wide.exe")
        proj = angr.Project(path, auto_load_libs=False)

        cfg = proj.analyses.CFGFast(data_references=True)
        recovered_strings = [d.content for d in cfg.memory_data.values() if d.sort == MemoryDataSort.UnicodeString]

        for testme in ("SOSNEAKY", "Welcome to the admin console, trusted user!\n", "Go away!\n", "Username: \n"):
            assert testme.encode("utf-16-le") in recovered_strings

    def test_arm_function_hints_from_data_references(self):
        path = os.path.join(test_location, "armel", "sha224sum")
        proj = angr.Project(path, auto_load_libs=False)

        proj.analyses.CFGFast(data_references=True)
        funcs = proj.kb.functions
        assert funcs.contains_addr(0x129C4)
        func = funcs[0x129C4]
        assert len(list(func.blocks)) == 1
        assert list(func.blocks)[0].size == 16


if __name__ == "__main__":
    unittest.main()

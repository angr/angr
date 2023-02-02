import time
import pickle
import networkx

import logging
import os
import unittest

from common import broken

import angr
from angr import options as o

l = logging.getLogger("angr.tests.test_cfgemulated")

test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries", "tests")


# pylint: disable=missing-class-docstring
# pylint: disable=no-self-use
class TestCfgemulate(unittest.TestCase):
    def compare_cfg(self, standard, g, function_list):
        """
        Standard graph comes with addresses only, and it is based on instructions, not on basic blocks
        """

        def get_function_name(addr):
            start = 0
            end = len(function_list) - 1

            while start <= end:
                mid = (start + end) / 2
                f = function_list[mid]
                if addr < f["start"]:
                    end = mid - 1
                elif addr > f["end"]:
                    start = mid + 1
                else:
                    return f["name"]

            return None

        # Sort function list
        function_list = sorted(function_list, key=lambda x: x["start"])

        # Convert the IDA-style CFG into VEX-style CFG
        s_graph = networkx.DiGraph()
        all_nodes = sorted(standard.nodes())
        addr_to_basicblock = {}
        last_basicblock = None
        for n in all_nodes:
            if last_basicblock is None:
                last_basicblock = (n, n)

            block = last_basicblock
            successors = standard.successors(n)
            if len(successors) == 1 and successors[0] >= block[0]:
                last_basicblock = (block[0], successors[0])
            else:
                # Save the existing block
                addr_to_basicblock[block[0]] = block

                # Create edges
                for s in successors:
                    s_graph.add_edge(block[0], s)

                # Clear last_basicblock so that we create a new basicblock next time
                last_basicblock = None

        graph = networkx.DiGraph()
        for src, dst in g.edges():
            graph.add_edge(src.addr, dst.addr)

        # Graph comparison
        for src, dst in s_graph.edges():
            if graph.has_edge(src, dst):
                continue
            else:
                # Edge doesn't exist in our CFG
                l.error(
                    "Edge (%s-0x%x, %s-0x%x) only exists in IDA CFG.",
                    get_function_name(src),
                    src,
                    get_function_name(dst),
                    dst,
                )

        for src, dst in graph.edges():
            if s_graph.has_edge(src, dst):
                continue
            else:
                # Edge doesn't exist in our CFG
                l.error(
                    "Edge (%s-0x%x, %s-0x%x) only exists in angr's CFG.",
                    get_function_name(src),
                    src,
                    get_function_name(dst),
                    dst,
                )

    def perform_single(self, binary_path, cfg_path=None):
        proj = angr.Project(
            binary_path,
            use_sim_procedures=True,
            default_analysis_mode="symbolic",
            load_options={"auto_load_libs": False},
        )
        start = time.time()
        cfg = proj.analyses.CFGEmulated(context_sensitivity_level=1, fail_fast=True)
        end = time.time()
        duration = end - start
        bbl_dict = cfg.nodes()

        l.info("CFG generated in %f seconds.", duration)
        l.info("Contains %d members in BBL dict.", len(bbl_dict))

        if cfg_path is not None and os.path.isfile(cfg_path):
            # Compare the graph with a predefined CFG
            info = pickle.load(open(cfg_path, "rb"))
            standard = info["cfg"]
            functions = info["functions"]
            graph = cfg.graph

            self.compare_cfg(standard, graph, functions)
        else:
            l.warning("No standard CFG specified.")

    @broken
    def test_cfg_0(self):
        binary_path = os.path.join(test_location, "x86_64", "cfg_0")
        cfg_path = binary_path + ".cfg"
        self.perform_single(binary_path, cfg_path)

    @broken
    def test_cfg_1(self):
        binary_path = os.path.join(test_location, "x86_64", "cfg_1")
        cfg_path = binary_path + ".cfg"
        self.perform_single(binary_path, cfg_path)

    @broken
    def test_cfg_2(self):
        binary_path = os.path.join(test_location, "armel", "test_division")
        cfg_path = binary_path + ".cfg"
        self.perform_single(binary_path, cfg_path)

    @broken
    def test_cfg_3(self):
        binary_path = os.path.join(test_location, "mips", "test_arrays")
        cfg_path = binary_path + ".cfg"
        self.perform_single(binary_path, cfg_path)

    @broken
    def test_cfg_4(self):
        binary_path = os.path.join(test_location, "mipsel", "darpa_ping")
        cfg_path = binary_path + ".cfg"
        self.perform_single(binary_path, cfg_path)

    def test_additional_edges(self):
        # Test the `additional_edges` parameter for CFG generation

        binary_path = os.path.join(test_location, "x86_64", "switch")
        proj = angr.Project(
            binary_path,
            use_sim_procedures=True,
            default_analysis_mode="symbolic",
            load_options={"auto_load_libs": False},
        )
        additional_edges = {0x400573: [0x400580, 0x40058F, 0x40059E]}
        cfg = proj.analyses.CFGEmulated(
            context_sensitivity_level=0,
            additional_edges=additional_edges,
            fail_fast=True,
            resolve_indirect_jumps=False,  # For this test case, we need to disable the
            # jump table resolving, otherwise CFGEmulated
            # can automatically find the node 0x4005ad.
        )

        assert cfg.get_any_node(0x400580) is not None
        assert cfg.get_any_node(0x40058F) is not None
        assert cfg.get_any_node(0x40059E) is not None
        assert cfg.get_any_node(0x4005AD) is None

    def test_not_returning(self):
        # Make sure we are properly labeling functions that do not return in function manager

        binary_path = os.path.join(test_location, "x86_64", "not_returning")
        proj = angr.Project(binary_path, use_sim_procedures=True, load_options={"auto_load_libs": False})
        proj.analyses.CFGEmulated(context_sensitivity_level=0, fail_fast=True)  # pylint:disable=unused-variable

        # function_a returns
        assert proj.kb.functions.function(name="function_a") is not None
        assert proj.kb.functions.function(name="function_a").returning

        # function_b does not return
        assert proj.kb.functions.function(name="function_b") is not None
        assert not proj.kb.functions.function(name="function_b").returning

        # function_c does not return
        assert proj.kb.functions.function(name="function_c") is not None
        assert not proj.kb.functions.function(name="function_c").returning

        # main does not return
        assert proj.kb.functions.function(name="main") is not None
        assert not proj.kb.functions.function(name="main").returning

        # function_d should not be reachable
        assert proj.kb.functions.function(name="function_d") is None

    @broken
    def test_cfg_5(self):
        binary_path = os.path.join(test_location, "mipsel", "busybox")
        cfg_path = binary_path + ".cfg"

        self.perform_single(binary_path, cfg_path)

    def test_cfg_6(self):
        function_addresses = [
            0xFA630,
            0xFA683,
            0xFA6D4,
            0xFA707,
            0xFA754,
            0xFA779,
            0xFA7A9,
            0xFA7D6,
            0xFA844,
            0xFA857,
            0xFA8D9,
            0xFA92F,
            0xFA959,
            0xFA9FB,
            0xFABD6,
            0xFAC61,
            0xFACC2,
            0xFAD29,
            0xFAF94,
            0xFBD07,
            0xFC100,
            0xFC101,
            0xFC14F,
            0xFC18E,
            0xFC25E,
            0xFC261,
            0xFC3C6,
            0xFC42F,
            0xFC4A3,
            0xFC4CF,
            0xFC4DB,
            0xFC5BA,
            0xFC5EF,
            0xFC5FE,
            0xFC611,
            0xFC682,
            0xFC6B7,
            0xFC7FC,
            0xFC8A8,
            0xFC8E7,
            0xFCB42,
            0xFCB50,
            0xFCB72,
            0xFCC3B,
            0xFCC7A,
            0xFCC8B,
            0xFCCDC,
            0xFD1A3,
            0xFF06E,
        ]

        # We need to add DO_CCALLS to resolve long jmp and support real mode
        o.modes["fastpath"] |= {o.DO_CCALLS}
        binary_path = test_location + "/i386/bios.bin.elf"
        proj = angr.Project(binary_path, use_sim_procedures=True, page_size=1, auto_load_libs=False)
        proj.analyses.CFGEmulated(context_sensitivity_level=1, fail_fast=True)  # pylint:disable=unused-variable
        assert {f for f in proj.kb.functions} >= set(function_addresses)
        o.modes["fastpath"] ^= {o.DO_CCALLS}

    def test_fauxware(self):
        binary_path = os.path.join(test_location, "x86_64", "fauxware")
        cfg_path = binary_path + ".cfg"

        self.perform_single(binary_path, cfg_path)

    @broken
    def test_loop_unrolling(self):
        binary_path = os.path.join(test_location, "x86_64", "cfg_loop_unrolling")

        p = angr.Project(binary_path, auto_load_libs=True)
        cfg = p.analyses.CFGEmulated(fail_fast=True)

        cfg.normalize()
        cfg.unroll_loops(5)

        assert len(cfg.get_all_nodes(0x400636)) == 7

    def test_thumb_mode(self):
        # In thumb mode, all addresses of instructions and in function manager should be odd numbers, which loyally
        # reflect VEX's trick to encode the THUMB state in the address.

        binary_path = os.path.join(test_location, "armhf", "test_arrays")
        p = angr.Project(binary_path, auto_load_libs=False)
        cfg = p.analyses.CFGEmulated(fail_fast=True)

        def check_addr(a):
            if a % 2 == 1:
                assert cfg.is_thumb_addr(a)
            else:
                assert not cfg.is_thumb_addr(a)

        # CFGNodes
        cfg_node_addrs = [n.addr for n in cfg.graph.nodes() if not n.is_simprocedure]
        for a in cfg_node_addrs:
            check_addr(a)

        # Functions in function manager
        for f_addr, f in p.kb.functions.items():
            if f.is_simprocedure:
                continue
            check_addr(f_addr)
            if f.startpoint is not None:
                check_addr(f.startpoint.addr)

    def test_fakeret_edges_0(self):
        # Test the bug where a fakeret edge can be missing in certain cases
        # Reported by Attila Axt (GitHub: @axt)
        # Ref: https://github.com/angr/angr/issues/72

        binary_path = os.path.join(test_location, "x86_64", "cfg_3")

        p = angr.Project(binary_path, auto_load_libs=False)
        cfg = p.analyses.CFGEmulated(context_sensitivity_level=3, fail_fast=True)

        putchar_plt = cfg.functions.function(name="putchar", plt=True)
        assert putchar_plt.returning

        putchar = cfg.functions.function(name="putchar", plt=False)
        assert putchar.returning

        # Since context sensitivity is 3, there should be two different putchar nodes
        putchar_cfgnodes = cfg.get_all_nodes(putchar.addr)
        assert len(putchar_cfgnodes) == 2

        # Each putchar node has a different predecessor as their PLT entry
        plt_entry_0 = cfg.get_predecessors(putchar_cfgnodes[0])
        assert len(plt_entry_0) == 1
        plt_entry_0 = plt_entry_0[0]

        plt_entry_1 = cfg.get_predecessors(putchar_cfgnodes[1])
        assert len(plt_entry_1) == 1
        plt_entry_1 = plt_entry_1[0]

        assert plt_entry_0 is not plt_entry_1

        # Each PLT entry should have a FakeRet edge
        preds_0 = cfg.get_predecessors(plt_entry_0)
        assert len(preds_0) == 1
        preds_1 = cfg.get_predecessors(plt_entry_1)
        assert len(preds_1) == 1

        # Each predecessor must have a call edge and a FakeRet edge
        edges_0 = cfg.get_successors_and_jumpkind(preds_0[0], excluding_fakeret=False)
        assert len(edges_0) == 2
        jumpkinds = {jumpkind for _, jumpkind in edges_0}
        assert jumpkinds == {"Ijk_Call", "Ijk_FakeRet"}

        edges_1 = cfg.get_successors_and_jumpkind(preds_1[0], excluding_fakeret=False)
        assert len(edges_1) == 2
        jumpkinds = {jumpkind for _, jumpkind in edges_1}
        assert jumpkinds == {"Ijk_Call", "Ijk_FakeRet"}

    def test_string_references(self):
        # Test AttributeError on 'addr' which occurs when searching for string
        # references

        binary_path = os.path.join(test_location, "i386", "ctf_nuclear")
        b = angr.Project(binary_path, load_options={"auto_load_libs": False})
        cfg = b.analyses.CFGEmulated(keep_state=True, fail_fast=True)

        string_references = []
        for f in cfg.functions.values():
            string_references.append(f.string_references())

        # test passes if hasn't thrown an exception

    def test_arrays(self):
        binary_path = os.path.join(test_location, "armhf", "test_arrays")
        b = angr.Project(binary_path, load_options={"auto_load_libs": False})
        cfg = b.analyses.CFGEmulated(fail_fast=True)

        node = cfg.model.get_any_node(0x10415)
        assert node is not None

        successors = cfg.model.get_successors(node)
        assert len(successors) == 2

    def test_max_steps(self):
        binary_path = os.path.join(test_location, "x86_64", "fauxware")
        b = angr.Project(binary_path, load_options={"auto_load_libs": False})
        cfg = b.analyses.CFGEmulated(max_steps=5, fail_fast=True)

        dfs_edges = networkx.dfs_edges(cfg.graph)

        depth_map = {}
        for src, dst in dfs_edges:
            if src not in depth_map:
                depth_map[src] = 0
            if dst not in depth_map:
                depth_map[dst] = depth_map[src] + 1
            depth_map[dst] = max(depth_map[src] + 1, depth_map[dst])

        assert max(depth_map.values()) <= 5

    def test_armel_final_missing_block(self):
        # Due to a stupid bug in CFGEmulated, the last block of a function might go missing in the function graph if the
        # only entry edge to that block is an Ijk_Ret edge. See #475 on GitHub.
        # Thank @gergo for reporting and providing this test binary.

        binary_path = os.path.join(test_location, "armel", "last_block")
        b = angr.Project(binary_path, auto_load_libs=False)
        cfg = b.analyses.CFGEmulated(fail_fast=True)

        blocks = list(cfg.kb.functions[0x8000].blocks)

        assert len(blocks) == 3
        assert {block.addr for block in blocks} == {0x8000, 0x8014, 0x8020}

    def test_armel_final_missing_block_b(self):
        # When _pending_jobs is not sorted, it is possible that we first process a pending job created earlier and then
        # process another pending job created later. Ideally, we hope that jobs are always processed in a topological
        # order, and the unsorted pending jobs break this assumption. In this test binary, at one point there can be two
        # pending jobs, 0x10b05/0x10ac5(Ijk_FakeRet) and 0x10bbe(Ijk_FakeRet). If 0x10bbe is processed before 0x10b05,
        # we do not # know whether the function 0x10a29(aes) returns or not. As a result, the final block of the main
        # function is not confirmed, and is not added to the function graph of function main.
        #
        # In fact, this also hints a different bug. We should always "confirm" that a function returns if its FakeRet
        # job are processed for whatever reason.
        #
        # Fixing either bug will resolve the issue that the final block does not show up in the function graph of main.
        # To stay on the safe side, both of them are fixed. Thanks @tyb0807 for reporting this issue and providing a
        # test binary.
        # EDG says: This binary is compiled incorrectly.
        # The binary's app code was compiled as CortexM, but linked against ARM libraries.
        # This is illegal, and does not actually execute on a real CortexM.
        # Somebody should recompile it....
        binary_path = os.path.join(test_location, "armel", "aes")
        b = angr.Project(binary_path, arch="ARMEL", auto_load_libs=False)

        function = b.loader.main_object.get_symbol("main").rebased_addr
        cfg = b.analyses.CFGEmulated(
            starts=[function],
            context_sensitivity_level=0,
            normalize=True,
            fail_fast=True,
        )

        blocks = list(cfg.kb.functions["main"].blocks)

        assert len(blocks) == 2
        assert {block.addr for block in blocks} == {0x10B79, 0x10BBF}

    def test_armel_incorrect_function_detection_caused_by_branch(self):
        # GitHub issue #685
        binary_path = os.path.join(test_location, "armel", "RTOSDemo.axf.issue_685")
        b = angr.Project(binary_path, auto_load_libs=False)

        cfg = b.analyses.CFGEmulated()

        # The Main function should be identified as a single function
        assert 0x80A1 in cfg.functions
        main_func = cfg.functions[0x80A1]

        # All blocks should be there
        block_addrs = sorted([b.addr for b in main_func.blocks])
        assert block_addrs == [0x80A1, 0x80B1, 0x80BB, 0x80CD, 0x80DF, 0x80E3, 0x80ED]

        # The ResetISR function should be identified as a single function, too
        assert 0x8009 in cfg.functions
        resetisr_func = cfg.functions[0x8009]

        # All blocks should be there
        block_addrs = sorted([b.addr for b in resetisr_func.blocks])
        assert block_addrs == [0x8009, 0x8011, 0x801F, 0x8027]

    def test_cfg_switches(self):
        # logging.getLogger('angr.analyses.cfg.cfg_fast').setLevel(logging.INFO)
        # logging.getLogger('angr.analyses.cfg.indirect_jump_resolvers.jumptable').setLevel(logging.DEBUG)

        filename = "cfg_switches"

        edges = {
            "x86_64": {
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
            },
        }

        arches = edges.keys()

        for arch in arches:
            path = os.path.join(test_location, arch, filename)
            proj = angr.Project(path, load_options={"auto_load_libs": False})

            cfg = proj.analyses.CFGEmulated()

            for src, dst in edges[arch]:
                src_node = cfg.get_any_node(src)
                dst_node = cfg.get_any_node(dst)
                assert dst_node in src_node.successors, "CFG edge {}-{} is not found.".format(
                    src_node,
                    dst_node,
                )

    class CFGEmulatedAborted(angr.analyses.cfg.cfg_emulated.CFGEmulated):  # pylint:disable=abstract-method
        """
        Only used in the test_abort_and_resume test case.
        """

        should_abort = False

        def _intra_analysis(self):
            if self.should_abort:
                self.abort()
            else:
                super()._intra_analysis()

    def test_abort_and_resume(self):
        angr.analyses.AnalysesHub.register_default("CFGEmulatedAborted", self.CFGEmulatedAborted)

        self.CFGEmulatedAborted.should_abort = False
        binary_path = os.path.join(test_location, "x86_64", "fauxware")
        b = angr.Project(binary_path, auto_load_libs=False)

        self.CFGEmulatedAborted.should_abort = True
        cfg = b.analyses.CFGEmulatedAborted()
        assert len(list(cfg.jobs)) > 0  # there should be left-over jobs

        self.CFGEmulatedAborted.should_abort = False
        cfg.resume()

        assert len(list(cfg.jobs)) == 0

    def test_base_graph(self):
        path = os.path.join(test_location, "x86_64", "test_cfgemulated_base_graph")

        func_addr = 0x401129

        edges = {
            (0x401129, 0x401144),
            (0x401129, 0x40114D),
            (0x401144, 0x401154),
            (0x40114D, 0x401154),
        }

        final_states_info = {
            0x401129: 2,
            0x40114D: 1,
            0x401144: 1,
            0x401154: 1,
        }

        proj = angr.Project(path, load_options={"auto_load_libs": False})

        cfg_fast = proj.analyses.CFGFast(normalize=True)
        target_function = cfg_fast.kb.functions[func_addr]
        target_function.normalize()

        target_function_cfg_emulated = proj.analyses.CFGEmulated(
            keep_state=True,
            state_add_options=angr.options.refs,
            base_graph=target_function.graph,
            starts=(func_addr,),
            normalize=True,
        )
        for src, dst in edges:
            src_node = target_function_cfg_emulated.get_any_node(src)
            dst_node = target_function_cfg_emulated.get_any_node(dst)
            assert dst_node in src_node.successors, "CFG edge {}-{} is not found.".format(
                src_node,
                dst_node,
            )

        for node_addr, final_states_number in final_states_info.items():
            node = target_function_cfg_emulated.get_any_node(node_addr)
            assert final_states_number == len(node.final_states), (
                "CFG node 0x%x has incorrect final states." % node_addr
            )


if __name__ == "__main__":
    logging.getLogger("angr.state_plugins.abstract_memory").setLevel(logging.DEBUG)
    # logging.getLogger("angr.state_plugins.symbolic_memory").setLevel(logging.DEBUG)
    # logging.getLogger("angr.analyses.cfg.cfg_emulated").setLevel(logging.DEBUG)
    # logging.getLogger("s_irsb").setLevel(logging.DEBUG)
    # Temporarily disable the warnings of claripy backend
    # logging.getLogger("claripy.backends.backend").setLevel(logging.ERROR)
    # logging.getLogger("claripy.claripy").setLevel(logging.ERROR)

    unittest.main()

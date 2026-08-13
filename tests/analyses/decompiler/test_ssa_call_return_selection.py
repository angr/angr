from __future__ import annotations

import unittest
from pathlib import Path

import archinfo
import networkx

import angr
from angr import ailment
from angr.analyses.decompiler import Decompiler
from angr.analyses.decompiler.clinic import Clinic
from angr.analyses.decompiler.ssailification import Ssailification
from angr.analyses.decompiler.ssailification.traversal import TraversalAnalysis
from angr.analyses.decompiler.variable_map import variable_map_of
from angr.calling_conventions import SimCCSystemVAMD64
from angr.sim_type import SimTypeBottom, SimTypeDouble, SimTypeFunction, SimTypeLongLong
from tests.common import bin_location


class TestSSACallReturnSelection(unittest.TestCase):
    """Test SSA selection of provisional integer and floating-point call returns."""

    @staticmethod
    def _make_return_call(project, manager, *, ins_addr=0x1000, args=(), bits=64):
        ret_expr = ailment.Expr.Register(manager.next_atom(), project.arch.ret_offset, bits, ins_addr=ins_addr)
        fp_ret_expr = ailment.Expr.Register(manager.next_atom(), project.arch.fp_ret_offset, bits, ins_addr=ins_addr)
        call = ailment.Expr.Call(
            manager.next_atom(),
            ailment.Expr.Const(manager.next_atom(), 0x2000, project.arch.bits),
            args=args,
            bits=bits,
            ins_addr=ins_addr,
        )
        return (
            ailment.Stmt.SideEffectStatement(
                manager.next_atom(),
                call,
                ret_expr=ret_expr,
                fp_ret_expr=fp_ret_expr,
                ins_addr=ins_addr,
            ),
            ret_expr,
            fp_ret_expr,
        )

    @staticmethod
    def _make_register_copy(project, manager, source, destination, *, bits=64, ins_addr=0x1005):
        return ailment.Stmt.Assignment(
            manager.next_atom(),
            ailment.Expr.Register(manager.next_atom(), project.arch.registers[destination][0], bits, ins_addr=ins_addr),
            ailment.Expr.Register(manager.next_atom(), project.arch.registers[source][0], bits, ins_addr=ins_addr),
            ins_addr=ins_addr,
        )

    @staticmethod
    def _ssailify(project, manager, blocks, edges=()):
        function = project.kb.functions.function(addr=blocks[0].addr, create=True)
        assert function is not None
        graph = networkx.DiGraph()
        graph.add_nodes_from(blocks)
        graph.add_edges_from(edges)
        result = project.analyses[Ssailification].prep(fail_fast=True)(
            function,
            graph,
            entry=blocks[0],
            ail_manager=manager,
        )
        assert result.out_graph is not None
        return result.out_graph

    @staticmethod
    def _count_calls(graph):
        class CallCounter(ailment.AILBlockViewer):
            """Count calls in an AIL graph."""

            def __init__(self):
                super().__init__()
                self.count = 0

            def _handle_Call(self, expr_idx, expr, stmt_idx, stmt, block):
                self.count += 1
                super()._handle_Call(expr_idx, expr, stmt_idx, stmt, block)

        counter = CallCounter()
        for block in graph:
            counter.walk(block)
        return counter.count

    def test_selects_explicit_floating_return_read(self):
        project = angr.load_shellcode(b"\xc3", "AMD64", load_address=0x1000)
        manager = ailment.Manager(arch=project.arch)
        call_stmt, _, fp_ret_expr = self._make_return_call(project, manager)
        use = self._make_register_copy(project, manager, "xmm0", "xmm1")

        graph = self._ssailify(project, manager, [ailment.Block(0x1000, 6, statements=[call_stmt, use])])

        rewritten = next(iter(graph))
        rewritten_call, rewritten_use = rewritten.statements
        self.assertIsInstance(rewritten_call, ailment.Stmt.Assignment)
        self.assertIsInstance(rewritten_call.dst, ailment.Expr.VirtualVariable)
        self.assertEqual(rewritten_call.dst.reg_offset, fp_ret_expr.reg_offset)
        self.assertIsInstance(rewritten_use.src, ailment.Expr.VirtualVariable)
        self.assertEqual(rewritten_use.src.varid, rewritten_call.dst.varid)

    def test_selects_explicit_integer_return_read(self):
        project = angr.load_shellcode(b"\xc3", "AMD64", load_address=0x1000)
        manager = ailment.Manager(arch=project.arch)
        call_stmt, ret_expr, _ = self._make_return_call(project, manager)
        use = self._make_register_copy(project, manager, "rax", "rbx")

        graph = self._ssailify(project, manager, [ailment.Block(0x1000, 6, statements=[call_stmt, use])])

        rewritten_call = next(iter(graph)).statements[0]
        self.assertIsInstance(rewritten_call, ailment.Stmt.Assignment)
        self.assertEqual(rewritten_call.dst.reg_offset, ret_expr.reg_offset)

    def test_selects_arm_hard_float_returns(self):
        project = angr.load_shellcode(b"\x1e\xff\x2f\xe1", archinfo.ArchARMHF(), load_address=0x1000)
        for source, destination, select_fp in (("r0", "r1", False), ("s0", "s2", True)):
            with self.subTest(source=source):
                manager = ailment.Manager(arch=project.arch)
                call_stmt, ret_expr, fp_ret_expr = self._make_return_call(project, manager, bits=32)
                use = self._make_register_copy(project, manager, source, destination, bits=32)

                graph = self._ssailify(project, manager, [ailment.Block(0x1000, 4, statements=[call_stmt, use])])

                rewritten_call = next(iter(graph)).statements[0]
                self.assertIsInstance(rewritten_call, ailment.Stmt.Assignment)
                expected = fp_ret_expr if select_fp else ret_expr
                self.assertEqual(rewritten_call.dst.reg_offset, expected.reg_offset)

    def test_selects_floating_return_across_blocks(self):
        project = angr.load_shellcode(b"\xc3", "AMD64", load_address=0x1000)
        manager = ailment.Manager(arch=project.arch)
        call_stmt, _, fp_ret_expr = self._make_return_call(project, manager)
        use = self._make_register_copy(project, manager, "xmm0", "xmm1", ins_addr=0x1010)
        call_block = ailment.Block(0x1000, 6, statements=[call_stmt])
        use_block = ailment.Block(0x1010, 1, statements=[use])

        graph = self._ssailify(project, manager, [call_block, use_block], [(call_block, use_block)])

        rewritten_call_block = next(block for block in graph if block.addr == call_block.addr)
        rewritten_call = rewritten_call_block.statements[0]
        self.assertIsInstance(rewritten_call, ailment.Stmt.Assignment)
        self.assertEqual(rewritten_call.dst.reg_offset, fp_ret_expr.reg_offset)

    def test_argument_probe_does_not_select_return(self):
        project = angr.load_shellcode(b"\xc3", "AMD64", load_address=0x1000)
        manager = ailment.Manager(arch=project.arch)
        first_call, _, _ = self._make_return_call(project, manager, ins_addr=0x1000)
        second_call, _, _ = self._make_return_call(project, manager, ins_addr=0x1005, args=None)
        second_call = ailment.Stmt.SideEffectStatement(
            second_call.idx,
            second_call.expr,
            ret_expr=None,
            fp_ret_expr=None,
            **second_call.tags,
        )

        graph = self._ssailify(project, manager, [ailment.Block(0x1000, 10, statements=[first_call, second_call])])

        rewritten_call = next(iter(graph)).statements[0]
        self.assertIsInstance(rewritten_call, ailment.Stmt.Assignment)
        self.assertEqual(rewritten_call.dst.reg_offset, project.arch.ret_offset)

    def test_explicit_call_argument_selects_floating_return(self):
        project = angr.load_shellcode(b"\xc3", "AMD64", load_address=0x1000)
        manager = ailment.Manager(arch=project.arch)
        first_call, _, fp_ret_expr = self._make_return_call(project, manager, ins_addr=0x1000)
        fp_ret_offset = project.arch.fp_ret_offset
        assert fp_ret_offset is not None
        argument = ailment.Expr.Register(manager.next_atom(), fp_ret_offset, 64, ins_addr=0x1005)
        second_call, _, _ = self._make_return_call(project, manager, ins_addr=0x1005, args=(argument,))
        second_call = ailment.Stmt.SideEffectStatement(
            second_call.idx,
            second_call.expr,
            ret_expr=None,
            fp_ret_expr=None,
            **second_call.tags,
        )

        graph = self._ssailify(project, manager, [ailment.Block(0x1000, 10, statements=[first_call, second_call])])

        rewritten_first, rewritten_second = next(iter(graph)).statements
        self.assertIsInstance(rewritten_first, ailment.Stmt.Assignment)
        self.assertEqual(rewritten_first.dst.reg_offset, fp_ret_expr.reg_offset)
        self.assertIsInstance(rewritten_second, ailment.Stmt.SideEffectStatement)
        self.assertIsInstance(rewritten_second.expr.args[0], ailment.Expr.VirtualVariable)
        self.assertEqual(rewritten_second.expr.args[0].varid, rewritten_first.dst.varid)

    def test_overwritten_floating_return_is_not_selected(self):
        project = angr.load_shellcode(b"\xc3", "AMD64", load_address=0x1000)
        manager = ailment.Manager(arch=project.arch)
        call_stmt, _, _ = self._make_return_call(project, manager)
        xmm0_offset = project.arch.registers["xmm0"][0]
        overwrite = ailment.Stmt.Assignment(
            manager.next_atom(),
            ailment.Expr.Register(manager.next_atom(), xmm0_offset, 64, ins_addr=0x1002),
            ailment.Expr.Const(manager.next_atom(), 0, 64, ins_addr=0x1002),
            ins_addr=0x1002,
        )
        use = self._make_register_copy(project, manager, "xmm0", "xmm1")

        graph = self._ssailify(project, manager, [ailment.Block(0x1000, 6, statements=[call_stmt, overwrite, use])])

        rewritten_call = next(iter(graph)).statements[0]
        self.assertIsInstance(rewritten_call, ailment.Stmt.Assignment)
        self.assertEqual(rewritten_call.dst.reg_offset, project.arch.ret_offset)

    def test_neither_return_candidate_preserves_integer_fallback(self):
        project = angr.load_shellcode(b"\xc3", "AMD64", load_address=0x1000)
        manager = ailment.Manager(arch=project.arch)
        call_stmt, _, _ = self._make_return_call(project, manager, args=None)

        graph = self._ssailify(project, manager, [ailment.Block(0x1000, 1, statements=[call_stmt])])

        rewritten_call = next(iter(graph)).statements[0]
        self.assertIsInstance(rewritten_call, ailment.Stmt.Assignment)
        self.assertEqual(rewritten_call.dst.reg_offset, project.arch.ret_offset)

    def test_selects_returns_independently_across_consecutive_calls(self):
        project = angr.load_shellcode(b"\xc3", "AMD64", load_address=0x1000)
        manager = ailment.Manager(arch=project.arch)
        first_call, ret_expr, _ = self._make_return_call(project, manager, ins_addr=0x1000)
        integer_use = self._make_register_copy(project, manager, "rax", "rbx", ins_addr=0x1001)
        second_call, _, fp_ret_expr = self._make_return_call(project, manager, ins_addr=0x1002)
        floating_use = self._make_register_copy(project, manager, "xmm0", "xmm1", ins_addr=0x1003)

        graph = self._ssailify(
            project,
            manager,
            [ailment.Block(0x1000, 6, statements=[first_call, integer_use, second_call, floating_use])],
        )

        statements = next(iter(graph)).statements
        self.assertEqual(statements[0].dst.reg_offset, ret_expr.reg_offset)
        self.assertEqual(statements[2].dst.reg_offset, fp_ret_expr.reg_offset)

    def test_selects_integer_partial_alias_and_widens_floating_return(self):
        project = angr.load_shellcode(b"\xc3", "AMD64", load_address=0x1000)
        manager = ailment.Manager(arch=project.arch)
        integer_call, _, _ = self._make_return_call(project, manager, ins_addr=0x1000)
        integer_use = self._make_register_copy(project, manager, "eax", "ebx", bits=32, ins_addr=0x1001)
        floating_call, _, _ = self._make_return_call(project, manager, ins_addr=0x1002)
        floating_use = self._make_register_copy(project, manager, "xmm0", "xmm1", bits=128, ins_addr=0x1003)

        graph = self._ssailify(
            project,
            manager,
            [ailment.Block(0x1000, 6, statements=[integer_call, integer_use, floating_call, floating_use])],
        )

        statements = next(iter(graph)).statements
        self.assertEqual(statements[0].dst.reg_offset, project.arch.ret_offset)
        self.assertEqual(statements[2].dst.reg_offset, project.arch.fp_ret_offset)
        self.assertEqual(statements[2].dst.bits, 128)
        self.assertIsInstance(statements[2].src, ailment.Expr.Insert)

    def test_selects_floating_return_that_reaches_a_phi(self):
        project = angr.load_shellcode(b"\xc3", "AMD64", load_address=0x1000)
        manager = ailment.Manager(arch=project.arch)
        entry = ailment.Block(0x1000, 1, statements=[])
        call_stmt, _, fp_ret_expr = self._make_return_call(project, manager, ins_addr=0x1010)
        call_block = ailment.Block(0x1010, 1, statements=[call_stmt])
        fp_ret_offset = project.arch.fp_ret_offset
        assert fp_ret_offset is not None
        other_def = ailment.Stmt.Assignment(
            manager.next_atom(),
            ailment.Expr.Register(manager.next_atom(), fp_ret_offset, 64, ins_addr=0x1020),
            ailment.Expr.Const(manager.next_atom(), 0, 64, ins_addr=0x1020),
            ins_addr=0x1020,
        )
        other_block = ailment.Block(0x1020, 1, statements=[other_def])
        use = self._make_register_copy(project, manager, "xmm0", "xmm1", ins_addr=0x1030)
        join = ailment.Block(0x1030, 1, statements=[use])

        graph = self._ssailify(
            project,
            manager,
            [entry, call_block, other_block, join],
            [(entry, call_block), (entry, other_block), (call_block, join), (other_block, join)],
        )

        rewritten_call = next(block for block in graph if block.addr == call_block.addr).statements[0]
        rewritten_join = next(block for block in graph if block.addr == join.addr)
        self.assertEqual(rewritten_call.dst.reg_offset, fp_ret_expr.reg_offset)
        self.assertIsInstance(rewritten_join.statements[0], ailment.Stmt.Assignment)
        self.assertIsInstance(rewritten_join.statements[0].src, ailment.Expr.Phi)
        phi_varids = {vvar.varid for _, vvar in rewritten_join.statements[0].src.src_and_vvars if vvar is not None}
        self.assertIn(rewritten_call.dst.varid, phi_varids)

    def test_selects_floating_return_that_reaches_a_loop_phi(self):
        project = angr.load_shellcode(b"\xc3", "AMD64", load_address=0x1000)
        manager = ailment.Manager(arch=project.arch)
        call_stmt, _, fp_ret_expr = self._make_return_call(project, manager, ins_addr=0x1000)
        entry = ailment.Block(0x1000, 1, statements=[call_stmt])
        use = self._make_register_copy(project, manager, "xmm0", "xmm1", ins_addr=0x1010)
        header = ailment.Block(0x1010, 1, statements=[use])
        fp_ret_offset = project.arch.fp_ret_offset
        assert fp_ret_offset is not None
        latch_def = ailment.Stmt.Assignment(
            manager.next_atom(),
            ailment.Expr.Register(manager.next_atom(), fp_ret_offset, 64, ins_addr=0x1020),
            ailment.Expr.Const(manager.next_atom(), 1, 64, ins_addr=0x1020),
            ins_addr=0x1020,
        )
        latch = ailment.Block(0x1020, 1, statements=[latch_def])
        exit_block = ailment.Block(0x1030, 1, statements=[])

        graph = self._ssailify(
            project,
            manager,
            [entry, header, latch, exit_block],
            [(entry, header), (header, latch), (latch, header), (header, exit_block)],
        )

        rewritten_call = next(block for block in graph if block.addr == entry.addr).statements[0]
        rewritten_header = next(block for block in graph if block.addr == header.addr)
        phi_stmt = rewritten_header.statements[0]
        self.assertEqual(rewritten_call.dst.reg_offset, fp_ret_expr.reg_offset)
        self.assertIsInstance(phi_stmt, ailment.Stmt.Assignment)
        self.assertIsInstance(phi_stmt.src, ailment.Expr.Phi)
        phi_varids = {vvar.varid for _, vvar in phi_stmt.src.src_and_vvars if vvar is not None}
        self.assertIn(rewritten_call.dst.varid, phi_varids)

    def test_repeated_ssa_does_not_duplicate_selected_call(self):
        project = angr.load_shellcode(b"\xc3", "AMD64", load_address=0x1000)
        manager = ailment.Manager(arch=project.arch)
        call_stmt, _, _ = self._make_return_call(project, manager)
        use = self._make_register_copy(project, manager, "xmm0", "xmm1")
        first_graph = self._ssailify(project, manager, [ailment.Block(0x1000, 6, statements=[call_stmt, use])])
        first_blocks = list(first_graph)
        first_edges = list(first_graph.edges())

        second_graph = self._ssailify(project, manager, first_blocks, first_edges)

        self.assertEqual(self._count_calls(first_graph), 1)
        self.assertEqual(self._count_calls(second_graph), 1)
        rewritten = next(iter(second_graph))
        self.assertIsInstance(rewritten.statements[0], ailment.Stmt.Assignment)
        self.assertIsInstance(rewritten.statements[0].dst, ailment.Expr.VirtualVariable)
        self.assertIsInstance(rewritten.statements[1].src, ailment.Expr.VirtualVariable)
        self.assertEqual(rewritten.statements[1].src.varid, rewritten.statements[0].dst.varid)
        self.assertFalse(
            any(
                isinstance(stmt, ailment.Stmt.SideEffectStatement)
                and stmt.ret_expr is not None
                and stmt.fp_ret_expr is not None
                for block in second_graph
                for stmt in block.statements
            )
        )

    def test_stack_probe_drops_provisional_fp_return_and_preserves_prior_fp_state(self):
        project = angr.load_shellcode(b"\xc3", "AMD64", load_address=0x1000)
        for probe_name, use_metadata_flag in (("__chkstk", False), ("helper", True)):
            with self.subTest(probe_name=probe_name, use_metadata_flag=use_metadata_flag):
                manager = ailment.Manager(arch=project.arch)
                probe = project.kb.functions.function(addr=0x2000, create=True)
                assert probe is not None
                probe.name = probe_name
                probe.info["is_alloca_probe"] = use_metadata_flag
                call_stmt, ret_expr, _ = self._make_return_call(project, manager)
                fp_ret_offset = project.arch.fp_ret_offset
                assert fp_ret_offset is not None
                prior = ailment.Stmt.Assignment(
                    manager.next_atom(),
                    ailment.Expr.Register(manager.next_atom(), fp_ret_offset, 64, ins_addr=0x0FFF),
                    ailment.Expr.Const(manager.next_atom(), 1, 64, ins_addr=0x0FFF),
                    ins_addr=0x0FFF,
                )
                use = self._make_register_copy(project, manager, "xmm0", "xmm1", ins_addr=0x1001)
                call_block = ailment.Block(0x1000, 1, statements=[prior, call_stmt])
                use_block = ailment.Block(0x1001, 1, statements=[use])
                graph = networkx.DiGraph()
                graph.add_edge(call_block, use_block)
                clinic = object.__new__(Clinic)
                clinic.kb = project.kb
                clinic.project = project

                fixed_graph = clinic._fix_special_call_calling_conventions(graph)  # pylint: disable=protected-access
                fixed_call_block = next(block for block in fixed_graph if block.addr == call_block.addr)
                fixed_call = fixed_call_block.statements[1]

                self.assertEqual(fixed_call.ret_expr, ret_expr)
                self.assertIsNone(fixed_call.fp_ret_expr)
                rewritten = self._ssailify(project, manager, list(fixed_graph), fixed_graph.edges())
                rewritten_call_block = next(block for block in rewritten if block.addr == call_block.addr)
                rewritten_use_block = next(block for block in rewritten if block.addr == use_block.addr)
                self.assertIsInstance(rewritten_call_block.statements[0], ailment.Stmt.Assignment)
                self.assertIsInstance(rewritten_call_block.statements[0].dst, ailment.Expr.VirtualVariable)
                self.assertIsInstance(rewritten_use_block.statements[0].src, ailment.Expr.VirtualVariable)
                self.assertEqual(
                    rewritten_use_block.statements[0].src.varid,
                    rewritten_call_block.statements[0].dst.varid,
                )

    def test_known_prototypes_preserve_machine_read_selection(self):
        project = angr.load_shellcode(b"\xc3", "AMD64", load_address=0x1000)
        cases = (
            ("integer", SimTypeLongLong(), "rax", "rbx", project.arch.ret_offset),
            ("floating", SimTypeDouble(), "xmm0", "xmm1", project.arch.fp_ret_offset),
            ("void", SimTypeBottom(label="void"), None, None, project.arch.ret_offset),
        )
        for name, return_type, source, destination, expected_offset in cases:
            with self.subTest(return_type=name):
                manager = ailment.Manager(arch=project.arch)
                call_stmt, _, _ = self._make_return_call(project, manager)
                variable_map = variable_map_of(manager)
                variable_map.set_calling_convention(call_stmt.expr, SimCCSystemVAMD64(project.arch))
                prototype = SimTypeFunction([], return_type).with_arch(project.arch)
                assert isinstance(prototype, SimTypeFunction)
                variable_map.set_prototype(call_stmt.expr, prototype)
                call_stmt.expr.tags["is_prototype_guessed"] = False
                statements: list[ailment.Statement] = [call_stmt]
                if source is not None and destination is not None:
                    statements.append(self._make_register_copy(project, manager, source, destination))

                graph = self._ssailify(project, manager, [ailment.Block(0x1000, 6, statements=statements)])

                rewritten_call = next(iter(graph)).statements[0]
                self.assertIsInstance(rewritten_call, ailment.Stmt.Assignment)
                self.assertEqual(rewritten_call.dst.reg_offset, expected_offset)

    def test_zero_trigger_graph_keeps_provisional_tracking_empty(self):
        project = angr.load_shellcode(b"\xc3", "AMD64", load_address=0x1000)
        manager = ailment.Manager(arch=project.arch)
        ret_offset = project.arch.ret_offset
        assert ret_offset is not None
        statements = []
        for idx in range(256):
            statements.append(
                ailment.Stmt.Assignment(
                    manager.next_atom(),
                    ailment.Expr.Register(manager.next_atom(), ret_offset, 64),
                    ailment.Expr.Const(manager.next_atom(), idx, 64),
                )
            )
        block = ailment.Block(0x1000, 1, statements=statements)
        graph = networkx.DiGraph()
        graph.add_node(block)
        function = project.kb.functions.function(addr=block.addr, create=True)
        assert function is not None

        traversal = TraversalAnalysis(
            project,
            function,
            graph,
            None,
            False,
            False,
            False,
            set(),
            project.kb.functions.get,
            variable_map=variable_map_of(manager),
        )

        self.assertFalse(traversal.provisional_call_return_defs)
        self.assertFalse(traversal.used_provisional_call_return_defs)

    @unittest.expectedFailure
    def test_both_explicit_returns(self):
        project = angr.load_shellcode(b"\xc3", "AMD64", load_address=0x1000)
        manager = ailment.Manager(arch=project.arch)
        call_stmt, _, _ = self._make_return_call(project, manager)
        integer_use = self._make_register_copy(project, manager, "rax", "rbx", ins_addr=0x1001)
        floating_use = self._make_register_copy(project, manager, "xmm0", "xmm1", ins_addr=0x1002)

        graph = self._ssailify(
            project,
            manager,
            [ailment.Block(0x1000, 6, statements=[call_stmt, integer_use, floating_use])],
        )
        self.assertEqual(self._count_calls(graph), 1)

    def test_syscall_uses_only_integer_return_candidate(self):
        project = angr.load_shellcode(b"\xc3", "AMD64", load_address=0x1000)
        manager = ailment.Manager(arch=project.arch)
        ret_offset = project.arch.ret_offset
        fp_ret_offset = project.arch.fp_ret_offset
        assert ret_offset is not None and fp_ret_offset is not None
        ret_expr = ailment.Expr.Register(manager.next_atom(), ret_offset, 64)
        fp_ret_expr = ailment.Expr.Register(manager.next_atom(), fp_ret_offset, 64)
        call = ailment.Expr.Call(
            manager.next_atom(),
            ailment.Expr.DirtyExpression(manager.next_atom(), "syscall", [], bits=64),
            args=None,
            bits=64,
        )
        stmt = ailment.Stmt.SideEffectStatement(manager.next_atom(), call, ret_expr=ret_expr, fp_ret_expr=fp_ret_expr)
        variable_map_of(manager).set_calling_convention(call, SimCCSystemVAMD64(project.arch))

        graph = self._ssailify(project, manager, [ailment.Block(0x1000, 2, statements=[stmt])])

        rewritten = next(iter(graph)).statements[0]
        self.assertIsInstance(rewritten, ailment.Stmt.Assignment)
        self.assertEqual(rewritten.dst.reg_offset, ret_expr.reg_offset)

    def test_refresh_progress_meter_uses_floating_point_call_return(self):
        binary = Path(bin_location) / "tests" / "x86_64" / "decompiler" / "openssh_scp_O2_noinline"
        if not binary.is_file():
            self.skipTest(f"missing test binary: {binary}")
        project = angr.Project(binary, auto_load_libs=False)
        cfg = project.analyses.CFGFast(
            normalize=True,
            function_starts=[0x40C120],
            regions=[(0x40C120, 0x40C680)],
            fail_fast=True,
            show_progressbar=False,
        )
        function = cfg.kb.functions[0x40C120]

        for structurer in ("sailr", "phoenix"):
            with self.subTest(structurer=structurer):
                result = project.analyses[Decompiler].prep(fail_fast=True)(
                    function,
                    cfg=cfg.model,
                    preset="full",
                    options=[("structurer_cls", structurer)],
                    use_cache=False,
                )

                assert result.codegen is not None and result.codegen.text is not None
                self.assertIn("= monotime_double();", result.codegen.text)


if __name__ == "__main__":
    unittest.main()

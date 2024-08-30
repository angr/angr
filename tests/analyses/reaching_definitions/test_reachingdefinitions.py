#!/usr/bin/env python3
# Disable some pylint warnings: no-self-use, missing-docstring
# pylint: disable=R0201,C0111,bad-builtin,expression-not-assigned,no-member
from __future__ import annotations

import os
import pickle
from unittest import TestCase, main

import ailment
import claripy

import angr
from angr.analyses import ReachingDefinitionsAnalysis, CFGFast, CompleteCallingConventionsAnalysis
from angr.code_location import CodeLocation, ExternalCodeLocation
from angr.analyses.reaching_definitions.rd_state import ReachingDefinitionsState
from angr.analyses.reaching_definitions.subject import Subject
from angr.analyses.reaching_definitions.dep_graph import DepGraph
from angr.block import Block
from angr.knowledge_plugins.key_definitions.live_definitions import LiveDefinitions
from angr.knowledge_plugins.key_definitions.atoms import AtomKind, GuardUse, Tmp, Register, MemoryLocation
from angr.knowledge_plugins.key_definitions.constants import ObservationPointType, OP_BEFORE, OP_AFTER
from angr.knowledge_plugins.key_definitions.live_definitions import Definition, SpOffset
from angr.storage.memory_mixins import MultiValuedMemory
from angr.storage.memory_object import SimMemoryObject
from angr.utils.constants import DEFAULT_STATEMENT


class InsnAndNodeObserveTestingUtils:
    @staticmethod
    def assert_for_live_definitions(assertion, live_definition_1, live_definition_2):
        [
            {assertion(getattr(live_definition_1, attr)._pages, getattr(live_definition_2, attr)._pages)}
            for attr in ["registers", "stack", "memory"]
        ]
        assertion(live_definition_1.tmps, live_definition_2.tmps)

    @staticmethod
    def filter(observed_results, observation_points):
        # Return only the observed results associated with the observation points,
        # and do not fail if an observation point do not appear in the observed results.
        return [observed_results[key] for key in filter(lambda key: key in observed_results, observation_points)]

    @staticmethod
    def setup(observation_points):
        binary_path = _binary_path("all")
        project = angr.Project(binary_path, load_options={"auto_load_libs": False})
        cfg = project.analyses[CFGFast].prep()()

        main_function = cfg.kb.functions["main"]
        reaching_definitions = project.analyses[ReachingDefinitionsAnalysis].prep()(
            subject=main_function,
            observation_points=observation_points,
        )

        state = ReachingDefinitionsState(
            CodeLocation(main_function.addr, None), project.arch, reaching_definitions.subject
        )

        return (project, main_function, reaching_definitions, state)


def _binary_path(binary_name, arch: str = "x86_64"):
    tests_location = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "..", "..", "..", "..", "binaries", "tests"
    )
    return os.path.join(tests_location, arch, binary_name)


def _result_path(binary_results_name):
    return os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "results", "x86_64", binary_results_name + ".pickle"
    )


class TestReachingDefinitions(TestCase):
    def _run_reaching_definition_analysis_test(self, project, function, result_path, _extract_result):
        tmp_kb = angr.KnowledgeBase(project)
        reaching_definition = project.analyses[ReachingDefinitionsAnalysis].prep(kb=tmp_kb)(
            subject=function,
            observe_all=True,
        )

        result = _extract_result(reaching_definition)

        # Uncomment these to regenerate the reference results... if you dare
        # with open(result_path, "wb") as result_file:
        #    pickle.dump(result, result_file)
        with open(result_path, "rb") as result_file:
            expected_result = pickle.load(result_file)

        self.assertListEqual(result, expected_result)

    @staticmethod
    def _extract_all_definitions_from_storage(storage: MultiValuedMemory):
        all_defs = []
        for page_id, page in storage._pages.items():
            last_mo = None
            for pos, n in enumerate(page.content):
                if n is not None and (type(n) is not set or len(n) == 1):
                    addr = page_id * 4096 + pos
                    if type(n) is set:
                        mo: SimMemoryObject = next(iter(n))
                    else:
                        mo: SimMemoryObject = n
                    if mo is not last_mo:
                        last_mo = mo
                        all_defs.append((addr, list(LiveDefinitions.extract_defs(mo.object))))

        return all_defs

    def test_reaching_definition_analysis_definitions(self):
        def _result_extractor(rda):
            unsorted_result = (
                {
                    "key": x[0],
                    "register_definitions": self._extract_all_definitions_from_storage(x[1].registers),
                    "stack_definitions": self._extract_all_definitions_from_storage(x[1].stack),
                    "memory_definitions": self._extract_all_definitions_from_storage(x[1].memory),
                }
                for x in [(k, v) for k, v in rda.observed_results.items() if k[0] != "stmt"]
            )
            return sorted(unsorted_result, key=lambda x: x["key"])

        binaries_and_results = [
            (_binary_path(binary), _result_path(binary + "_definitions")) for binary in ["all", "fauxware", "loop"]
        ]

        for binary, result_path in binaries_and_results:
            project = angr.Project(binary, load_options={"auto_load_libs": False})
            cfg = project.analyses[CFGFast].prep()()
            function = cfg.kb.functions["main"]

            self._run_reaching_definition_analysis_test(project, function, result_path, _result_extractor)

    def test_reaching_definition_analysis_visited_blocks(self):
        def _result_extractor(rda):
            return sorted(rda.visited_blocks, key=lambda b: b.addr)

        binaries_and_results = [
            (_binary_path(binary), _result_path(binary + "_visited_blocks")) for binary in ["all", "fauxware", "loop"]
        ]

        for binary, result_path in binaries_and_results:
            project = angr.Project(binary, load_options={"auto_load_libs": False})
            cfg = project.analyses[CFGFast].prep()()
            function = cfg.kb.functions["main"]

            self._run_reaching_definition_analysis_test(project, function, result_path, _result_extractor)

    def test_node_observe(self):
        # Create several different observation points
        observation_points = [("node", 0x42, OP_AFTER), ("insn", 0x43, OP_AFTER)]

        _, _, reaching_definition, state = InsnAndNodeObserveTestingUtils.setup(observation_points)

        reaching_definition.node_observe(0x42, state, OP_AFTER)

        results = InsnAndNodeObserveTestingUtils.filter(reaching_definition.observed_results, observation_points)
        expected_results = [state.live_definitions]

        self.assertEqual(results, expected_results)

    def test_insn_observe_an_ailment_statement(self):
        # Create several different observation points
        observation_points = [("node", 0x42, OP_AFTER), ("insn", 0x43, OP_AFTER)]

        _, main_function, reaching_definition, state = InsnAndNodeObserveTestingUtils.setup(observation_points)

        # Here, the statement content does not matter, neither if it is really in the block or else…
        statement = ailment.statement.DirtyStatement(0, None)
        block = main_function._addr_to_block_node[main_function.addr]  # pylint: disable=W0212

        reaching_definition.insn_observe(0x43, statement, block, state, OP_AFTER)

        results = InsnAndNodeObserveTestingUtils.filter(reaching_definition.observed_results, observation_points)
        expected_results = [state.live_definitions]

        self.assertGreater(len(results), 0)
        [
            InsnAndNodeObserveTestingUtils.assert_for_live_definitions(self.assertEqual, x[0], x[1])
            for x in zip(results, expected_results)
        ]

    def test_insn_observe_before_an_imark_pyvex_statement(self):
        # Create several different observation points
        observation_points = [("node", 0x42, OP_AFTER), ("insn", 0x43, OP_BEFORE)]

        project, main_function, reaching_definition, state = InsnAndNodeObserveTestingUtils.setup(observation_points)

        code_block = main_function._addr_to_block_node[main_function.addr]  # pylint: disable=W0212
        block = Block(addr=0x43, byte_string=code_block.bytestr, project=project)
        statement = block.vex.statements[0]

        reaching_definition.insn_observe(0x43, statement, block, state, OP_BEFORE)

        results = InsnAndNodeObserveTestingUtils.filter(reaching_definition.observed_results, observation_points)
        expected_results = [state.live_definitions]

        self.assertGreater(len(results), 0)
        [
            InsnAndNodeObserveTestingUtils.assert_for_live_definitions(self.assertEqual, x[0], x[1])
            for x in zip(results, expected_results)
        ]

    def test_insn_observe_after_a_pyvex_statement(self):
        # Create several different observation points
        observation_points = [("node", 0x42, OP_AFTER), ("insn", 0x43, OP_AFTER)]

        project, main_function, reaching_definition, state = InsnAndNodeObserveTestingUtils.setup(observation_points)

        code_block = main_function._addr_to_block_node[main_function.addr]  # pylint: disable=W0212
        block = Block(addr=0x43, byte_string=code_block.bytestr, project=project)
        # When observing OP_AFTER an instruction, the statement has to be the last of a block
        # (or preceding an IMark)
        statement = block.vex.statements[-1]

        reaching_definition.insn_observe(0x43, statement, block, state, OP_AFTER)

        results = InsnAndNodeObserveTestingUtils.filter(reaching_definition.observed_results, observation_points)
        expected_results = [state.live_definitions]

        self.assertGreater(len(results), 0)
        [
            InsnAndNodeObserveTestingUtils.assert_for_live_definitions(self.assertEqual, x[0], x[1])
            for x in zip(results, expected_results)
        ]

    def test_reaching_definition_analysis_exposes_its_subject(self):
        binary_path = _binary_path("all")
        project = angr.Project(binary_path, load_options={"auto_load_libs": False})
        cfg = project.analyses[CFGFast].prep()()

        main_function = cfg.kb.functions["main"]
        reaching_definitions = project.analyses[ReachingDefinitionsAnalysis].prep()(subject=main_function)

        self.assertEqual(reaching_definitions.subject.__class__ is Subject, True)

    def test_get_the_sp_from_a_reaching_definition(self):
        binary = _binary_path("all")
        project = angr.Project(binary, auto_load_libs=False)
        cfg = project.analyses[CFGFast].prep()()

        tmp_kb = angr.KnowledgeBase(project)
        main_func = cfg.kb.functions["main"]
        rda = project.analyses[ReachingDefinitionsAnalysis].prep(kb=tmp_kb)(subject=main_func, observe_all=True)

        def _is_right_before_main_node(definition):
            bloc, ins_addr, op_type = definition[0]
            return bloc == "node" and ins_addr == main_func.addr and op_type == OP_BEFORE

        reach_definition_at_main = next(filter(_is_right_before_main_node, rda.observed_results.items()))[1]

        sp_value = reach_definition_at_main.get_sp()

        self.assertEqual(sp_value, LiveDefinitions.INITIAL_SP_64BIT)

    def test_dep_graph(self):
        project = angr.Project(_binary_path("true"), auto_load_libs=False)
        cfg = project.analyses[CFGFast].prep()()
        main_func = cfg.functions["main"]

        # build a def-use graph for main() of /bin/true without tmps.
        # check that the only dependency of the first block's
        # guard is the four cc registers
        rda = project.analyses[ReachingDefinitionsAnalysis].prep()(
            subject=main_func, track_tmps=False, track_consts=False, dep_graph=True
        )
        guard_use = next(
            filter(
                lambda def_: type(def_.atom) is GuardUse and def_.codeloc.block_addr == main_func.addr,
                rda.dep_graph._graph.nodes(),
            )
        )
        preds = list(rda.dep_graph._graph.pred[guard_use])
        self.assertEqual(len(preds), 1)
        self.assertIsInstance(preds[0].atom, Register)
        self.assertEqual(
            preds[0].atom.reg_offset,
            project.arch.registers["rdi"][0],
        )

        # build a def-use graph for main() of /bin/true. check that t7 in the first block is only used by the guard
        rda = project.analyses[ReachingDefinitionsAnalysis].prep()(
            subject=main_func, track_tmps=True, dep_graph=DepGraph()
        )
        tmp_7 = next(
            filter(
                lambda def_: type(def_.atom) is Tmp
                and def_.atom.tmp_idx == 7
                and def_.codeloc.block_addr == main_func.addr,
                rda.dep_graph._graph.nodes(),
            )
        )
        self.assertEqual(len(rda.dep_graph._graph.succ[tmp_7]), 1)
        self.assertEqual(type(next(iter(rda.dep_graph._graph.succ[tmp_7])).atom), GuardUse)

    def test_dep_graph_stack_variables(self):
        bin_path = _binary_path("fauxware")
        project = angr.Project(bin_path, auto_load_libs=False)
        arch = project.arch
        cfg = project.analyses[CFGFast].prep()()
        main_func = cfg.functions["authenticate"]

        rda: ReachingDefinitionsAnalysis = project.analyses[ReachingDefinitionsAnalysis].prep()(
            subject=main_func, track_tmps=False, track_consts=False, dep_graph=True
        )
        dep_graph = rda.dep_graph
        open_rdi = next(
            iter(
                filter(
                    lambda def_: isinstance(def_.atom, Register)
                    and def_.atom.reg_offset == arch.registers["rdi"][0]
                    and def_.codeloc.ins_addr == 0x4006A2,
                    dep_graph._graph.nodes(),
                )
            )
        )

        # 4006A2     mov  rdi, rax
        preds = list(dep_graph._graph.predecessors(open_rdi))
        self.assertEqual(len(preds), 1)
        rax: Definition = preds[0]
        self.assertIsInstance(rax.atom, Register)
        self.assertEqual(rax.atom.reg_offset, arch.registers["rax"][0])
        self.assertEqual(rax.codeloc.ins_addr, 0x400699)

        # 400699     mov  rax, [rbp+file]
        preds = list(dep_graph._graph.predecessors(rax))
        self.assertEqual(len(preds), 1)
        file_var: Definition = preds[0]
        self.assertIsInstance(file_var.atom, MemoryLocation)
        self.assertIsInstance(file_var.atom.addr, SpOffset)
        self.assertEqual(file_var.atom.addr.offset, -32)
        self.assertEqual(file_var.codeloc.ins_addr, 0x40066C)

        # 40066C     mov  [rbp+file], rdi
        preds = list(dep_graph._graph.predecessors(file_var))
        self.assertEqual(len(preds), 1)
        rdi: Definition = preds[0]
        self.assertIsInstance(rdi.atom, Register)
        self.assertEqual(rdi.atom.reg_offset, arch.registers["rdi"][0])
        self.assertIsInstance(rdi.codeloc, ExternalCodeLocation)

    def test_uses_function_call_arguments(self):
        bin_path = _binary_path("fauxware")
        project = angr.Project(bin_path, auto_load_libs=False)
        arch = project.arch
        cfg = project.analyses[CFGFast].prep()()
        main_func = cfg.functions["main"]

        project.analyses[CompleteCallingConventionsAnalysis].prep()(recover_variables=True)
        rda = project.analyses[ReachingDefinitionsAnalysis].prep()(subject=main_func, track_tmps=False)

        # 4007ae
        # rsi and rdi are all used by authenticate()
        code_location = CodeLocation(0x4007A0, DEFAULT_STATEMENT, ins_addr=0x4007AE)
        uses = rda.all_uses.get_uses_by_location(code_location)
        self.assertEqual(len(uses), 2)
        auth_rdi = next(
            iter(
                filter(
                    lambda def_: isinstance(def_.atom, Register) and def_.atom.reg_offset == arch.registers["rdi"][0],
                    uses,
                )
            )
        )
        auth_rsi = next(
            iter(
                filter(
                    lambda def_: isinstance(def_.atom, Register) and def_.atom.reg_offset == arch.registers["rsi"][0],
                    uses,
                )
            )
        )

        # 4007AB mov     rdi, rax
        self.assertEqual(auth_rdi.codeloc.ins_addr, 0x4007AB)

        # 4007A8 mov     rsi, rdx
        self.assertEqual(auth_rsi.codeloc.ins_addr, 0x4007A8)

    def test_rda_on_a_block_without_cfg(self):
        bin_path = _binary_path("fauxware")
        project = angr.Project(bin_path, auto_load_libs=False)

        block = project.factory.block(project.entry, cross_insn_opt=False)
        _ = project.analyses[ReachingDefinitionsAnalysis].prep()(subject=block, track_tmps=False)  # it should not crash

    def test_partial_register_read(self):
        bin_path = _binary_path("fauxware")
        project = angr.Project(bin_path, auto_load_libs=False)
        cfg = project.analyses[CFGFast].prep()()
        rda = project.analyses[ReachingDefinitionsAnalysis].prep()(subject=cfg.kb.functions["main"], observe_all=True)
        mv = rda.model.observed_results[("insn", 0x400765, OP_BEFORE)].registers.load(
            project.arch.registers["edx"][0],
            size=4,
            endness=project.arch.register_endness,
        )
        assert claripy.is_true(mv.one_value() == claripy.BVV(1, 32))

    def test_conditional_return(self):
        bin_path = _binary_path("check_dap", arch="armel")
        project = angr.Project(bin_path, auto_load_libs=False)
        cfg = project.analyses[CFGFast].prep()(normalize=True)
        rda = project.analyses[ReachingDefinitionsAnalysis].prep()(subject=cfg.kb.functions[0x93E0], observe_all=True)
        sp_0 = rda.model.observed_results[("insn", 0x9410, OP_BEFORE)].registers.load(
            project.arch.sp_offset,
            size=4,
            endness=project.arch.register_endness,
        )
        sp_1 = rda.model.observed_results[("insn", 0x9410, OP_AFTER)].registers.load(
            project.arch.sp_offset,
            size=4,
            endness=project.arch.register_endness,
        )
        assert sp_0 == sp_1

    def test_constants_not_stored_to_live_memory_defs(self):
        # Ensure constants loaded from read-only sections are not stored back to memory definitions. If they are stored,
        # we may accidentally pair them with TOP during state merging.
        project = angr.Project(_binary_path("two_cond_func_call_with_const_arg", "armel"), auto_load_libs=False)
        project.analyses.CFGFast()
        project.analyses.CompleteCallingConventions(recover_variables=True)
        rda = project.analyses.ReachingDefinitions("main", observe_all=True)

        for info in rda.callsites_to("f"):
            (defn,) = info.args_defns[0]
            ld = rda.model.get_observation_by_insn(info.callsite, ObservationPointType.OP_BEFORE)

            # Expect a singular mem predecessor
            preds = rda.dep_graph.find_all_predecessors(defn, kind=AtomKind.MEMORY)
            assert len(preds) == 1

            # Verify not stored
            with self.assertRaises(angr.errors.SimMemoryMissingError):
                atom = preds[0].atom
                ld.memory.load(atom.addr, atom.size)

            # Verify expected constant value
            assert ld.get_concrete_value_from_definition(defn) == 1337


if __name__ == "__main__":
    main()

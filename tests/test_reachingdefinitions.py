# Disable some pylint warnings: no-self-use, missing-docstring
# pylint: disable=R0201, C0111

import logging
import os
import pickle
import random

from unittest import TestCase
import nose

import ailment
import angr
import archinfo
from angr.knowledge_plugins.key_definitions.atoms import GuardUse, Tmp, Register, MemoryLocation
from angr.knowledge_plugins.key_definitions.constants import OP_BEFORE, OP_AFTER
from angr.knowledge_plugins.key_definitions.live_definitions import Definition, SpOffset
from angr.analyses.reaching_definitions.external_codeloc import ExternalCodeLocation, CodeLocation
from angr.analyses.reaching_definitions.rd_state import ReachingDefinitionsState
from angr.analyses.reaching_definitions.subject import Subject, SubjectType
from angr.analyses.reaching_definitions.dep_graph import DepGraph
from angr.utils.constants import DEFAULT_STATEMENT
from angr.block import Block

LOGGER = logging.getLogger('test_reachingdefinitions')

TESTS_LOCATION = os.path.join(
    os.path.dirname(os.path.realpath(__file__)),
    '..', '..', 'binaries', 'tests'
)


class InsnAndNodeObserveTestingUtils():
    @staticmethod
    def assert_equals_for_live_definitions(live_definition_1, live_definition_2):
        list(map(
            lambda attr: {
                nose.tools.assert_equals(getattr(live_definition_1, attr),
                                         getattr(live_definition_2, attr))
            },
            ["register_definitions", "stack_definitions", "memory_definitions", "tmp_definitions"]
        ))

    @staticmethod
    def filter(observed_results, observation_points):
        # Return only the observed results associated with the observation points,
        # and do not fail if an observation point do not appear in the observed results.
        return list(map(
            lambda key: observed_results[key],
            filter(
                lambda key: key in observed_results,
                observation_points
            )
        ))

    @staticmethod
    def setup(observation_points):
        binary_path = os.path.join(TESTS_LOCATION, 'x86_64', 'all')
        project = angr.Project(binary_path, load_options={'auto_load_libs': False})
        cfg = project.analyses.CFGFast()

        main_function = cfg.kb.functions['main']
        reaching_definitions = project.analyses.ReachingDefinitions(
            subject=main_function, observation_points=observation_points
        )

        state = ReachingDefinitionsState(
           project.arch, reaching_definitions.subject,
        )

        return project, main_function, reaching_definitions, state


class ReachingDefinitionsAnalysisTest(TestCase):
    def _run_reaching_definition_analysis_test(self, project, function, result_path, _extract_result):
        tmp_kb = angr.KnowledgeBase(project)
        reaching_definition = project.analyses.ReachingDefinitions(
            subject=function, kb=tmp_kb, observe_all=True
        )

        result = _extract_result(reaching_definition)

        # Uncomment these to regenerate the reference results... if you dare
        #with open(result_path, 'wb') as result_file:
        #    pickle.dump(result, result_file)
        with open(result_path, 'rb') as result_file:
            expected_result = pickle.load(result_file)

        nose.tools.assert_list_equal(result, expected_result)

    def _binary_path(self, binary_name):
        return os.path.join(TESTS_LOCATION, 'x86_64', binary_name)

    def _result_path(self, binary_results_name):
        return os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            'reachingdefinitions_results',
            'x86_64',
            binary_results_name + '.pickle'
        )

    def test_reaching_definition_analysis_definitions(self):
        def _result_extractor(rda):
            unsorted_result = map(
                lambda x: {'key': x[0],
                           'register_definitions': x[1].register_definitions._storage,
                           'stack_definitions': x[1].stack_definitions._storage,
                           'memory_definitions': x[1].memory_definitions._storage},
                rda.observed_results.items()
            )
            return list(sorted(
                unsorted_result,
                key=lambda x: x['key']
            ))

        binaries_and_results = list(map(
            lambda binary: (self._binary_path(binary), self._result_path(binary + '_definitions')),
            ['all', 'fauxware', 'loop']
        ))

        for binary, result_path in binaries_and_results:
            project = angr.Project(binary, load_options={'auto_load_libs': False})
            cfg = project.analyses.CFGFast()
            function = cfg.kb.functions['main']

            self._run_reaching_definition_analysis_test(project, function, result_path, _result_extractor)

    def test_reaching_definition_analysis_visited_blocks(self):
        def _result_extractor(rda):
            return list(sorted(rda.visited_blocks, key=lambda b: b.addr))

        binaries_and_results = list(map(
            lambda binary: (self._binary_path(binary), self._result_path(binary + '_visited_blocks')),
            ['all', 'fauxware', 'loop']
        ))

        for binary, result_path in binaries_and_results:
            project = angr.Project(binary, load_options={'auto_load_libs': False})
            cfg = project.analyses.CFGFast()
            function = cfg.kb.functions['main']

            self._run_reaching_definition_analysis_test(project, function, result_path, _result_extractor)

    def test_node_observe(self):
        # Create several different observation points
        observation_points = [('node', 0x42, OP_AFTER), ('insn', 0x43, OP_AFTER)]

        _, _, reaching_definition, state =\
            InsnAndNodeObserveTestingUtils.setup(observation_points)

        reaching_definition.node_observe(0x42, state, OP_AFTER)

        results = InsnAndNodeObserveTestingUtils.filter(
            reaching_definition.observed_results,
            observation_points
        )
        expected_results = [state.live_definitions]

        nose.tools.assert_equals(results, expected_results)

    def test_insn_observe_an_ailment_statement(self):
        # Create several different observation points
        observation_points = [('node', 0x42, OP_AFTER), ('insn', 0x43, OP_AFTER)]

        _, main_function, reaching_definition, state =\
            InsnAndNodeObserveTestingUtils.setup(observation_points)

        # Here, the statement content does not matter, neither if it is really in the block or else…
        statement = ailment.statement.DirtyStatement(0, None)
        block = main_function._addr_to_block_node[main_function.addr] # pylint: disable=W0212

        reaching_definition.insn_observe(0x43, statement, block, state, OP_AFTER)

        results = InsnAndNodeObserveTestingUtils.filter(
            reaching_definition.observed_results,
            observation_points
        )
        expected_results = [state]

        nose.tools.assert_greater(len(results), 0)
        list(map(
            lambda x: InsnAndNodeObserveTestingUtils.assert_equals_for_live_definitions(x[0], x[1]),
            zip(results, expected_results)
        ))

    def test_insn_observe_before_an_imark_pyvex_statement(self):
        # Create several different observation points
        observation_points = [('node', 0x42, OP_AFTER), ('insn', 0x43, OP_BEFORE)]

        project, main_function, reaching_definition, state =\
            InsnAndNodeObserveTestingUtils.setup(observation_points)

        code_block = main_function._addr_to_block_node[main_function.addr] # pylint: disable=W0212
        block = Block(addr=0x43, byte_string=code_block.bytestr, project=project)
        statement = block.vex.statements[0]

        reaching_definition.insn_observe(0x43, statement, block, state, OP_BEFORE)

        results = InsnAndNodeObserveTestingUtils.filter(
            reaching_definition.observed_results,
            observation_points
        )
        expected_results = [state]

        nose.tools.assert_greater(len(results), 0)
        list(map(
            lambda x: InsnAndNodeObserveTestingUtils.assert_equals_for_live_definitions(x[0], x[1]),
            zip(results, expected_results)
        ))

    def test_insn_observe_after_a_pyvex_statement(self):
        # Create several different observation points
        observation_points = [('node', 0x42, OP_AFTER), ('insn', 0x43, OP_AFTER)]

        project, main_function, reaching_definition, state =\
            InsnAndNodeObserveTestingUtils.setup(observation_points)

        code_block = main_function._addr_to_block_node[main_function.addr] # pylint: disable=W0212
        block = Block(addr=0x43, byte_string=code_block.bytestr, project=project)
        # When observing OP_AFTER an instruction, the statement has to be the last of a block
        # (or preceding an IMark)
        statement = block.vex.statements[-1]

        reaching_definition.insn_observe(0x43, statement, block, state, OP_AFTER)

        results = InsnAndNodeObserveTestingUtils.filter(
            reaching_definition.observed_results,
            observation_points
        )
        expected_results = [state]

        nose.tools.assert_greater(len(results), 0)
        list(map(
            lambda x: InsnAndNodeObserveTestingUtils.assert_equals_for_live_definitions(x[0], x[1]),
            zip(results, expected_results)
        ))

    def test_reaching_definition_analysis_exposes_its_subject(self):
        binary_path = os.path.join(TESTS_LOCATION, 'x86_64', 'all')
        project = angr.Project(binary_path, load_options={'auto_load_libs': False})
        cfg = project.analyses.CFGFast()

        main_function = cfg.kb.functions['main']
        reaching_definitions = project.analyses.ReachingDefinitions(
            subject=main_function
        )

        nose.tools.assert_equals(reaching_definitions.subject.__class__ is Subject, True)


class LiveDefinitionsTest(TestCase):
    class _MockFunctionSubject:
        class _MockFunction:
            def __init__(self):
                self.addr = 0x42

        def __init__(self):
            self.type = SubjectType.Function
            self.cc = None
            self.content = self._MockFunction()

    def test_initializing_live_definitions_for_ppc_without_rtoc_value_should_raise_an_error(self):
        arch = archinfo.arch_ppc64.ArchPPC64()
        nose.tools.assert_raises(
           ValueError,
           ReachingDefinitionsState, arch=arch, subject=self._MockFunctionSubject()
        )

    def test_initializing_live_definitions_for_ppc_with_rtoc_value(self):
        arch = archinfo.arch_ppc64.ArchPPC64()
        rtoc_value = random.randint(0, 0xffffffffffffffff)

        live_definition = ReachingDefinitionsState(
           arch=arch, subject=self._MockFunctionSubject(), rtoc_value=rtoc_value
        )

        rtoc_offset = arch.registers['rtoc'][0]
        rtoc_definition = next(iter(
            live_definition.register_definitions.get_objects_by_offset(rtoc_offset)
        ))
        rtoc_definition_value = rtoc_definition.data.get_first_element()

        nose.tools.assert_equals(rtoc_definition_value, rtoc_value)

    def test_get_the_sp_from_a_reaching_definition(self):
        binary = os.path.join(TESTS_LOCATION, 'x86_64', 'all')
        project = angr.Project(binary, auto_load_libs=False)
        cfg = project.analyses.CFGFast()

        tmp_kb = angr.KnowledgeBase(project)
        main_func = cfg.kb.functions['main']
        rda = project.analyses.ReachingDefinitions(
            subject=main_func, kb=tmp_kb, observe_all=True
        )

        def _is_right_before_main_node(definition):
            bloc, ins_addr, op_type = definition[0]
            return (
                bloc == 'node' and
                ins_addr == main_func.addr and
                op_type == OP_BEFORE
            )

        reach_definition_at_main = next(filter(
            _is_right_before_main_node,
            rda.observed_results.items()
        ))[1]

        sp_value = reach_definition_at_main.get_sp()

        nose.tools.assert_equal(sp_value, SpOffset(project.arch.bits, 0))


def test_dep_graph():
    project = angr.Project(os.path.join(TESTS_LOCATION, 'x86_64', 'true'), auto_load_libs=False)
    cfg = project.analyses.CFGFast()
    main = cfg.functions['main']

    # build a def-use graph for main() of /bin/true without tmps. check that the only dependency of the first block's
    # guard is the four cc registers
    rda = project.analyses.ReachingDefinitions(subject=main, track_tmps=False, dep_graph=DepGraph())
    guard_use = list(filter(
        lambda def_: type(def_.atom) is GuardUse and def_.codeloc.block_addr == main.addr,
        rda.dep_graph._graph.nodes()
    ))[0]
    preds = list(rda.dep_graph._graph.pred[guard_use])
    nose.tools.assert_equal(
        len(preds),
        1
    )
    nose.tools.assert_is_instance(
        preds[0].atom,
        Register
    )
    nose.tools.assert_equal(
        preds[0].atom.reg_offset,
        project.arch.registers['rdi'][0],
    )

    # build a def-use graph for main() of /bin/true. check that t7 in the first block is only used by the guard
    rda = project.analyses.ReachingDefinitions(subject=main, track_tmps=True, dep_graph=DepGraph())
    tmp_7 = list(filter(
        lambda def_: type(def_.atom) is Tmp and def_.atom.tmp_idx == 7 and def_.codeloc.block_addr == main.addr,
        rda.dep_graph._graph.nodes()
    ))[0]
    nose.tools.assert_equal(
        len(rda.dep_graph._graph.succ[tmp_7]),
        1
    )
    nose.tools.assert_equal(
        type(list(rda.dep_graph._graph.succ[tmp_7])[0].atom),
        GuardUse
    )


def test_dep_graph_stack_variables():
    bin_path = os.path.join(TESTS_LOCATION, 'x86_64', 'fauxware')
    project = angr.Project(bin_path, auto_load_libs=False)
    arch = project.arch
    cfg = project.analyses.CFGFast()
    auth = cfg.functions['authenticate']

    rda = project.analyses.ReachingDefinitions(subject=auth, track_tmps=False, dep_graph=DepGraph())
    dep_graph = rda.dep_graph
    open_rdi = next(iter(filter(
        lambda def_: isinstance(def_.atom, Register) and def_.atom.reg_offset == arch.registers['rdi'][0]
                     and def_.codeloc.ins_addr == 0x4006a2,
        dep_graph._graph.nodes()
    )))

    # 4006A2     mov  rdi, rax
    preds = list(dep_graph._graph.predecessors(open_rdi))
    assert len(preds) == 1
    rax: Definition = preds[0]
    assert isinstance(rax.atom, Register)
    assert rax.atom.reg_offset == arch.registers['rax'][0]
    assert rax.codeloc.ins_addr == 0x400699

    # 400699     mov  rax, [rbp+file]
    preds = list(dep_graph._graph.predecessors(rax))
    assert len(preds) == 1
    file_var: Definition = preds[0]
    assert isinstance(file_var.atom, MemoryLocation)
    assert isinstance(file_var.atom.addr, SpOffset)
    assert file_var.atom.addr.offset == -32
    assert file_var.codeloc.ins_addr == 0x40066c

    # 40066C     mov  [rbp+file], rdi
    preds = list(dep_graph._graph.predecessors(file_var))
    assert len(preds) == 1
    rdi: Definition = preds[0]
    assert isinstance(rdi.atom, Register)
    assert rdi.atom.reg_offset == arch.registers['rdi'][0]
    assert isinstance(rdi.codeloc, ExternalCodeLocation)


def test_uses_function_call_arguments():
    bin_path = os.path.join(TESTS_LOCATION, 'x86_64', 'fauxware')
    project = angr.Project(bin_path, auto_load_libs=False)
    arch = project.arch
    cfg = project.analyses.CFGFast()
    main = cfg.functions['main']

    project.analyses.CompleteCallingConventions(recover_variables=True)
    rda = project.analyses.ReachingDefinitions(subject=main, track_tmps=False)

    # 4007ae
    # rsi and rdi are all used by authenticate()
    uses = rda.all_uses.get_uses_by_location(CodeLocation(0x4007a0, DEFAULT_STATEMENT))
    assert len(uses) == 2
    auth_rdi = next(iter(filter(
        lambda def_: isinstance(def_.atom, Register) and def_.atom.reg_offset == arch.registers['rdi'][0],
        uses
    )))
    auth_rsi = next(iter(filter(
        lambda def_: isinstance(def_.atom, Register) and def_.atom.reg_offset == arch.registers['rsi'][0],
        uses
    )))

    # 4007AB mov     rdi, rax
    assert auth_rdi.codeloc.ins_addr == 0x4007ab

    # 4007A8 mov     rsi, rdx
    assert auth_rsi.codeloc.ins_addr == 0x4007a8


if __name__ == '__main__':
    #LOGGER.setLevel(logging.DEBUG)
    #logging.getLogger('angr.analyses.reaching_definitions').setLevel(logging.DEBUG)

    # nose.core.runmodule()
    test_dep_graph_stack_variables()

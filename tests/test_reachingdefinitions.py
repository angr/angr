# Disable some pylint warnings: no-self-use, missing-docstring
# pylint: disable=R0201, C0111

import logging
import os
import pickle
import random

from unittest import mock, TestCase
import nose

import ailment
import angr
import archinfo
from angr.analyses.reaching_definitions import ReachingDefinitionsAnalysis
from angr.analyses.reaching_definitions.live_definitions import LiveDefinitions
from angr.analyses.reaching_definitions.constants import OP_BEFORE, OP_AFTER
from angr.analyses.reaching_definitions.atoms import GuardUse, Tmp, Register

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
            lambda attr: {\
                nose.tools.assert_equals(getattr(live_definition_1, attr),\
                                         getattr(live_definition_2, attr))\
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
        reaching_definition = project.analyses.ReachingDefinitions(
            subject=main_function, init_func=True, observation_points=observation_points
        )

        state = LiveDefinitions(project.arch, project.loader)

        return (project, main_function, reaching_definition, state)


class ReachingDefinitionsAnalysisTest(TestCase):
    def _run_reaching_definition_analysis_test(self, project, function, result_path, _extract_result):
        tmp_kb = angr.KnowledgeBase(project)
        reaching_definition = project.analyses.ReachingDefinitions(
            subject=function, init_func=True, kb=tmp_kb, observe_all=True
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
                lambda x: {'key': x[0],\
                           'register_definitions': x[1].register_definitions,\
                           'stack_definitions': x[1].stack_definitions,\
                           'memory_definitions': x[1].memory_definitions},
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
            return rda.visited_blocks

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
        expected_results = [state]

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
        block = angr.block.Block(addr=0x43, byte_string=code_block.bytestr, project=project)
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
        block = angr.block.Block(addr=0x43, byte_string=code_block.bytestr, project=project)
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


    def test_reaching_definition_analysis_returns_an_error_without_suject(self):
        binary_path = os.path.join(TESTS_LOCATION, 'x86_64', 'all')
        project = angr.Project(binary_path, load_options={'auto_load_libs': False})

        with nose.tools.assert_raises(ValueError) as reaching_definitions:
            project.analyses.ReachingDefinitions()

        nose.tools.assert_equal("%s" % reaching_definitions.exception, 'Unsupported analysis target.')


    @mock.patch.object(ReachingDefinitionsAnalysis, '_analyze')
    def test_reaching_definition_analysis_with_a_function_as_suject(self, _):
        binary_path = os.path.join(TESTS_LOCATION, 'x86_64', 'all')
        project = angr.Project(binary_path, load_options={'auto_load_libs': False})
        cfg = project.analyses.CFGFast()

        main_function = cfg.kb.functions['main']
        # Valuable to test that `init_func` and `cc` are assigned correctly.
        # However, set `init_func` to False so `cc` content does not get checked (which would fail here because it is
        # not supposed to be a string).
        init_func = False
        cc = "cc_mock"

        reaching_definitions = project.analyses.ReachingDefinitions(
            subject=main_function, init_func=init_func, cc=cc
        )

        nose.tools.assert_equal(reaching_definitions._function, main_function)
        nose.tools.assert_equal(reaching_definitions._block, None)
        nose.tools.assert_equal(reaching_definitions._init_func, init_func)
        nose.tools.assert_equal(reaching_definitions._cc, cc)


    def test_reaching_definition_analysis_with_a_block_as_subject(self):
        binary_path = os.path.join(TESTS_LOCATION, 'x86_64', 'all')
        project = angr.Project(binary_path, load_options={'auto_load_libs': False})
        cfg = project.analyses.CFGFast()

        main_function = cfg.kb.functions['main']
        main_block = Block(addr=main_function.addr, project=project)

        reaching_definitions = project.analyses.ReachingDefinitions(subject=main_block)

        nose.tools.assert_equal(reaching_definitions._function, None)
        nose.tools.assert_equal(reaching_definitions._block, main_block)
        nose.tools.assert_equal(reaching_definitions._init_func, False)
        nose.tools.assert_equal(reaching_definitions._cc, None)


class LiveDefinitionsTest(TestCase):
    def test_initializing_live_definitions_for_ppc_without_rtoc_value_should_raise_an_error(self):
        arch = archinfo.arch_ppc64.ArchPPC64()
        nose.tools.assert_raises(ValueError, LiveDefinitions, arch=arch, init_func=True)


    def test_initializing_live_definitions_for_ppc_with_rtoc_value(self):
        arch = archinfo.arch_ppc64.ArchPPC64()
        rtoc_value = random.randint(0, 0xffffffffffffffff)
        live_definition = LiveDefinitions(arch=arch, init_func=True, rtoc_value=rtoc_value)

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
            subject=main_func, init_func=True, kb=tmp_kb, observe_all=True
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

        nose.tools.assert_equal(sp_value, project.arch.initial_sp)

def test_def_use_graph():
    project = angr.Project(os.path.join(TESTS_LOCATION, 'x86_64', 'true'), auto_load_libs=False)
    cfg = project.analyses.CFGFast()
    main = cfg.functions['main']

    # build a def-use graph for main() of /bin/true without tmps. check that the only dependency of the first block's guard is the four cc registers
    rda = project.analyses.ReachingDefinitions(subject=main, track_tmps=False)
    guard_use = list(filter(
        lambda def_: type(def_.atom) is GuardUse and def_.codeloc.block_addr == main.addr,
        rda.def_use_graph.nodes()
    ))[0]
    nose.tools.assert_equal(
        len(rda.def_use_graph.pred[guard_use]),
        4
    )
    nose.tools.assert_equal(
        all(type(def_.atom) is Register for def_ in rda.def_use_graph.pred[guard_use]),
        True
    )
    nose.tools.assert_equal(
        set(def_.atom.reg_offset for def_ in rda.def_use_graph.pred[guard_use]),
        {reg.vex_offset for reg in project.arch.register_list if reg.name.startswith('cc_')}
    )

    # build a def-use graph for main() of /bin/true. check that t7 in the first block is only used by the guard
    rda = project.analyses.ReachingDefinitions(subject=main, track_tmps=True)
    tmp_7 = list(filter(
        lambda def_: type(def_.atom) is Tmp and def_.atom.tmp_idx == 7 and def_.codeloc.block_addr == main.addr,
        rda.def_use_graph.nodes()
    ))[0]
    nose.tools.assert_equal(
        len(rda.def_use_graph.succ[tmp_7]),
        1
    )
    nose.tools.assert_equal(
        type(list(rda.def_use_graph.succ[tmp_7])[0].atom),
        GuardUse
    )


if __name__ == '__main__':
    LOGGER.setLevel(logging.DEBUG)
    logging.getLogger('angr.analyses.reaching_definitions').setLevel(logging.DEBUG)

    nose.core.runmodule()

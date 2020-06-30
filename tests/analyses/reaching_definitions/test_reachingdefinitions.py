# Disable some pylint warnings: no-self-use, missing-docstring
# pylint: disable=R0201, C0111

import os
import pickle
from unittest import TestCase

import ailment
import angr
from angr.code_location import CodeLocation
from angr.analyses.reaching_definitions.external_codeloc import ExternalCodeLocation
from angr.analyses.reaching_definitions.rd_state import ReachingDefinitionsState
from angr.analyses.reaching_definitions.subject import Subject
from angr.analyses.reaching_definitions.dep_graph import DepGraph
from angr.analyses.cfg_slice_to_sink import CFGSliceToSink
from angr.block import Block
from angr.knowledge_plugins.key_definitions.atoms import GuardUse, Tmp, Register, MemoryLocation
from angr.knowledge_plugins.key_definitions.constants import OP_BEFORE, OP_AFTER
from angr.knowledge_plugins.key_definitions.live_definitions import Definition, SpOffset
from angr.utils.constants import DEFAULT_STATEMENT

class InsnAndNodeObserveTestingUtils():
    @staticmethod
    def assert_for_live_definitions(assertion, live_definition_1, live_definition_2):
        list(map(
            lambda attr: {\
                assertion(getattr(live_definition_1, attr),\
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
        binary_path = _binary_path('all')
        project = angr.Project(binary_path, load_options={'auto_load_libs': False})
        cfg = project.analyses.CFGFast()

        main_function = cfg.kb.functions['main']
        reaching_definitions = project.analyses.ReachingDefinitions(
            subject=main_function, observation_points=observation_points
        )

        state = ReachingDefinitionsState(
           project.arch, reaching_definitions.subject, project.loader
        )

        return (project, main_function, reaching_definitions, state)


def _binary_path(binary_name):
    tests_location = os.path.join(
        os.path.dirname(os.path.realpath(__file__)),
        '..', '..', '..', '..', 'binaries', 'tests'
    )
    return os.path.join(tests_location, 'x86_64', binary_name)

def _result_path(binary_results_name):
    return os.path.join(
        os.path.dirname(os.path.realpath(__file__)),
        'results',
        'x86_64',
        binary_results_name + '.pickle'
    )

class TestReachingDefinitions(TestCase):
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

        self.assertListEqual(result, expected_result)

    def test_reaching_definition_analysis_definitions(self):
        def _result_extractor(rda):
            unsorted_result = map(
                lambda x: {'key': x[0],\
                           'register_definitions': x[1].register_definitions._storage,\
                           'stack_definitions': x[1].stack_definitions._storage,\
                           'memory_definitions': x[1].memory_definitions._storage},
                rda.observed_results.items()
            )
            return list(sorted(
                unsorted_result,
                key=lambda x: x['key']
            ))

        binaries_and_results = list(map(
            lambda binary: (_binary_path(binary), _result_path(binary + '_definitions')),
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
            lambda binary: (_binary_path(binary), _result_path(binary + '_visited_blocks')),
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

        self.assertEqual(results, expected_results)

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

        self.assertGreater(len(results), 0)
        list(map(
            lambda x: InsnAndNodeObserveTestingUtils.assert_for_live_definitions(self.assertEqual, x[0], x[1]),
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

        self.assertGreater(len(results), 0)
        list(map(
            lambda x: InsnAndNodeObserveTestingUtils.assert_for_live_definitions(self.assertEqual, x[0], x[1]),
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
        expected_results = [state.live_definitions]

        self.assertGreater(len(results), 0)
        list(map(
            lambda x: InsnAndNodeObserveTestingUtils.assert_for_live_definitions(self.assertEqual, x[0], x[1]),
            zip(results, expected_results)
        ))

    def test_init_the_call_stack_with_a_block_as_subject_add_its_owning_function_to_the_call_stack(self):
        binary_path = _binary_path('all')
        project = angr.Project(binary_path, load_options={'auto_load_libs': False})
        cfg = project.analyses.CFGFast()

        _start = cfg.kb.functions['_start']
        __libc_start_main = cfg.kb.functions['__libc_start_main']
        call_stack = [ _start.addr, __libc_start_main.addr ]

        main_function = cfg.kb.functions['main']
        main_address = main_function.addr
        main_block = Block(addr=main_address, project=project)

        reaching_definitions = project.analyses.ReachingDefinitions(subject=main_block, call_stack=call_stack)
        expected_call_stack = call_stack + [ main_function.addr ]

        self.assertEqual(reaching_definitions._call_stack, expected_call_stack)

    def test_init_the_call_stack_with_another_block_as_subject_does_not_deepen_the_call_stack(self):
        binary_path = _binary_path('all')
        project = angr.Project(binary_path, load_options={'auto_load_libs': False})
        cfg = project.analyses.CFGFast()

        _start = cfg.kb.functions['_start']
        __libc_start_main = cfg.kb.functions['__libc_start_main']
        initial_call_stack = [ _start.addr, __libc_start_main.addr ]

        main_function = cfg.kb.functions['main']
        main_address = main_function.addr
        main_block = Block(addr=main_address, project=project)
        another_block_in_main = Block(addr=0x4006fd, project=project)

        new_call_stack = project.analyses.ReachingDefinitions(
            subject=main_block,
            call_stack=initial_call_stack
        )._call_stack

        reaching_definitions = project.analyses.ReachingDefinitions(
            subject=another_block_in_main,
            call_stack=new_call_stack
        )
        expected_call_stack = initial_call_stack + [ main_function.addr ]

        self.assertEqual(reaching_definitions._call_stack, expected_call_stack)

    def test_init_the_call_stack_with_a_function_as_subject_adds_it_to_the_call_stack(self):
        binary_path = _binary_path('all')
        project = angr.Project(binary_path, load_options={'auto_load_libs': False})
        cfg = project.analyses.CFGFast()

        _start = cfg.kb.functions['_start']
        __libc_start_main = cfg.kb.functions['__libc_start_main']
        initial_call_stack = [ _start.addr, __libc_start_main.addr ]

        main_function = cfg.kb.functions['main']

        reaching_definitions = project.analyses.ReachingDefinitions(
            subject=main_function,
            call_stack=initial_call_stack
        )
        expected_call_stack = initial_call_stack + [ main_function.addr ]

        self.assertEqual(reaching_definitions._call_stack, expected_call_stack)

    def test_init_the_call_stack_with_a_slice_as_subject_does_not_change_the_call_stack(self):
        binary_path = _binary_path('all')
        project = angr.Project(binary_path, load_options={'auto_load_libs': False})

        initial_call_stack = [ ]

        reaching_definitions = project.analyses.ReachingDefinitions(
            subject=CFGSliceToSink(None, {}),
            call_stack=initial_call_stack
        )

        self.assertEqual(reaching_definitions._call_stack, initial_call_stack)

    def test_reaching_definition_analysis_exposes_its_subject(self):
        binary_path = _binary_path('all')
        project = angr.Project(binary_path, load_options={'auto_load_libs': False})
        cfg = project.analyses.CFGFast()

        main_function = cfg.kb.functions['main']
        reaching_definitions = project.analyses.ReachingDefinitions(
            subject=main_function
        )

        self.assertEqual(reaching_definitions.subject.__class__ is Subject, True)

    def test_get_the_sp_from_a_reaching_definition(self):
        binary = _binary_path('all')
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

        self.assertEqual(sp_value, SpOffset(project.arch.bits, 0))

    def test_dep_graph(self):
        project = angr.Project(_binary_path('true'), auto_load_libs=False)
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
        self.assertEqual(
            len(preds),
            1
        )
        self.assertIsInstance(
            preds[0].atom,
            Register
        )
        self.assertEqual(
            preds[0].atom.reg_offset,
            project.arch.registers['rdi'][0],
        )

        # build a def-use graph for main() of /bin/true. check that t7 in the first block is only used by the guard
        rda = project.analyses.ReachingDefinitions(subject=main, track_tmps=True, dep_graph=DepGraph())
        tmp_7 = list(filter(
            lambda def_: type(def_.atom) is Tmp and def_.atom.tmp_idx == 7 and def_.codeloc.block_addr == main.addr,
            rda.dep_graph._graph.nodes()
        ))[0]
        self.assertEqual(
            len(rda.dep_graph._graph.succ[tmp_7]),
            1
        )
        self.assertEqual(
            type(list(rda.dep_graph._graph.succ[tmp_7])[0].atom),
            GuardUse
        )

    def test_dep_graph_stack_variables(self):
        bin_path = _binary_path('fauxware')
        project = angr.Project(bin_path, auto_load_libs=False)
        arch = project.arch
        cfg = project.analyses.CFGFast()
        main = cfg.functions['authenticate']

        rda = project.analyses.ReachingDefinitions(subject=main, track_tmps=False, dep_graph=DepGraph())
        dep_graph = rda.dep_graph
        open_rdi = next(iter(filter(
            lambda def_: isinstance(def_.atom, Register) and def_.atom.reg_offset == arch.registers['rdi'][0]
                         and def_.codeloc.ins_addr == 0x4006a2,
            dep_graph._graph.nodes()
        )))

        # 4006A2     mov  rdi, rax
        preds = list(dep_graph._graph.predecessors(open_rdi))
        self.assertEqual(len(preds), 1)
        rax: Definition = preds[0]
        self.assertIsInstance(rax.atom, Register)
        self.assertEqual(rax.atom.reg_offset, arch.registers['rax'][0])
        self.assertEqual(rax.codeloc.ins_addr, 0x400699)

        # 400699     mov  rax, [rbp+file]
        preds = list(dep_graph._graph.predecessors(rax))
        self.assertEqual(len(preds), 1)
        file_var: Definition = preds[0]
        self.assertIsInstance(file_var.atom, MemoryLocation)
        self.assertIsInstance(file_var.atom.addr, SpOffset)
        self.assertEqual(file_var.atom.addr.offset, -32)
        self.assertEqual(file_var.codeloc.ins_addr, 0x40066c)

        # 40066C     mov  [rbp+file], rdi
        preds = list(dep_graph._graph.predecessors(file_var))
        self.assertEqual(len(preds), 1)
        rdi: Definition = preds[0]
        self.assertIsInstance(rdi.atom, Register)
        self.assertEqual(rdi.atom.reg_offset, arch.registers['rdi'][0])
        self.assertIsInstance(rdi.codeloc, ExternalCodeLocation)

    def test_uses_function_call_arguments(self):
        bin_path = _binary_path('fauxware')
        project = angr.Project(bin_path, auto_load_libs=False)
        arch = project.arch
        cfg = project.analyses.CFGFast()
        main = cfg.functions['main']

        project.analyses.CompleteCallingConventions(recover_variables=True)
        rda = project.analyses.ReachingDefinitions(subject=main, track_tmps=False)

        # 4007ae
        # rsi and rdi are all used by authenticate()
        context = (main.addr, )
        code_location = CodeLocation(0x4007a0, DEFAULT_STATEMENT, ins_addr=0x4007ae, context=context)
        uses = rda.all_uses.get_uses_by_location(code_location)
        self.assertEqual(len(uses), 2)
        auth_rdi = next(iter(filter(
            lambda def_: isinstance(def_.atom, Register) and def_.atom.reg_offset == arch.registers['rdi'][0],
            uses
        )))
        auth_rsi = next(iter(filter(
            lambda def_: isinstance(def_.atom, Register) and def_.atom.reg_offset == arch.registers['rsi'][0],
            uses
        )))

        # 4007AB mov     rdi, rax
        self.assertEqual(auth_rdi.codeloc.ins_addr, 0x4007ab)

        # 4007A8 mov     rsi, rdx
        self.assertEqual(auth_rsi.codeloc.ins_addr, 0x4007a8)

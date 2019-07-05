import logging
import os
import pickle
import random

import nose
import unittest
from unittest import TestCase

import archinfo
import angr
from angr.analyses.reaching_definitions import LiveDefinitions

l = logging.getLogger('test_reachingdefinitions')

TESTS_LOCATION = os.path.join(
    os.path.dirname(os.path.realpath(__file__)),
    '..', '..', 'binaries', 'tests'
)


class ReachingDefinitionAnalysisTest(TestCase):
    def _run_reaching_definition_analysis(self, project, func, result_path):
        tmp_kb = angr.KnowledgeBase(project)
        rd = project.analyses.ReachingDefinitions(func, init_func=True, kb=tmp_kb, observe_all=True)

        unsorted_result = map(
            lambda x: {'key': x[0],\
                       'register_definitions': x[1].register_definitions,\
                       'stack_definitions': x[1].stack_definitions,\
                       'memory_definitions': x[1].memory_definitions},
            rd.observed_results.items()
        )
        result = list(sorted(
            unsorted_result,
            key=lambda x: x['key']
        ))

        with open(result_path, 'rb') as f:
            expected_result = pickle.load(f)

        nose.tools.assert_list_equal(result, expected_result)


    def test_reaching_definition_analysis(self):
        def _binary_path(binary_name):
            return os.path.join(TESTS_LOCATION, 'x86_64', binary_name)
        def _result_path(binary_name):
            return os.path.join(
                os.path.dirname(os.path.realpath(__file__)),
                'reachingdefinitions_results',
                'x86_64',
                binary_name + '.pickle'
            )

        binaries_and_results = list(map(
            lambda binary: (_binary_path(binary), _result_path(binary)),
            ['all', 'fauxware', 'loop']
        ))

        for binary, result_path in binaries_and_results:
            project = angr.Project(binary, load_options={'auto_load_libs': False})
            cfg = project.analyses.CFGFast()

            yield self._run_reaching_definition_analysis, project, cfg.kb.functions['main'], result_path


class LiveDefinitionsTest(TestCase):
    def test_initializing_live_definitions_for_ppc_without_rtoc_value_should_raise_an_error(self):
        arch = archinfo.arch_ppc64.ArchPPC64()
        nose.tools.assert_raises(ValueError, LiveDefinitions, arch=arch, init_func=True)


    def test_initializing_live_definitions_for_ppc_with_rtoc_value(self):
        arch = archinfo.arch_ppc64.ArchPPC64()
        rtoc_value = random.randint(0, 0xffffffffffffffff)
        live_definition = LiveDefinitions(arch=arch, init_func=True, rtoc_value=rtoc_value)

        rtoc_offset = arch.registers['rtoc'][0]
        rtoc_definition = next(iter(live_definition.register_definitions.get_objects_by_offset(rtoc_offset)))
        rtoc_definition_value = rtoc_definition.data.get_first_element()

        nose.tools.assert_equals(rtoc_definition_value, rtoc_value)


if __name__ == '__main__':
    l.setLevel(logging.DEBUG)
    logging.getLogger('angr.analyses.reaching_definitions').setLevel(logging.DEBUG)

    nose.core.runmodule()

import os
import random

from unittest import mock, TestCase

import archinfo

from angr.analyses.reaching_definitions.heap_allocator import HeapAllocator
from angr.analyses.reaching_definitions.rd_state import ReachingDefinitionsState
from angr.analyses.reaching_definitions.subject import SubjectType
from angr.knowledge_plugins.key_definitions.live_definitions import LiveDefinitions


TESTS_LOCATION = os.path.join(
    os.path.dirname(os.path.realpath(__file__)),
    '..', '..', '..', '..', 'binaries', 'tests'
)


class _MockFunctionSubject:  # pylint:disable=too-few-public-methods
    class _MockFunction:  # pylint:disable=too-few-public-methods
        def __init__(self):
            self.addr = 0x42

    def __init__(self):
        self.type = SubjectType.Function
        self.cc = None  # pylint:disable=invalid-name
        self.content = self._MockFunction()

class TestReachingDefinitionsState(TestCase):
    def test_initializing_rd_state_for_ppc_without_rtoc_value_should_raise_an_error(self):
        arch = archinfo.arch_ppc64.ArchPPC64()
        self.assertRaises(
           ValueError,
           ReachingDefinitionsState, arch=arch, subject=_MockFunctionSubject()
        )

    def test_initializing_rd_state_for_ppc_with_rtoc_value(self):
        arch = archinfo.arch_ppc64.ArchPPC64()
        rtoc_value = random.randint(0, 0xffffffffffffffff)

        state = ReachingDefinitionsState(
           arch=arch, subject=_MockFunctionSubject(), rtoc_value=rtoc_value
        )

        rtoc_offset = arch.registers['rtoc'][0]
        rtoc_definition_value = state.register_definitions.load(rtoc_offset, size=8, endness=arch.register_endness)

        self.assertFalse(rtoc_definition_value.symbolic)
        self.assertEqual(rtoc_definition_value._model_concrete.value, rtoc_value)

    def test_rd_state_gets_a_default_heap_allocator(self):
        arch = archinfo.arch_arm.ArchARM()
        state = ReachingDefinitionsState(arch, _MockFunctionSubject())

        self.assertTrue(isinstance(state.heap_allocator, HeapAllocator))

    def test_get_sp_delegates_to_the_underlying_live_definitions(self):  # pylint:disable=no-self-use
        arch = archinfo.arch_arm.ArchARM()
        live_definitions = LiveDefinitions(arch)

        state = ReachingDefinitionsState(
           arch=arch, subject=_MockFunctionSubject(), live_definitions=live_definitions
        )

        with mock.patch.object(LiveDefinitions, 'get_sp') as live_definitions_get_sp_mock:
            state.get_sp()

            live_definitions_get_sp_mock.assert_called_once()

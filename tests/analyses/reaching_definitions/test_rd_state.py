import os
import random

from unittest import TestCase

import archinfo

from angr.analyses.reaching_definitions.heap_allocator import HeapAllocator
from angr.analyses.reaching_definitions.rd_state import ReachingDefinitionsState
from angr.analyses.reaching_definitions.subject import SubjectType


TESTS_LOCATION = os.path.join(
    os.path.dirname(os.path.realpath(__file__)),
    '..', '..', '..', '..', 'binaries', 'tests'
)


class _MockFunctionSubject:
    class _MockFunction:
        def __init__(self):
            self.addr = 0x42

    def __init__(self):
        self.type = SubjectType.Function
        self.cc = None
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
        rtoc_definition = next(iter(
            state.register_definitions.get_objects_by_offset(rtoc_offset)
        ))
        rtoc_definition_value = rtoc_definition.data.get_first_element()

        self.assertEqual(rtoc_definition_value, rtoc_value)

    def test_rd_state_gets_a_default_heap_allocator(self):
        arch = archinfo.arch_arm.ArchARM()
        state = ReachingDefinitionsState(arch, _MockFunctionSubject())

        self.assertTrue(isinstance(state.heap_allocator, HeapAllocator))

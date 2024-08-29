#!/usr/bin/env python3
from __future__ import annotations

__package__ = __package__ or "tests.analyses.reaching_definitions"  # pylint:disable=redefined-builtin

import os
import random

from unittest import main, mock, TestCase

import archinfo

from angr.analyses.reaching_definitions.heap_allocator import HeapAllocator
from angr.analyses.reaching_definitions.rd_state import ReachingDefinitionsState
from angr.analyses.reaching_definitions.subject import SubjectType
from angr.knowledge_plugins.key_definitions.live_definitions import LiveDefinitions
from angr.code_location import CodeLocation

from ...common import bin_location


TESTS_LOCATION = os.path.join(bin_location, "tests")


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
            ValueError, ReachingDefinitionsState, CodeLocation(0x42, None), arch=arch, subject=_MockFunctionSubject()
        )

    def test_initializing_rd_state_for_ppc_with_rtoc_value(self):
        arch = archinfo.arch_ppc64.ArchPPC64()
        rtoc_value = random.randint(0, 0xFFFFFFFFFFFFFFFF)

        state = ReachingDefinitionsState(
            CodeLocation(0x42, None), arch=arch, subject=_MockFunctionSubject(), rtoc_value=rtoc_value
        )

        rtoc_offset = arch.registers["rtoc"][0]
        rtoc_definition_value = state.registers.load(rtoc_offset, size=8)

        self.assertIsNotNone(rtoc_definition_value.one_value())
        v = rtoc_definition_value.one_value()
        self.assertFalse(v.symbolic)
        self.assertEqual(v.concrete_value, rtoc_value)

    def test_rd_state_gets_a_default_heap_allocator(self):
        arch = archinfo.arch_arm.ArchARM()
        state = ReachingDefinitionsState(CodeLocation(0x42, None), arch, _MockFunctionSubject())

        self.assertTrue(isinstance(state.heap_allocator, HeapAllocator))

    def test_get_sp_delegates_to_the_underlying_live_definitions(self):  # pylint:disable=no-self-use
        arch = archinfo.arch_arm.ArchARM()
        live_definitions = LiveDefinitions(arch)

        state = ReachingDefinitionsState(
            CodeLocation(0x42, None), arch=arch, subject=_MockFunctionSubject(), live_definitions=live_definitions
        )

        with mock.patch.object(LiveDefinitions, "get_sp") as live_definitions_get_sp_mock:
            state.get_sp()

            live_definitions_get_sp_mock.assert_called_once()


if __name__ == "__main__":
    main()

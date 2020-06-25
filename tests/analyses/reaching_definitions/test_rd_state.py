import os
import random

import nose

import archinfo

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


def test_initializing_rd_state_for_ppc_without_rtoc_value_should_raise_an_error():
    arch = archinfo.arch_ppc64.ArchPPC64()
    nose.tools.assert_raises(
       ValueError,
       ReachingDefinitionsState, arch=arch, subject=_MockFunctionSubject()
    )


def test_initializing_rd_state_for_ppc_with_rtoc_value():
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

    nose.tools.assert_equals(rtoc_definition_value, rtoc_value)

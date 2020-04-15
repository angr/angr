from unittest import mock

import nose

import ailment

from archinfo.arch_x86 import ArchX86
from angr.analyses.forward_analysis.visitors import FunctionGraphVisitor, CFGVisitor
from angr.analyses.reaching_definitions.subject import Subject, SubjectType
from angr.analyses.cfg_slice_to_sink import CFGSliceToSink
from angr.block import Block
from angr.knowledge_plugins import Function


def _a_mock_function(address, name):
    return Function(None, address, name=name, syscall=False, is_simprocedure=False, is_plt=False, returning=False)

@mock.patch.object(Function, '_get_initial_binary_name', return_value='binary')
def test_can_be_instantiated_with_a_function(_):
    function = _a_mock_function(0x42, 'function_name')
    subject = Subject(function, None)

    nose.tools.assert_equals(subject.content, function)
    nose.tools.assert_equals(subject.type, SubjectType.Function)


@mock.patch.object(Block, '_parse_vex_info', return_value=None)
def test_can_be_instantiated_with_a_block(_):
    arch = ArchX86()
    block = Block(0x42, byte_string=b'', arch=arch)
    subject = Subject(block, None)

    nose.tools.assert_equals(subject.content, block)
    nose.tools.assert_equals(subject.type, SubjectType.Block)


def test_can_be_instantiated_with_an_ailment_block():
    block = ailment.Block(0x42, original_size=4)
    subject = Subject(block, None)

    nose.tools.assert_equals(subject.content, block)
    nose.tools.assert_equals(subject.type, SubjectType.Block)


@mock.patch.object(CFGVisitor, 'sort_nodes')
def test_can_be_instantiated_with_a_slice(_):
    cfg_slice_to_sink = CFGSliceToSink(None, {})
    subject = Subject(cfg_slice_to_sink, None)

    nose.tools.assert_equals(subject.content, cfg_slice_to_sink)
    nose.tools.assert_equals(subject.type, SubjectType.CFGSliceToSink)


def test_fails_when_instanciated_with_an_inadequate_object():
    nose.tools.assert_raises(TypeError, Subject, 'test-me', None)


@mock.patch.object(Function, '_get_initial_binary_name', return_value='binary')
@mock.patch.object(FunctionGraphVisitor, 'sort_nodes')
def test_when_instanciated_with_a_function_need_other_attributes(_, __):
    function = _a_mock_function(0x42, 'function_name')
    func_graph = 'mock_func_graph'
    cc = 'mock_cc'

    subject = Subject(function, None, func_graph, cc)

    nose.tools.assert_equals(subject.func_graph, func_graph)
    nose.tools.assert_equals(subject.cc, cc)


def test_cc_attribute_should_raise_error_when_subject_is_a_block():
    arch = ArchX86()
    block = Block(0x42, byte_string=b'', arch=arch)
    subject = Subject(block, None)

    with nose.tools.assert_raises(TypeError):
        _ = subject.cc


def test_func_graph_attribute_should_raise_error_when_subject_is_a_block():
    arch = ArchX86()
    block = Block(0x42, byte_string=b'', arch=arch)
    subject = Subject(block, None)

    with nose.tools.assert_raises(TypeError):
        _ = subject.func_graph

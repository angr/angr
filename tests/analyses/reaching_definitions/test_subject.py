#!/usr/bin/env python3
from __future__ import annotations
from unittest import mock
import unittest

import networkx

import ailment

from archinfo.arch_x86 import ArchX86
from angr.analyses.forward_analysis.visitors import FunctionGraphVisitor
from angr.analyses.reaching_definitions.subject import Subject, SubjectType
from angr.block import Block
from angr.knowledge_plugins import Function


def _a_mock_function(address, name):
    return Function(None, address, name=name, syscall=False, is_simprocedure=False, is_plt=False, returning=False)


class TestSubject(unittest.TestCase):
    @mock.patch.object(Function, "_get_initial_binary_name", return_value="binary")
    def test_can_be_instantiated_with_a_function(self, _):
        function = _a_mock_function(0x42, "function_name")
        subject = Subject(function)

        assert subject.content == function
        assert subject.type == SubjectType.Function

    @mock.patch.object(Block, "_parse_vex_info", return_value=None)
    def test_can_be_instantiated_with_a_block(self, _):
        arch = ArchX86()
        block = Block(0x42, byte_string=b"", arch=arch)
        subject = Subject(block)

        assert subject.content == block
        assert subject.type == SubjectType.Block

    def test_can_be_instantiated_with_an_ailment_block(self):
        block = ailment.Block(0x42, original_size=4)
        subject = Subject(block)

        assert subject.content == block
        assert subject.type == SubjectType.Block

    def test_fails_when_instantiated_with_an_inadequate_object(self):
        self.assertRaises(TypeError, Subject, "test-me", None)

    @mock.patch.object(Function, "_get_initial_binary_name", return_value="binary")
    @mock.patch.object(FunctionGraphVisitor, "sort_nodes")
    def test_when_instantiated_with_a_function_need_other_attributes(self, _, __):
        function = _a_mock_function(0x42, "function_name")
        func_graph = networkx.DiGraph()
        cc = "mock_cc"

        subject = Subject(function, func_graph, cc)

        assert subject.func_graph == func_graph
        assert subject.cc == cc

    def test_cc_attribute_should_raise_error_when_subject_is_a_block(self):
        arch = ArchX86()
        block = Block(0x42, byte_string=b"", arch=arch)
        subject = Subject(block)
        with self.assertRaises(TypeError):
            _ = subject.cc

    def test_func_graph_attribute_should_raise_error_when_subject_is_a_block(self):
        arch = ArchX86()
        block = Block(0x42, byte_string=b"", arch=arch)
        subject = Subject(block)
        with self.assertRaises(TypeError):
            _ = subject.func_graph


if __name__ == "__main__":
    unittest.main()

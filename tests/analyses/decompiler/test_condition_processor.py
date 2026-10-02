#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

import unittest
from collections import OrderedDict
from unittest import TestCase

import archinfo

from angr import ailment
from angr.ailment.expression import BinaryOp, Const, Convert, Extract, Load, VirtualVariable, VirtualVariableCategory
from angr.ailment.statement import Jump
from angr.analyses.decompiler.condition_processor import ConditionProcessor
from angr.analyses.decompiler.structurer_nodes import (
    BreakNode,
    CascadingConditionNode,
    CodeNode,
    ConditionalBreakNode,
    ConditionNode,
    ContinueNode,
    EmptyBlockNotice,
    IncompleteSwitchCaseNode,
    LoopNode,
    MultiNode,
    SequenceNode,
    SwitchCaseNode,
)


def _vvar(idx, bits, oident):
    return VirtualVariable(idx, idx, bits, VirtualVariableCategory.REGISTER, oident=oident)


def _block(addr, empty=False):
    return ailment.Block(addr, 1, statements=[] if empty else [Jump(0, Const(0, addr, 64), ins_addr=addr)])


def _guarded_chain(levels, leaf, empty_true=True):
    """`levels` nested ConditionNodes, each inside its own SequenceNode.

    The shape a long chain of guarded statements structures into, and the shape the walk was
    found alternating through when it ran out of stack.
    """
    node = leaf
    for level in range(levels):
        addr = 0x400000 + level
        node = SequenceNode(addr, nodes=[ConditionNode(addr, None, True, _block(addr, empty=empty_true), node)])
    return node


class TestConditionProcessor(TestCase):
    def test_extract_placeholders_include_semantic_properties(self):
        arch = archinfo.ArchAMD64()
        manager = ailment.Manager()
        condition_processor = ConditionProcessor(arch, manager)

        base = VirtualVariable(0, 1, 64, VirtualVariableCategory.REGISTER, oident=arch.registers["rax"][0])
        offset = Const(1, 0, 64)
        extract_byte = Extract(2, 8, base, offset, arch.memory_endness)
        extract_word = Extract(3, 16, base, offset, arch.memory_endness)
        extract_byte_be = Extract(4, 8, base, offset, archinfo.Endness.BE)

        byte_ast = condition_processor.claripy_ast_from_ail_condition(extract_byte)
        word_ast = condition_processor.claripy_ast_from_ail_condition(extract_word)
        byte_be_ast = condition_processor.claripy_ast_from_ail_condition(extract_byte_be)

        assert byte_ast.args[0] != word_ast.args[0]
        assert byte_ast.args[0] != byte_be_ast.args[0]
        assert condition_processor.convert_claripy_bool_ast(byte_ast) is extract_byte
        assert condition_processor.convert_claripy_bool_ast(word_ast) is extract_word
        assert condition_processor.convert_claripy_bool_ast(byte_be_ast) is extract_byte_be

    def test_operands_of_different_widths_are_unified(self):
        # a shift amount wider than the value (busybox encode_then_append_var_plusminus) used to trip an assertion, and
        # a comparison whose operands convert to bit-vectors of different widths died in claripy
        arch = archinfo.ArchAMD64()
        manager = ailment.Manager()
        cp = ConditionProcessor(arch, manager)
        byte = Load(0, _vvar(1, 64, 16), 1, arch.memory_endness, bits=8)
        amount = Convert(2, 8, 64, False, _vvar(3, 8, 24))
        shifted = cp.claripy_ast_from_ail_condition(BinaryOp(4, "Shr", [byte, amount], False, bits=8))
        assert shifted.size() == 8
        cmp = BinaryOp(5, "CmpEQ", [_vvar(6, 32, 16), _vvar(7, 64, 24)], False, bits=1)
        assert cp.claripy_ast_from_ail_condition(cmp) is not None

    def test_signed_comparisons_map_to_signed_claripy_operations(self):
        arch = archinfo.ArchAMD64()
        cp = ConditionProcessor(arch, ailment.Manager())
        for ail_op, claripy_op in (("CmpLE", "SLE"), ("CmpLT", "SLT"), ("CmpGE", "SGE"), ("CmpGT", "SGT")):
            cmp = BinaryOp(0, ail_op, [_vvar(1, 32, 16), _vvar(2, 32, 24)], True, bits=1)
            assert cmp.verbose_op == ail_op + "s"
            assert cp.claripy_ast_from_ail_condition(cmp).op == claripy_op


class TestLastStatements(TestCase):
    """get_last_statement(s) walk a structured tree, and the tree can be deeper than the stack.

    Measured on a Windows PE with 17,835 functions: one function's tree ran the walk 978 frames
    deep and hit CPython's limit of 1000, the decompiler swallowed the RecursionError, and the
    function decompiled to nothing at all. A hand-built tree puts the ceiling at 498 levels of
    nesting -- 499 raised -- so these walk a much deeper one, and pin the branch semantics that
    are easy to lose when a recursive walk is rewritten.
    """

    LEVELS = 2000

    def test_a_tree_deeper_than_the_recursion_limit_still_walks(self):
        leaf = _block(0x1000)
        tree = _guarded_chain(self.LEVELS, leaf)

        assert ConditionProcessor.get_last_statements(tree) == [leaf.statements[-1]]
        assert ConditionProcessor.get_last_statement(tree) is leaf.statements[-1]

    def test_every_branch_of_a_deep_tree_contributes_its_last_statement(self):
        leaf = _block(0x1000)
        tree = _guarded_chain(self.LEVELS, leaf, empty_true=False)

        last = ConditionProcessor.get_last_statements(tree)
        assert len(last) == self.LEVELS + 1
        assert last[-1] is leaf.statements[-1]

    def test_an_empty_true_branch_is_skipped_and_an_empty_false_branch_is_not(self):
        good, empty = _block(0x10), _block(0x20, empty=True)

        assert ConditionProcessor.get_last_statements(ConditionNode(0, None, True, empty, good)) == [
            good.statements[-1]
        ]
        with self.assertRaises(EmptyBlockNotice):
            ConditionProcessor.get_last_statements(ConditionNode(0, None, True, good, empty))

        # the singular walker takes the true branch when it has one and falls back otherwise
        assert ConditionProcessor.get_last_statement(ConditionNode(0, None, True, empty, good)) is good.statements[-1]
        assert ConditionProcessor.get_last_statement(ConditionNode(0, None, True, good, empty)) is good.statements[-1]

    def test_a_missing_branch_contributes_a_none(self):
        good = _block(0x10)

        assert ConditionProcessor.get_last_statements(ConditionNode(0, None, True, good, None)) == [
            good.statements[-1],
            None,
        ]
        assert ConditionProcessor.get_last_statements(ConditionNode(0, None, True, None, good)) == [
            None,
            good.statements[-1],
        ]

    def test_a_sequence_falls_back_to_an_earlier_node_and_gives_up_when_all_are_empty(self):
        first, empty = _block(0x10), _block(0x20, empty=True)

        assert ConditionProcessor.get_last_statements(SequenceNode(0, nodes=[first, empty])) == [first.statements[-1]]
        assert ConditionProcessor.get_last_statements(MultiNode([first, empty], addr=0)) == [first.statements[-1]]
        with self.assertRaises(EmptyBlockNotice):
            ConditionProcessor.get_last_statements(SequenceNode(0, nodes=[empty, empty]))
        with self.assertRaises(EmptyBlockNotice):
            ConditionProcessor.get_last_statements(SequenceNode(0, nodes=[]))

    def test_a_cascade_skips_an_empty_else_but_not_an_empty_condition(self):
        good, empty = _block(0x10), _block(0x20, empty=True)

        assert ConditionProcessor.get_last_statements(
            CascadingConditionNode(0, [(True, good)], else_node=SequenceNode(1, nodes=[empty]))
        ) == [good.statements[-1]]
        assert ConditionProcessor.get_last_statements(CascadingConditionNode(0, [(True, good)])) == [
            None,
            good.statements[-1],
        ]
        with self.assertRaises(EmptyBlockNotice):
            ConditionProcessor.get_last_statements(
                CascadingConditionNode(0, [(True, empty)], else_node=SequenceNode(1, nodes=[good]))
            )

    def test_the_remaining_node_kinds_are_still_handled(self):
        good, empty = _block(0x10), _block(0x20, empty=True)
        brk, cont = BreakNode(0x30, None), ContinueNode(0x40, None)
        conditional_break = ConditionalBreakNode(0x50, True, 0x60)

        assert ConditionProcessor.get_last_statements(CodeNode(good, None)) == [good.statements[-1]]
        assert ConditionProcessor.get_last_statements(LoopNode("while", None, SequenceNode(0, nodes=[good]))) == [
            good.statements[-1]
        ]
        assert ConditionProcessor.get_last_statements(brk) == [brk]
        assert ConditionProcessor.get_last_statements(cont) == [cont]
        assert ConditionProcessor.get_last_statements(conditional_break) == [conditional_break]
        assert ConditionProcessor.get_last_statements(
            SwitchCaseNode(True, OrderedDict({0: SequenceNode(1, nodes=[good])}), None, addr=0)
        ) == [
            good.statements[-1],
            None,
        ]
        with self.assertRaises(EmptyBlockNotice):
            ConditionProcessor.get_last_statements(
                SwitchCaseNode(
                    True, OrderedDict({0: SequenceNode(1, nodes=[empty])}), SequenceNode(2, nodes=[good]), addr=0
                )
            )
        incomplete = IncompleteSwitchCaseNode(0, SequenceNode(1, nodes=[good]), [SequenceNode(2, nodes=[good])])
        assert ConditionProcessor.get_last_statements(incomplete) == [good.statements[-1]]
        assert ConditionProcessor.get_last_statement(incomplete) is None


if __name__ == "__main__":
    unittest.main()

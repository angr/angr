#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import unittest

import networkx

import angr
from angr.ailment.block import Block
from angr.ailment.expression import (
    BinaryOp,
    Const,
    Load,
    Phi,
    UnaryOp,
    VirtualVariable,
    VirtualVariableCategory,
)
from angr.ailment.manager import Manager
from angr.ailment.statement import Assignment, ConditionalJump, Jump
from angr.analyses.decompiler.optimization_pass_registry import name_to_pass
from angr.analyses.decompiler.optimization_passes import VM_OPTIMIZATION_PASSES
from angr.analyses.decompiler.optimization_passes.code_motion import (
    EquivalenceAwareCodeMotionOptimization,
    EquivalentDefinitionSinker,
)
from angr.analyses.decompiler.presets import DECOMPILATION_PRESETS
from tests.common import bin_location

ENDNESS = "Iend_LE"
SP_SLOT = -0x78  # the VM's stack-pointer slot
FRAME = -0x170  # a frame object the VM stack lives in


def _slot(varid, offset, bits=64):
    return VirtualVariable(varid, varid, bits, VirtualVariableCategory.STACK, oident=offset)


def _ref(varid, offset):
    return UnaryOp(100 + varid, "Reference", _slot(varid, offset), bits=64)


def _add(a, c):
    return BinaryOp(200 + c, "Add", [a, Const(300 + c, c, 64)], False, bits=64)


def _sub(a, c):
    return BinaryOp(400 + c, "Sub", [a, Const(500 + c, c, 64)], False, bits=64)


def _jump(target):
    return Jump(600, Const(601, target, 64), ins_addr=target)


def _diamond(then_stmts, else_stmts, join_extra=(), head_extra=(), back_edge=False):
    """
    head -> (then | else) -> join; the join merges SP_SLOT through a phi of vvar 20 (then) and vvar 30 (else).
    """
    head = Block(
        0x10,
        1,
        statements=[
            Assignment(1, _slot(5, FRAME), Const(2, 0, 64), ins_addr=0x10),
            *head_extra,
            ConditionalJump(3, Const(4, 1, 1), Const(5, 0x20, 64), Const(6, 0x30, 64), ins_addr=0x10),
        ],
    )
    then_ = Block(0x20, 1, statements=[*then_stmts, _jump(0x40)])
    else_ = Block(0x30, 1, statements=[*else_stmts, _jump(0x40)])
    phi = Phi(40, 64, [((0x20, 0), _slot(20, SP_SLOT)), ((0x30, 0), _slot(30, SP_SLOT))])
    join = Block(0x40, 1, statements=[Assignment(41, _slot(50, SP_SLOT), phi, ins_addr=0x40), *join_extra])
    graph = networkx.DiGraph()
    graph.add_edges_from([(head, then_), (head, else_), (then_, join), (else_, join)])
    if back_edge:
        graph.add_edge(join, then_)
    return graph, head, join


def _sink(graph, head):
    sinker = EquivalentDefinitionSinker(graph, head, Manager())
    return sinker, sinker.run()


def _join_def(new_join):
    defs = [s for s in new_join.statements if isinstance(s, Assignment) and s.dst.varid == 50]
    assert len(defs) == 1
    return defs[0]


class TestEquivalenceAwareCodeMotion(unittest.TestCase):
    def test_identical_arm_values_are_sunk(self):
        # iter = &frame - 8 in both arms
        graph, head, join = _diamond(
            [Assignment(21, _slot(20, SP_SLOT), _sub(_ref(5, FRAME), 8), ins_addr=0x20)],
            [Assignment(31, _slot(30, SP_SLOT), _sub(_ref(5, FRAME), 8), ins_addr=0x30)],
        )
        sinker, repl = _sink(graph, head)
        assert sinker.sunk == 1
        stmt = _join_def(repl[join])
        assert not stmt.is_phi_assignment
        assert stmt.src.likes(_sub(_ref(5, FRAME), 8))

    def test_differently_computed_equal_addresses_are_sunk(self):
        # then: iter = &frame + 16 - 16; else: t = &frame + 8; iter = t - 8
        graph, head, join = _diamond(
            [
                Assignment(21, _slot(22, SP_SLOT), _add(_ref(5, FRAME), 16), ins_addr=0x20),
                Assignment(23, _slot(20, SP_SLOT), _sub(_slot(22, SP_SLOT), 16), ins_addr=0x21),
            ],
            [
                Assignment(31, _slot(32, SP_SLOT), _add(_ref(5, FRAME), 8), ins_addr=0x30),
                Assignment(33, _slot(30, SP_SLOT), _sub(_slot(32, SP_SLOT), 8), ins_addr=0x31),
            ],
        )
        sinker, repl = _sink(graph, head)
        assert sinker.sunk == 1
        src = _join_def(repl[join]).src
        # neither arm's expression is usable at the join, so the frame address is rebuilt
        assert isinstance(src, UnaryOp) and src.op == "Reference" and src.operand.stack_offset == FRAME

    def test_different_values_are_left_alone(self):
        graph, head, _ = _diamond(
            [Assignment(21, _slot(20, SP_SLOT), _sub(_ref(5, FRAME), 8), ins_addr=0x20)],
            [Assignment(31, _slot(30, SP_SLOT), _sub(_ref(5, FRAME), 16), ins_addr=0x30)],
        )
        sinker, repl = _sink(graph, head)
        assert sinker.sunk == 0 and not repl

    def test_memory_reads_are_never_equal(self):
        # identical text, but each Load reads memory at a different point
        load = lambda idx: Load(idx, _ref(5, FRAME), 8, ENDNESS)  # noqa:E731
        graph, head, _ = _diamond(
            [Assignment(21, _slot(20, SP_SLOT), load(22), ins_addr=0x20)],
            [Assignment(31, _slot(30, SP_SLOT), load(32), ins_addr=0x30)],
        )
        _, repl = _sink(graph, head)
        assert not repl

    def test_loop_head_is_left_alone(self):
        graph, head, _ = _diamond(
            [Assignment(21, _slot(20, SP_SLOT), _sub(_ref(5, FRAME), 8), ins_addr=0x20)],
            [Assignment(31, _slot(30, SP_SLOT), _sub(_ref(5, FRAME), 8), ins_addr=0x30)],
            back_edge=True,
        )
        # the join's successor is also its predecessor
        _, repl = _sink(graph, head)
        assert not repl

    def test_values_defined_in_a_loop_are_left_alone(self):
        # r is defined in a loop: equal names are only trusted for variables defined once per execution
        loop = Block(
            0x18,
            1,
            statements=[
                Assignment(9, _slot(11, -0x90), Load(12, _ref(5, FRAME), 8, ENDNESS), ins_addr=0x18),
                ConditionalJump(13, Const(14, 1, 1), Const(15, 0x18, 64), Const(16, 0x19, 64), ins_addr=0x18),
            ],
        )
        graph, head, _ = _diamond(
            [Assignment(21, _slot(20, SP_SLOT), _add(_slot(11, -0x90), 8), ins_addr=0x20)],
            [Assignment(31, _slot(30, SP_SLOT), _add(_slot(11, -0x90), 8), ins_addr=0x30)],
        )
        for succ in list(graph.successors(head)):
            graph.remove_edge(head, succ)
            graph.add_edge(loop, succ)
        graph.add_edge(head, loop)
        graph.add_edge(loop, loop)
        _, repl = _sink(graph, head)
        assert not repl

    def test_escaped_slot_is_left_alone(self):
        # &iter is taken, so the arm stores may be read through a pointer
        escape = Assignment(7, _slot(6, -0x200), _ref(9, SP_SLOT), ins_addr=0x11)
        graph, head, _ = _diamond(
            [Assignment(21, _slot(20, SP_SLOT), _sub(_ref(5, FRAME), 8), ins_addr=0x20)],
            [Assignment(31, _slot(30, SP_SLOT), _sub(_ref(5, FRAME), 8), ins_addr=0x30)],
            head_extra=[escape],
        )
        _, repl = _sink(graph, head)
        assert not repl

    def test_slot_inside_an_escaped_object_is_left_alone(self):
        # &obj covers iter's slot, so a pointer can reach it
        obj = VirtualVariable(9, 9, 192, VirtualVariableCategory.STACK, oident=SP_SLOT - 8)
        escape = Assignment(7, _slot(6, -0x200), UnaryOp(8, "Reference", obj, bits=64), ins_addr=0x11)
        graph, head, _ = _diamond(
            [Assignment(21, _slot(20, SP_SLOT), _sub(_ref(5, FRAME), 8), ins_addr=0x20)],
            [Assignment(31, _slot(30, SP_SLOT), _sub(_ref(5, FRAME), 8), ins_addr=0x30)],
            head_extra=[escape],
        )
        _, repl = _sink(graph, head)
        assert not repl

    def test_an_unclobbered_chain_variable_is_preferred(self):
        # r (a register) holds the VM stack pointer before the branch; each arm moves it and moves it back
        r = VirtualVariable(10, 10, 64, VirtualVariableCategory.REGISTER, oident=16)
        root = Assignment(8, r, _add(_ref(5, FRAME), 0x40), ins_addr=0x12)
        graph, head, join = _diamond(
            [
                Assignment(21, _slot(22, SP_SLOT), _sub(r, 8), ins_addr=0x20),
                Assignment(23, _slot(20, SP_SLOT), _sub(_slot(22, SP_SLOT), 8), ins_addr=0x21),
            ],
            [
                Assignment(31, _slot(32, SP_SLOT), _add(r, 8), ins_addr=0x30),
                Assignment(33, _slot(30, SP_SLOT), _sub(_slot(32, SP_SLOT), 24), ins_addr=0x31),
            ],
            head_extra=[root],
        )
        _, repl = _sink(graph, head)
        assert _join_def(repl[join]).src.likes(_sub(r, 16))

    def test_redefined_root_is_not_read_at_the_join(self):
        # v = &frame (before the branch); then: iter = v + 0; else: iter = v + 8 - 8, after redefining v's slot
        root = Assignment(8, _slot(10, SP_SLOT), _ref(5, FRAME), ins_addr=0x12)
        graph, head, join = _diamond(
            [Assignment(21, _slot(20, SP_SLOT), _add(_slot(10, SP_SLOT), 0), ins_addr=0x20)],
            [
                Assignment(31, _slot(32, SP_SLOT), _add(_slot(10, SP_SLOT), 8), ins_addr=0x30),
                Assignment(33, _slot(30, SP_SLOT), _sub(_slot(32, SP_SLOT), 8), ins_addr=0x31),
            ],
            head_extra=[root],
        )
        _, repl = _sink(graph, head)
        src = _join_def(repl[join]).src
        # reading vvar 10 at the join would make it interfere with vvar 32 (same slot)
        assert not (isinstance(src, VirtualVariable) and src.varid == 10)
        assert isinstance(src, UnaryOp) and src.op == "Reference"

    def test_definition_goes_after_remaining_phis(self):
        other_phi = Assignment(
            42,
            _slot(51, -0x80),
            Phi(43, 64, [((0x20, 0), _slot(24, -0x80)), ((0x30, 0), _slot(34, -0x80))]),
            ins_addr=0x40,
        )
        graph, head, join = _diamond(
            [
                Assignment(21, _slot(20, SP_SLOT), _sub(_ref(5, FRAME), 8), ins_addr=0x20),
                Assignment(25, _slot(24, -0x80), Const(26, 1, 64), ins_addr=0x21),
            ],
            [
                Assignment(31, _slot(30, SP_SLOT), _sub(_ref(5, FRAME), 8), ins_addr=0x30),
                Assignment(35, _slot(34, -0x80), Const(36, 2, 64), ins_addr=0x31),
            ],
            join_extra=[other_phi],
        )
        _, repl = _sink(graph, head)
        stmts = repl[join].statements
        assert stmts[0].is_phi_assignment and stmts[0].dst.varid == 51
        assert not stmts[1].is_phi_assignment and stmts[1].dst.varid == 50

    def test_pass_only_runs_under_vm_deobfuscation(self):
        for preset in DECOMPILATION_PRESETS.values():
            assert EquivalenceAwareCodeMotionOptimization not in preset.opt_passes
        assert EquivalenceAwareCodeMotionOptimization in VM_OPTIMIZATION_PASSES
        assert name_to_pass("EquivalenceAwareCodeMotionOptimization") is EquivalenceAwareCodeMotionOptimization

        proj = angr.Project(os.path.join(bin_location, "tests", "x86_64", "fauxware"), auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True, function_starts=[0x40071D], force_smart_scan=False)
        func = cfg.kb.functions["authenticate"]
        plain = proj.analyses.Decompiler(func, cfg=cfg, decompile=False)
        vm = proj.analyses.Decompiler(func, cfg=cfg, decompile=False, vm_deobfuscation=True)
        assert EquivalenceAwareCodeMotionOptimization not in plain._optimization_passes
        assert EquivalenceAwareCodeMotionOptimization in vm._optimization_passes


if __name__ == "__main__":
    unittest.main()

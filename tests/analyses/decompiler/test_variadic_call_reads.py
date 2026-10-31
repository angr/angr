#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
"""The outgoing stack-argument stores of a variadic call whose variadic arguments could not be determined."""
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import re
import unittest
from types import SimpleNamespace

import archinfo
import networkx

import angr
from angr import ailment
from angr.ailment.block import Block
from angr.ailment.expression import Call, Const, Load, StackBaseOffset, VirtualVariable, VirtualVariableCategory
from angr.ailment.statement import Assignment, SideEffectStatement, Store
from angr.analyses.decompiler.clinic import Clinic
from angr.analyses.decompiler.stack_dead_store_eliminator import StackDeadStoreEliminator
from angr.analyses.decompiler.variadic_call_reads import (
    VARIADIC_STACK_ARGS_TAG,
    VARIADIC_UNRESOLVED_TAG,
    block_variadic_tags,
    variadic_call_read_vvars,
)
from angr.calling_conventions import SimCCCdecl
from angr.sim_type import SimTypeChar, SimTypeFunction, SimTypeInt, SimTypePointer

from .test_stack_passed_format import TestStackPassedFormat


class TestUnresolvedVariadicCall(TestStackPassedFormat):
    """A VM-mode decompilation removes dead stack stores; a variadic callee not known to be printf-like keeps them."""

    test_constant_stack_format_gets_its_arguments = None

    def test_unresolved_variadic_call_keeps_outgoing_arg_store(self):
        proto = SimTypeFunction([SimTypePointer(SimTypeChar())], SimTypeInt(), variadic=True)
        loop = self._decompile(True, proto)
        assert re.search(r"v\d+ = [^;]+\[j\];\s+vlog\(\"%d \"\);", loop), loop

    def test_non_variadic_call_store_is_removed(self):
        proto = SimTypeFunction([SimTypePointer(SimTypeChar())], SimTypeInt())
        loop = self._decompile(True, proto)
        assert re.search(r"{\s+vlog\(\"%d \"\);\s+}", loop), loop


class _Frame:
    """AMD64 helpers: stack and register variables, and a variadic call."""

    def __init__(self):
        self.arch = archinfo.ArchAMD64()
        self.m = ailment.Manager()

    def const(self, value, bits=64):
        return Const(self.m.next_atom(), value, bits)

    def stack_def(self, varid, off, value):
        dst = VirtualVariable(self.m.next_atom(), varid, 64, VirtualVariableCategory.STACK, oident=off)
        return Assignment(self.m.next_atom(), dst, self.const(value), ins_addr=0x1000)

    def stack_use(self, varid, off, dst_varid=100):
        src = VirtualVariable(self.m.next_atom(), varid, 64, VirtualVariableCategory.STACK, oident=off)
        dst = VirtualVariable(self.m.next_atom(), dst_varid, 64, VirtualVariableCategory.REGISTER, oident=16)
        return Assignment(self.m.next_atom(), dst, src, ins_addr=0x1010)

    def call(self, tags):
        call = Call(self.m.next_atom(), self.const(0x2000), args=[self.const(0)], ins_addr=0x1008, **tags)
        return SideEffectStatement(self.m.next_atom(), call, ins_addr=0x1008)


class TestVariadicCallReadVVars(unittest.TestCase):
    """SSA level 1: the stack variables an unresolved variadic call may read."""

    # sp at the call is -0x50; MS x64 puts the first stack argument past the 0x20-byte shadow space
    TAGS = {VARIADIC_UNRESOLVED_TAG: 0x20, VARIADIC_STACK_ARGS_TAG: -0x30}

    def _run(self, tags, extra_first=()):
        f = _Frame()
        statements = [
            *extra_first,
            f.stack_def(10, -0x30, 1),  # outgoing arguments
            f.stack_def(11, -0x28, 2),
            f.stack_def(12, -0x10, 3),  # above the lowest frame-local slot
            f.stack_def(13, -0x18, 4),  # the lowest frame-local slot (read below)
            f.call(tags),
            f.stack_use(13, -0x18),
        ]
        block = Block(0x1000, 0x20, statements=statements)
        return variadic_call_read_vvars({(0x1000, None): block}, {(0x1000, None): []})

    def test_outgoing_area(self):
        assert self._run(self.TAGS) == {10, 11}

    def test_overwritten_store_is_not_read(self):
        f = _Frame()
        assert self._run(self.TAGS, extra_first=(f.stack_def(9, -0x30, 0),)) == {10, 11}

    def test_unknown_sp_reads_every_reaching_slot(self):
        assert self._run({VARIADIC_UNRESOLVED_TAG: 0x20}) == {10, 11, 12, 13}

    def test_resolved_call(self):
        assert self._run({}) == set()

    def test_slot_read_only_before_the_call_is_not_a_local(self):
        # a VM reuses its frame: -0x28 is read before the call, through an older definition
        f = _Frame()
        assert self._run(self.TAGS, extra_first=(f.stack_def(8, -0x28, 0), f.stack_use(8, -0x28, 101))) == {10, 11}

    def test_across_blocks(self):
        f = _Frame()
        b0 = Block(0x1000, 8, statements=[f.stack_def(10, -0x30, 1), f.stack_def(11, -0x18, 2)])
        b1 = Block(0x1008, 8, statements=[f.call(self.TAGS), f.stack_use(11, -0x18)])
        kept = variadic_call_read_vvars(
            {(0x1000, None): b0, (0x1008, None): b1}, {(0x1000, None): [(0x1008, None)], (0x1008, None): []}
        )
        assert kept == {10}


class TestDeadStackStoresAroundVariadicCall(unittest.TestCase):
    """SSA level 0: StackDeadStoreEliminator keeps stores an unresolved variadic call may read."""

    def _run(self, tags):
        f = _Frame()

        def store(off, value):
            return Store(f.m.next_atom(), StackBaseOffset(f.m.next_atom(), 64, off), f.const(value), 8, "Iend_LE",
                         ins_addr=0x1000)

        load = Load(f.m.next_atom(), StackBaseOffset(f.m.next_atom(), 64, -0x18), 8, "Iend_LE")
        statements = [
            store(-0x30, 1),  # outgoing argument
            store(-0x10, 2),  # above the lowest frame-local slot, never read
            store(-0x18, 3),
            f.call(tags),
            Assignment(
                f.m.next_atom(),
                VirtualVariable(f.m.next_atom(), 100, 64, VirtualVariableCategory.REGISTER, oident=16),
                load,
                ins_addr=0x1010,
            ),
        ]
        block = Block(0x1000, 0x20, statements=statements)
        graph = networkx.DiGraph()
        graph.add_node(block)
        StackDeadStoreEliminator(f.arch, graph, ail_manager=f.m).run()
        block = next(iter(graph))
        return sorted(s.addr.offset for s in block.statements if isinstance(s, Store))

    def test_outgoing_store_kept(self):
        assert self._run(TestVariadicCallReadVVars.TAGS) == [-0x30, -0x18]

    def test_without_the_tag(self):
        assert self._run({}) == [-0x18]


class TestRemakeResolvesToNoArguments(unittest.TestCase):
    """Making a call site again whose format takes no variadic argument drops the unresolved tag (hunatcha_vmp)."""

    def test_tag_dropped(self):
        proj = angr.load_shellcode(b"\x90" * 0x10 + b"[autorun]\r\n\0", "X86")
        func = proj.kb.functions.function(addr=0x2000, create=True)
        func.name = "sprintf"
        func.calling_convention = SimCCCdecl(proj.arch)
        func.prototype = SimTypeFunction(
            [SimTypePointer(SimTypeChar()), SimTypePointer(SimTypeChar())], SimTypeInt(), variadic=True
        ).with_arch(proj.arch)
        m = ailment.Manager()

        def c(v):
            return Const(m.next_atom(), v, 32)

        def slot(off):
            return StackBaseOffset(m.next_atom(), 32, off)

        args = [Load(m.next_atom(), slot(-0x20), 4, "Iend_LE"), Load(m.next_atom(), slot(-0x1C), 4, "Iend_LE")]
        tags = {VARIADIC_UNRESOLVED_TAG: 8, VARIADIC_STACK_ARGS_TAG: -0x18, "ins_addr": 0x1008}
        # as an earlier CallSiteMaker run left it
        expr = Call(m.next_atom(), c(0x2000), args=args, arg_vvars=[], **tags)
        call = SideEffectStatement(expr.idx, expr, ins_addr=0x1008)
        fmt = Store(m.next_atom(), slot(-0x1C), c(0x10), 4, "Iend_LE", ins_addr=0x1000)
        graph = networkx.DiGraph()
        graph.add_node(Block(0x1000, 0xD, statements=[fmt, call]))

        class _Spt:
            def offset_before(self, addr, reg):
                return -0x20

        clinic = SimpleNamespace(
            project=proj,
            _ail_manager=m,
            _x87_call_ftop=None,
            flavor="pseudocode",
            calls_as_rets={},
            _inlining_parents=(),
            _fix_fp_call_return_values=lambda graph: None,
        )
        Clinic._make_callsites(clinic, graph, stack_pointer_tracker=_Spt())
        assert block_variadic_tags(next(iter(graph))) == (None, None)


if __name__ == "__main__":
    unittest.main()

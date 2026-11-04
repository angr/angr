#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import unittest

import networkx

import angr
from angr import ailment
from angr.ailment.block import Block
from angr.ailment.expression import (
    BinaryOp,
    Call,
    Const,
    StackBaseOffset,
    UnaryOp,
    VirtualVariable,
    VirtualVariableCategory,
)
from angr.ailment.statement import Assignment, Jump, Return, SideEffectStatement, Store
from angr.knowledge_plugins.functions import Function


class TestVMStackConstPropagation(unittest.TestCase):
    """SPropagator (VM bodies) copies a constant held in a stack slot into all of its uses."""

    def setUp(self):
        self.proj = angr.load_shellcode(b"\xc3", "AMD64")
        self.idx = iter(range(100, 1_000_000))

    def _slot(self):
        return VirtualVariable(next(self.idx), 10, 64, VirtualVariableCategory.STACK, oident=-0x740)

    def _const(self, v, bits=64):
        return Const(next(self.idx), v, bits)

    def _bin(self, op, a, b):
        return BinaryOp(next(self.idx), op, [a, b], False, bits=64)

    def _simplify(self, vm: bool, take_address: bool = False, escape: bool = False):
        # the pushed encrypted VIP, read by two duplicated entry blocks
        self.proj.vm_deobfuscation = vm
        entry = Block(
            0x401000,
            0x10,
            statements=[
                Assignment(0, self._slot(), self._const(0xFFFFFFFFFD9E9F43), ins_addr=0x401000),
                *(
                    # a callee may write the slot through its escaped address
                    [
                        SideEffectStatement(
                            1,
                            Call(next(self.idx), "fill", args=[StackBaseOffset(next(self.idx), 64, -0x740)], bits=64),
                            ins_addr=0x401002,
                        )
                    ]
                    if escape
                    else []
                ),
                Jump(2, self._const(0x401010), ins_addr=0x401004),
            ],
            idx=0,
        )
        reads = []
        for i, addr in enumerate((0x401010, 0x401020)):
            use = UnaryOp(next(self.idx), "Reference", self._slot(), bits=64) if take_address else self._slot()
            data = self._bin("Add", use, self._const(0xCE70EC4A))
            reads.append(
                Block(
                    addr,
                    0x10,
                    statements=[
                        Store(0, self._const(0x500000 + 8 * i), data, 8, "Iend_LE", ins_addr=addr),
                        Return(1, [], ins_addr=addr + 4),
                    ],
                    idx=0,
                )
            )
        graph = networkx.DiGraph()
        graph.add_edge(entry, reads[0])
        graph.add_edge(entry, reads[1])
        func = Function(self.proj.kb.functions, 0x401000)
        simp = self.proj.analyses.AILSimplifier(
            func, func_graph=graph, ail_manager=ailment.Manager(), remove_dead_memdefs=False
        )
        return [st for b in simp.func_graph for st in b.statements if isinstance(st, Store)]

    def test_constant_reaches_every_use(self):
        stores = self._simplify(vm=True)
        assert len(stores) == 2
        for store in stores:
            assert "vvar_10" not in str(store), store
            assert str(0xFFFFFFFFFD9E9F43) in str(store), store

    def test_address_taken_slot_is_kept(self):
        stores = self._simplify(vm=True, take_address=True)
        assert all("vvar_10" in str(store) for store in stores)

    def test_slot_a_call_may_write_is_kept(self):
        stores = self._simplify(vm=True, escape=True)
        assert all("vvar_10" in str(store) for store in stores)

    def test_slot_updated_in_a_loop_is_kept(self):
        # x = 0x100; loop: use(x); x += 1 -- with the in-loop use read straight from the first definition, as stack SSA
        # produces when it misses the loop update
        self.proj.vm_deobfuscation = True
        entry = Block(
            0x401000,
            0x10,
            statements=[
                Assignment(0, self._slot(), self._const(0x100), ins_addr=0x401000),
                Jump(1, self._const(0x401010), ins_addr=0x401004),
            ],
            idx=0,
        )
        update = VirtualVariable(next(self.idx), 11, 64, VirtualVariableCategory.STACK, oident=-0x740)
        loop = Block(
            0x401010,
            0x10,
            statements=[
                Store(0, self._const(0x500000), self._slot(), 8, "Iend_LE", ins_addr=0x401010),
                Assignment(1, update, self._bin("Add", self._slot(), self._const(1)), ins_addr=0x401014),
                Store(2, self._const(0x500008), update, 8, "Iend_LE", ins_addr=0x401018),
                Jump(3, self._const(0x401010), ins_addr=0x40101C),
            ],
            idx=0,
        )
        graph = networkx.DiGraph()
        graph.add_edge(entry, loop)
        graph.add_edge(loop, loop)
        func = Function(self.proj.kb.functions, 0x401000)
        simp = self.proj.analyses.AILSimplifier(
            func, func_graph=graph, ail_manager=ailment.Manager(), remove_dead_memdefs=False
        )
        stores = [st for b in simp.func_graph for st in b.statements if isinstance(st, Store)]
        assert stores and str(0x100) not in str(stores[0]), stores

    def test_only_uses_before_a_frame_write_get_the_constant(self):
        # x = C; use(x); *(&y + 0x730) = 1 (x's slot, through another slot's address); use(x)
        self.proj.vm_deobfuscation = True
        other = VirtualVariable(next(self.idx), 20, 32, VirtualVariableCategory.STACK, oident=-0x10)
        through = BinaryOp(
            next(self.idx), "Sub", [UnaryOp(next(self.idx), "Reference", other, bits=64), self._const(0x730)], bits=64
        )
        block = Block(
            0x401000,
            0x20,
            statements=[
                Assignment(0, self._slot(), self._const(0x1234), ins_addr=0x401000),
                Store(1, self._const(0x500000), self._slot(), 8, "Iend_LE", ins_addr=0x401004),
                Store(2, through, self._const(1), 8, "Iend_LE", ins_addr=0x401008),
                Store(3, self._const(0x500008), self._slot(), 8, "Iend_LE", ins_addr=0x40100C),
                Return(4, [], ins_addr=0x401010),
            ],
            idx=0,
        )
        graph = networkx.DiGraph()
        graph.add_node(block)
        func = Function(self.proj.kb.functions, 0x401000)
        simp = self.proj.analyses.AILSimplifier(
            func, func_graph=graph, ail_manager=ailment.Manager(), remove_dead_memdefs=False
        )
        stores = [st for b in simp.func_graph for st in b.statements if isinstance(st, Store)]
        before = next(st for st in stores if isinstance(st.addr, Const) and st.addr.value == 0x500000)
        after = next(st for st in stores if isinstance(st.addr, Const) and st.addr.value == 0x500008)
        assert str(0x1234) in str(before), before
        assert "vvar_10" in str(after), after

    def test_native_code_keeps_stack_variables(self):
        stores = self._simplify(vm=False)
        assert all("vvar_10" in str(store) for store in stores)


if __name__ == "__main__":
    unittest.main()

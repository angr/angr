#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import itertools
import unittest

import networkx

import angr
from angr.ailment import Manager
from angr.ailment.block import Block
from angr.ailment.expression import BinaryOp, Const, Load, VEXCCallExpression
from angr.ailment.statement import ConditionalJump, Jump, Label, Return, Store
from angr.analyses.decompiler.peephole_optimizations import (
    ConstantDereferences,
    ReadOnlyConstantDereferences,
    vm_peephole_optimizations,
)
from angr.analyses.decompiler.vm_deobfuscation_simplifier import VMDeobfuscationSimplifierMixin

G, FLAGS = 0x601000, 0x601010
_ids = itertools.count(1)


def _c(value: int, bits: int = 64) -> Const:
    return Const(next(_ids), value, bits)


def _label(addr: int) -> Label:
    return Label(next(_ids), f"L{addr:x}", ins_addr=addr, block_idx=None)


def _themida_flag_graph(copy_check: bool = False) -> networkx.DiGraph:
    """
    g = 0; if (flags & 64) == 0 goto set else goto check
    set:   g = 1; goto check
    check: if g == 0 goto d else goto e
    """
    flags = BinaryOp(next(_ids), "And", [Load(next(_ids), _c(FLAGS), 4, "Iend_LE"), _c(64, 32)], False)
    cond = BinaryOp(next(_ids), "CmpEQ", [flags, _c(0, 32)], False)
    head = Block(
        0x400000,
        4,
        statements=[
            _label(0x400000),
            Store(next(_ids), _c(G), _c(0, 8), 1, "Iend_LE", ins_addr=0x400000),
            ConditionalJump(next(_ids), cond, _c(0x400010), _c(0x400020), ins_addr=0x400001),
        ],
    )
    set_g = Block(
        0x400010,
        4,
        statements=[
            _label(0x400010),
            Store(next(_ids), _c(G), _c(1, 8), 1, "Iend_LE", ins_addr=0x400010),
            Jump(next(_ids), _c(0x400020), ins_addr=0x400011),
        ],
    )
    g_is_zero = BinaryOp(next(_ids), "CmpEQ", [Load(next(_ids), _c(G), 1, "Iend_LE"), _c(0, 8)], False)
    check = Block(
        0x400020,
        4,
        statements=[
            _label(0x400020),
            ConditionalJump(next(_ids), g_is_zero, _c(0x400030), _c(0x400040), ins_addr=0x400020),
        ],
    )
    d = Block(0x400030, 1, statements=[Return(next(_ids), [], ins_addr=0x400030)])
    e = Block(0x400040, 1, statements=[Return(next(_ids), [], ins_addr=0x400040)])
    if copy_check:
        # set jumps to its own copy of check, as after block duplication
        check_copy = Block(0x400020, 4, statements=list(check.statements), idx=1)
        edges = [(head, set_g), (head, check), (set_g, check_copy), (check, d), (check, e), (check_copy, d)]
        return networkx.DiGraph([*edges, (check_copy, e)])
    return networkx.DiGraph([(head, set_g), (head, check), (set_g, check), (check, d), (check, e)])


def _eflags_check_graph(leaf) -> networkx.DiGraph:
    """
    if (((((leaf | 2) | a) | b) | c) & 64) == 0, as Themida checks ZF on x86
    """
    expr = leaf
    for value in (2, 0x10, 0x20, 0x40):
        expr = BinaryOp(next(_ids), "Or", [expr, _c(value, 32)], False)
    cond = BinaryOp(next(_ids), "CmpEQ", [BinaryOp(next(_ids), "And", [expr, _c(64, 32)], False), _c(0, 32)], False)
    head = Block(0x400000, 4, statements=[ConditionalJump(next(_ids), cond, _c(0x400010), _c(0x400020), ins_addr=1)])
    d = Block(0x400010, 1, statements=[Return(next(_ids), [], ins_addr=0x400010)])
    e = Block(0x400020, 1, statements=[Return(next(_ids), [], ins_addr=0x400020)])
    return networkx.DiGraph([(head, d), (head, e)])


class _Host(VMDeobfuscationSimplifierMixin):
    def __init__(self):
        self.project = angr.load_shellcode(b"\xc3" * 0x100, arch="amd64", load_address=0x400000)
        self.kb = self.project.kb
        self.function = self.kb.functions.function(addr=0x400000, create=True)
        self._ail_manager = Manager()
        self.entry_node_addr = (0x400000, None)


class TestRemoveRedundantConditionalCheck(unittest.TestCase):
    def test_flag_copy_branch_is_folded(self):
        graph = _Host().remove_redundant_conditional_check(_themida_flag_graph())
        assert sorted(node.addr for node in graph) == [0x400000, 0x400030, 0x400040]
        head = next(node for node in graph if node.addr == 0x400000)
        jump = head.statements[-1]
        assert isinstance(jump, ConditionalJump)
        # flags & 64 == 0 sets g, so the check's false target is taken
        assert (jump.true_target.value, jump.false_target.value) == (0x400040, 0x400030)
        assert jump.tags["ins_addr"] == 0x400020

    def test_flag_copy_branch_with_copied_check_is_folded(self):
        graph = _Host().remove_redundant_conditional_check(_themida_flag_graph(copy_check=True))
        assert sorted(node.addr for node in graph) == [0x400000, 0x400030, 0x400040]
        head = next(node for node in graph if node.addr == 0x400000)
        assert (head.statements[-1].true_target.value, head.statements[-1].false_target.value) == (0x400040, 0x400030)

    def test_eflags_or_chain_is_dropped(self):
        ccall = VEXCCallExpression(next(_ids), "x86g_calculate_eflags_all", (_c(15, 32),), bits=32)
        graph = _Host().calculate_flags_simplifier(_eflags_check_graph(ccall))
        cond = next(node for node in graph if node.addr == 0x400000).statements[-1].condition
        assert cond.operands[0].operands[0] is ccall or cond.operands[0].operands[0].likes(ccall)
        # any other leaf is left alone
        load = Load(next(_ids), _c(FLAGS, 64), 4, "Iend_LE")
        graph = _Host().calculate_flags_simplifier(_eflags_check_graph(load))
        cond = next(node for node in graph if node.addr == 0x400000).statements[-1].condition
        assert cond.operands[0].operands[0].op == "Or"

    def test_transforms_raise_nothing(self):
        # the driver swallows exceptions, so run every transform directly
        host = _Host()
        for name in dict.fromkeys(name for name, _ in _Host.VM_DEOBF_TRANSFORMS):
            getattr(host, name)(_themida_flag_graph())


class TestVMDecompilerPasses(unittest.TestCase):
    # mov dword [rsp+0x10], "abcd"; mov byte [rsp+0x14], 0; lea rcx, [rsp+0x10]; call puts; ret
    CODE = bytes.fromhex("4883ec28c744241061626364c644241400488d4c2410e8e50000004883c428c3").ljust(0x100, b"\x90")

    def _decompile(self, vm: bool) -> str:
        proj = angr.load_shellcode(self.CODE + b"\xc3", arch="amd64", load_address=0x400000)
        proj.hook(0x400100, angr.SIM_PROCEDURES["libc"]["puts"]())
        cfg = proj.analyses.CFGFast(normalize=True, function_starts=[0x400000])
        dec = proj.analyses.Decompiler(
            proj.kb.functions[0x400000], cfg=cfg.model, vm_deobfuscation=vm, fail_fast=True
        )
        assert dec.codegen is not None and dec.codegen.text is not None
        return dec.codegen.text

    def test_blob_memory_is_not_constant(self):
        # a VM body is decompiled from a writable process dump loaded as a blob
        proj = angr.load_shellcode(b"\x01" * 0x100, arch="amd64", load_address=0x400000)
        load = Load(next(_ids), _c(0x400010), 1, "Iend_LE")
        assert ConstantDereferences(proj, proj.kb, Manager(), 0x400000).optimize(load) is not None
        assert ReadOnlyConstantDereferences(proj, proj.kb, Manager(), 0x400000).optimize(load) is None
        opts = vm_peephole_optimizations()
        assert ReadOnlyConstantDereferences in opts and ConstantDereferences not in opts

    def test_constant_frame_stores_stay_stores(self):
        assert "strcpy" in self._decompile(False)
        assert "strcpy" not in self._decompile(True)


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import re
import unittest

import networkx

import angr
from angr import ailment
from angr.ailment.block import Block
from angr.ailment.expression import Call, Const, UnaryOp, VirtualVariable, VirtualVariableCategory
from angr.ailment.statement import Assignment, Return, SideEffectStatement
from angr.knowledge_plugins.functions import Function


class TestAILSimplifierUnifyRefs(unittest.TestCase):
    @staticmethod
    def _simplify(address_taken: bool) -> list:
        # a devirtualized VM body: s = rdi (rdi live on entry); f(&s) or f(); return s
        proj = angr.load_shellcode(b"\xc3", "AMD64")
        proj.vm_deobfuscation = True
        rdi = VirtualVariable(5, 25, 64, VirtualVariableCategory.REGISTER, oident=proj.arch.registers["rdi"][0])

        def slot(idx: int) -> VirtualVariable:
            return VirtualVariable(idx, 20, 64, VirtualVariableCategory.STACK, oident=-24)

        args = [UnaryOp(13, "Reference", slot(2), bits=64)] if address_taken else []
        block = Block(
            0x401000,
            0x10,
            statements=[
                Assignment(0, slot(1), rdi, ins_addr=0x401000),
                SideEffectStatement(1, Call(11, Const(12, 0x402000, 64), args=args), ins_addr=0x401004),
                Return(2, [slot(3)], ins_addr=0x40100C),
            ],
            idx=0,
        )
        graph = networkx.DiGraph()
        graph.add_node(block)
        func = Function(proj.kb.functions, 0x401000)
        simp = proj.analyses.AILSimplifier(func, func_graph=graph, ail_manager=ailment.Manager(), unify_variables=True)
        return next(iter(simp.func_graph)).statements

    def test_copy_of_entry_register_whose_address_is_taken_is_kept(self):
        # the callee may write the slot; &rdi is no address at all
        stmts = self._simplify(True)
        ret = stmts[-1].ret_exprs[0]
        assert isinstance(ret, VirtualVariable) and ret.was_stack, stmts
        ref = stmts[-2].expr.args[0]
        assert ref.operand.was_stack, stmts

    def test_referenced_stack_copy_of_argument_register_outside_vms(self):
        # push esi; xchg [esp], eax; call f; add esp, 4; ret      f: mov eax, [esp+4]; ret
        # the slot holds a copy of esi that the exchange overwrites; it is no alias of esi (no &esi)
        proj = angr.load_shellcode(
            bytes.fromhex("56870424e80400000083c404c38b442404c3"), "X86", load_address=0x400000, start_offset=0
        )
        cfg = proj.analyses.CFGFast(normalize=True, function_starts=[0x400000], fail_fast=True, show_progressbar=False)
        proj.analyses.CompleteCallingConventions(recover_variables=False)
        dec = proj.analyses.Decompiler(cfg.functions[0x400000], cfg=cfg, fail_fast=True)
        assert dec.codegen is not None and dec.codegen.text is not None
        text = dec.codegen.text
        m = re.search(r"atomic_exchange\(&(\w+),", text)
        assert m is not None, text
        assert re.search(rf"\b{m.group(1)};\s+// \[bp-", text), text

    def test_copy_of_entry_register_is_unified(self):
        ret = self._simplify(False)[-1].ret_exprs[0]
        assert isinstance(ret, VirtualVariable) and ret.was_reg


if __name__ == "__main__":
    unittest.main()

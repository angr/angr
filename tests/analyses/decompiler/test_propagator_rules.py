#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,no-member
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import unittest

import networkx

import angr
from angr import ailment
from angr.ailment.block import Block
from angr.ailment.expression import (
    ITE,
    BinaryOp,
    Call,
    Const,
    Load,
    Phi,
    StackBaseOffset,
    Tmp,
    UnaryOp,
    VirtualVariable,
    VirtualVariableCategory,
)
from angr.ailment.statement import Assignment, Jump, Return, SideEffectStatement, Store
from angr.analyses.s_propagator import SPropagator
from angr.knowledge_plugins.functions import Function
from tests.common import WORKER, bin_location, load_project_with_scoped_cfg, print_decompilation_result

test_location = os.path.join(bin_location, "tests")

# the two blocks of the hand-built graph in the tmp-propagation tests below
BLOCK_A = 0x401000
BLOCK_B = 0x401010


class TestPropagatorRules(unittest.TestCase):
    def test_propagator_do_not_propagate_constants_through_unsafe_stack_variables(self):
        bin_path = os.path.join(
            test_location, "x86_64", "windows", "03fb29dab8ab848f15852a37a1c04aa65289c0160d9200dceff64d890b3290dd"
        )
        proj = angr.Project(bin_path, auto_load_libs=False)

        cfg = proj.analyses.CFGFast(show_progressbar=not WORKER, fail_fast=True, normalize=True)

        func = cfg.functions[0x13640]
        assert func is not None
        dec = proj.analyses.Decompiler(func, cfg=cfg)
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)

        # incorrect propagation of stack variable at bp-0x10 will result in missing code blocks and function calls
        assert dec.codegen.text.count("ObfDereferenceObject(") == 1
        assert dec.codegen.text.count("ObReferenceObjectByPointer(") == 1
        assert dec.codegen.text.count("ExFreePoolWithTag") == 1

    def test_propagator_do_not_create_overly_deep_expressions(self):
        bin_path = os.path.join(
            test_location, "x86_64", "windows", "94def0c6290dbc32ebb9a6e72d2f76d0ffe66365606efeef952834768e47f1d8"
        )
        proj = angr.Project(bin_path, auto_load_libs=False)

        cfg = proj.analyses.CFGFast(show_progressbar=not WORKER, fail_fast=True, normalize=True)

        func = cfg.functions[0x14000F190]
        assert func is not None
        dec = proj.analyses.Decompiler(func, cfg=cfg)
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)

        # ensure that each line contains at most five operators
        for line in dec.codegen.text.splitlines():
            if line.strip() == "":
                continue
            op_count = line.count("+") + line.count("-") + line.count("^") + line.count("ROL") + line.count("ROR")
            if "return" in line:
                assert op_count <= 12
            else:
                assert op_count <= 7

    def test_spropagator_do_not_propagate_vvars_defined_in_assignment_src(self):
        bin_path = os.path.join(
            test_location, "i386", "windows", "0c694dfa7ad465bded90c4faf63100c7008b5efc4bc49b38644a9770b42669b0"
        )
        proj, _ = load_project_with_scoped_cfg(bin_path, 0x4847D4, expand_call_tree=False, run_ccc=False)
        dec = proj.analyses.Decompiler(0x4847D4, fail_fast=True)
        # it should not raise any exceptions; it was triggering an assertion error before this fix at
        # ailment/expression.py:
        #
        # assert not isinstance(offset, Const) or offset.value * 8 + value.bits <= base.bits
        #
        # this is because we were trying to propagate Reference(vvar_780) to vvar_780 (16-byte) in a statement of
        # `vvar_781 = Reference(vvar_780)`, where both vvar_780 and vvar_781 are defined at the same statement.
        assert dec.codegen is not None and dec.codegen.text is not None

    @staticmethod
    def _load_propagated_across_two_blocks(tmp_address: bool) -> SPropagator:
        """
        Run SPropagator over two blocks where a register is defined by a Load in the first one and
        used once in the second one. With ``tmp_address`` the Load reads through a tmp computed in
        the first block, which is what a p-code effective-address calculation looks like.
        """
        proj = angr.Project(os.path.join(test_location, "i386", "fauxware"), auto_load_libs=False)
        bits = proj.arch.bits

        def vvar(varid: int, vvar_bits: int = 32) -> VirtualVariable:
            return VirtualVariable(varid, varid, vvar_bits, VirtualVariableCategory.REGISTER, oident=16)

        addr = Tmp(90, 0, bits) if tmp_address else Const(90, 0x500000, bits)
        block_a = Block(
            BLOCK_A,
            8,
            statements=[
                # tmp 0 holds the address, and is defined in this block only
                Assignment(
                    0, Tmp(91, 0, bits), BinaryOp(92, "Add", [vvar(10, bits), vvar(11, bits)]), ins_addr=BLOCK_A
                ),
                Assignment(
                    1,
                    vvar(1),
                    Load(93, addr, 4, proj.arch.memory_endness, ins_addr=BLOCK_A + 4),
                    ins_addr=BLOCK_A + 4,
                ),
                Jump(2, Const(94, BLOCK_B, bits), ins_addr=BLOCK_A + 8),
            ],
            idx=0,
        )
        block_b = Block(
            BLOCK_B,
            8,
            statements=[
                Assignment(0, vvar(2), BinaryOp(95, "Add", [vvar(1), Const(96, 1, 32)]), ins_addr=BLOCK_B),
                Return(1, [vvar(2)], ins_addr=BLOCK_B + 4),
            ],
            idx=0,
        )
        graph = networkx.DiGraph()
        graph.add_edge(block_a, block_b)
        return SPropagator(
            proj,
            Function(proj.kb.functions, BLOCK_A),
            ail_manager=ailment.Manager(),
            func_graph=graph,
            only_consts=False,
        )

    @staticmethod
    def _replacements_in(prop: SPropagator, block_addr: int) -> dict:
        return {
            (loc, expr): value
            for loc, reps in prop.replacements.items()
            if loc.block_addr == block_addr
            for expr, value in reps.items()
        }

    def test_spropagator_do_not_propagate_loads_with_tmps_to_other_blocks(self):
        prop = self._load_propagated_across_two_blocks(tmp_address=True)
        landed = self._replacements_in(prop, BLOCK_B)
        assert all(not isinstance(getattr(value, "addr", None), Tmp) for value in landed.values()), (
            f"a Load with tmps inside is propagated to another block: {landed}"
        )

    def test_spropagator_propagates_constant_tmp_vvars_to_every_use(self):
        proj = angr.Project(os.path.join(test_location, "i386", "fauxware"), auto_load_libs=False)
        tmp_vvar = lambda: VirtualVariable(1, 1, 32, VirtualVariableCategory.TMP, oident=3)
        reg = lambda varid: VirtualVariable(varid, varid, 32, VirtualVariableCategory.REGISTER, oident=16)
        block_a = Block(
            BLOCK_A,
            8,
            statements=[
                Assignment(0, tmp_vvar(), Const(90, 5213208, 32), ins_addr=BLOCK_A),
                Assignment(1, reg(2), BinaryOp(91, "Xor", [tmp_vvar(), Const(92, 7, 32)]), ins_addr=BLOCK_A + 4),
                Jump(2, Const(93, BLOCK_B, 32), ins_addr=BLOCK_A + 8),
            ],
            idx=0,
        )
        block_b = Block(
            BLOCK_B,
            8,
            statements=[
                Assignment(0, reg(3), BinaryOp(94, "Add", [tmp_vvar(), reg(2)]), ins_addr=BLOCK_B),
                Return(1, [reg(3)], ins_addr=BLOCK_B + 4),
            ],
            idx=0,
        )
        graph = networkx.DiGraph()
        graph.add_edge(block_a, block_b)
        prop = SPropagator(
            proj,
            Function(proj.kb.functions, BLOCK_A),
            ail_manager=ailment.Manager(),
            func_graph=graph,
            only_consts=False,
        )
        for block_addr in (BLOCK_A, BLOCK_B):
            landed = self._replacements_in(prop, block_addr)
            assert any(
                isinstance(expr, VirtualVariable)
                and expr.varid == 1
                and isinstance(value, Const)
                and value.value == 5213208
                for (_, expr), value in landed.items()
            ), (hex(block_addr), landed)

    def test_spropagator_phi_sp_holds_its_block_entry_offset(self):
        # sp = phi(...); STORE(sp - 8) (pushfq, sp -= 8); x = Load(sp - 8) (popfq, sp += 8)
        # a block-spanning tmp copy of the phi'd sp lands its uses past the push; both must name the same slot
        proj = angr.load_shellcode(b"\xc3", "AMD64")
        sp = proj.arch.sp_offset
        blk, push, pop = 0x400030, 0x400031, 0x400035

        class _SPT:
            before = {blk: -0x10, push: -0x10, pop: -0x18}
            after = {blk: -0x10, push: -0x18, pop: -0x10}

            def offset_before(self, ins, reg):
                return self.before.get(ins) if reg == sp else None

            def offset_after(self, ins, reg):
                return self.after.get(ins) if reg == sp else None

        def rsp(varid: int) -> VirtualVariable:
            return VirtualVariable(varid, varid, 64, VirtualVariableCategory.REGISTER, oident=sp)

        def slot(atom: int, ins: int) -> BinaryOp:
            return BinaryOp(atom, "Sub", [rsp(1), Const(atom + 1, 8, 64)], False, ins_addr=ins)

        block = Block(
            blk,
            8,
            statements=[
                Assignment(0, rsp(1), Phi(10, 64, [((0x400010, 0), rsp(2)), ((0x400020, 0), rsp(3))]), ins_addr=blk),
                Store(1, slot(20, push), Const(22, 0x246, 64), 8, "Iend_LE", ins_addr=push),
                Assignment(2, Tmp(30, 0, 64), Load(31, slot(32, pop), 8, "Iend_LE", ins_addr=pop), ins_addr=pop),
                Return(3, [Tmp(40, 0, 64)], ins_addr=pop),
            ],
            idx=0,
        )
        prop = SPropagator(proj, block, ail_manager=ailment.Manager(), stack_pointer_tracker=_SPT(), func_addr=blk)
        offsets = {
            loc.stmt_idx: value.offset
            for loc, reps in prop.replacements.items()
            for expr, value in reps.items()
            if isinstance(expr, VirtualVariable) and expr.varid == 1 and isinstance(value, StackBaseOffset)
        }
        assert offsets == {1: -0x10, 2: -0x10}, offsets

    @staticmethod
    def _call_push_sp(call_sp_adjustments, sp_after_call: bool = False) -> SPropagator:
        # A: sp_2 = sp-0x48 (the call's push); call f(sp_2)    C: sp_3 = sp-0x40
        # B (return site): sp_4 = phi(sp_2, sp_3); STORE(sp_2 + 0x20) = 5
        # no StackPointerTracker offsets (it lost sp, e.g. after an aligned VM frame)
        proj = angr.load_shellcode(b"\xc3", "AMD64")
        sp = proj.arch.sp_offset
        call_ins, c_addr = BLOCK_A + 4, 0x401020

        def rsp(varid: int) -> VirtualVariable:
            return VirtualVariable(varid, varid, 64, VirtualVariableCategory.REGISTER, oident=sp)

        block_a = Block(
            BLOCK_A,
            9,
            statements=[
                (
                    # StackDeadStoreEliminator's rewrite: the variable holds sp after the call
                    Assignment(0, rsp(2), StackBaseOffset(10, 64, -0x40), ins_addr=call_ins, sp_after_call=True)
                    if sp_after_call
                    else Assignment(0, rsp(2), StackBaseOffset(10, 64, -0x48), ins_addr=call_ins)
                ),
                SideEffectStatement(
                    1, Call(11, Const(12, 0x402000, 64), args=[] if sp_after_call else [rsp(2)]), ins_addr=call_ins
                ),
            ],
            idx=0,
        )
        block_c = Block(
            c_addr,
            4,
            statements=[
                Assignment(0, rsp(3), StackBaseOffset(20, 64, -0x40), ins_addr=c_addr),
                Jump(1, Const(21, BLOCK_B, 64), ins_addr=c_addr),
            ],
            idx=0,
        )
        block_b = Block(
            BLOCK_B,
            8,
            statements=[
                Assignment(0, rsp(4), Phi(30, 64, [((BLOCK_A, 0), rsp(2)), ((c_addr, 0), rsp(3))]), ins_addr=BLOCK_B),
                Store(
                    1,
                    BinaryOp(31, "Add", [rsp(2), Const(32, 0x20, 64)], False),
                    Const(33, 5, 32),
                    4,
                    "Iend_LE",
                    ins_addr=BLOCK_B,
                ),
                Return(2, [rsp(4)], ins_addr=BLOCK_B + 4),
            ],
            idx=0,
        )
        graph = networkx.DiGraph()
        graph.add_edge(block_a, block_b)
        graph.add_edge(block_c, block_b)
        return SPropagator(
            proj,
            Function(proj.kb.functions, BLOCK_A),
            ail_manager=ailment.Manager(),
            func_graph=graph,
            call_sp_adjustments=call_sp_adjustments,
        )

    def test_spropagator_sp_defined_by_a_call_push_includes_the_ret_pop_after_the_call(self):
        def sp_offsets(prop: SPropagator) -> dict:
            return {
                (loc.block_addr, loc.stmt_idx, expr.varid): value.offset
                for loc, reps in prop.replacements.items()
                for expr, value in reps.items()
                if isinstance(expr, VirtualVariable) and isinstance(value, StackBaseOffset)
            }

        # the call itself reads the push; the return site reads sp after the callee popped the return address
        offsets = sp_offsets(self._call_push_sp({BLOCK_A + 4: 8}))
        assert offsets[(BLOCK_A, 1, 2)] == -0x48, offsets
        assert offsets[(BLOCK_B, 1, 2)] == -0x40, offsets
        assert offsets[(BLOCK_B, 2, 4)] == -0x40, offsets
        # the callee's sp effect is unknown: nothing after the call is resolved
        offsets = sp_offsets(self._call_push_sp({BLOCK_A + 4: None}))
        assert offsets[(BLOCK_A, 1, 2)] == -0x48, offsets
        assert (BLOCK_B, 1, 2) not in offsets and (BLOCK_B, 2, 4) not in offsets, offsets
        # a definition that already holds sp after the call is not adjusted again
        offsets = sp_offsets(self._call_push_sp({BLOCK_A + 4: 8}, sp_after_call=True))
        assert offsets[(BLOCK_B, 1, 2)] == -0x40, offsets
        assert offsets[(BLOCK_B, 2, 4)] == -0x40, offsets

    @staticmethod
    def _vm_slot_read_after_call(src_kind: str, address_taken: bool) -> dict:
        # s_24 = <src>; call f(&s_24) (or f()); return s_24, in a devirtualized VM body
        proj = angr.load_shellcode(b"\xc3", "AMD64")
        proj.vm_deobfuscation = True

        def slot(varid: int, offset: int, bits: int = 64) -> VirtualVariable:
            return VirtualVariable(varid, varid, bits, VirtualVariableCategory.STACK, oident=offset)

        if src_kind == "stack_address":
            src = UnaryOp(10, "Reference", slot(6, 0, 8), bits=64)
        else:
            src = ITE(
                10,
                VirtualVariable(11, 7, 1, VirtualVariableCategory.REGISTER, oident=16),
                Const(12, 1, 64),
                Const(13, 2, 64),
            )
        args = [UnaryOp(20, "Reference", slot(5, -24), bits=64)] if address_taken else []
        block = Block(
            BLOCK_A,
            9,
            statements=[
                Assignment(0, slot(5, -24), src, ins_addr=BLOCK_A),
                SideEffectStatement(1, Call(21, Const(22, 0x402000, 64), args=args), ins_addr=BLOCK_A + 2),
                Return(2, [slot(5, -24)], ins_addr=BLOCK_A + 7),
            ],
            idx=0,
        )
        graph = networkx.DiGraph()
        graph.add_node(block)
        prop = SPropagator(proj, Function(proj.kb.functions, BLOCK_A), ail_manager=ailment.Manager(), func_graph=graph)
        return {
            (loc.stmt_idx, expr.varid): value
            for loc, reps in prop.replacements.items()
            for expr, value in reps.items()
            if isinstance(expr, VirtualVariable)
        }

    def test_spropagator_vm_does_not_propagate_a_slot_whose_address_is_taken(self):
        # the callee may write the slot through its address, so the read after the call is not the definition
        for src_kind in ("stack_address", "const_arm_ite"):
            assert (2, 5) not in self._vm_slot_read_after_call(src_kind, True), src_kind
            # control: without the reference the VM rules propagate it
            assert (2, 5) in self._vm_slot_read_after_call(src_kind, False), src_kind


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os.path
import unittest

import angr
from angr import ailment
from angr.analyses.decompiler.optimization_passes.base_ptr_save_simplifier import (
    BasePointerSaveSimplifier,
)
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


def _get_block(clinic, addr):
    for block in clinic.graph.nodes():
        if block.addr == addr:
            return block
    return None


def check_bp_save_fauxware(arch):
    p = angr.Project(os.path.join(test_location, arch, "fauxware"), auto_load_libs=False)
    cfg = p.analyses.CFGFast(normalize=True)
    main = p.kb.functions["main"]
    optimization_passes = [BasePointerSaveSimplifier]
    dra = p.analyses.Decompiler(main, cfg=cfg, optimization_passes=optimization_passes)
    first_block_stmts = dra.codegen._sequence.nodes[0].nodes[0].statements
    for stmt in first_block_stmts:
        if isinstance(stmt, ailment.Stmt.Store):
            assert not (isinstance(stmt.data, ailment.Expr.Register) and stmt.data.reg_offset == p.arch.bp_offset) or (
                isinstance(stmt.data, ailment.Expr.StackBaseOffset) and stmt.data.offset == 0
            )


# pylint: disable=missing-class-docstring
# pylint: disable=no-self-use
class TestBaseptrSaveSimplifier(unittest.TestCase):
    def test_baseptr_save_simplifier_amd64(self):
        # decompile all:main and make sure the first and the last blocks do not save or restore to rbp
        bin_path = os.path.join(test_location, "x86_64", "all")
        proj = angr.Project(bin_path, auto_load_libs=False, load_debug_info=True)

        cfg = proj.analyses.CFG(data_references=True, normalize=True)

        optimization_passes = [BasePointerSaveSimplifier]
        main_func = cfg.functions["main"]
        dec = proj.analyses.Decompiler(main_func, cfg=cfg, optimization_passes=optimization_passes)

        entry_block = _get_block(dec.clinic, main_func.addr)
        endpoint_block = _get_block(dec.clinic, next(iter(main_func.endpoints)).addr)

        assert entry_block is not None
        assert endpoint_block is not None

        for stmt in entry_block.statements:
            if isinstance(stmt, ailment.Stmt.Store) and isinstance(stmt.data, ailment.Expr.StackBaseOffset):
                assert False, "Found a base-pointer saving statement in the first block."

        for stmt in endpoint_block.statements:
            if (
                isinstance(stmt, ailment.Stmt.Assignment)
                and isinstance(stmt.dst, ailment.Expr.Register)
                and stmt.dst.reg_offset == proj.arch.bp_offset
            ):
                assert False, "Found a base-pointer restoring statement in the last block."

    def test_bp_save_amd64_fauxware(self):
        check_bp_save_fauxware("x86_64")

    def test_bp_save_armel_fauxware(self):
        check_bp_save_fauxware("armel")

    @staticmethod
    def _decompile(code: bytes):
        proj = angr.load_shellcode(code, "AMD64", load_address=0x400000)
        cfg = proj.analyses.CFGFast(normalize=True)
        dec = proj.analyses.Decompiler(proj.kb.functions[0x400000], cfg=cfg.model, fail_fast=True)
        assert dec.codegen is not None and dec.codegen.text is not None
        return dec

    def test_frame_address_slot_that_is_read_is_not_a_bp_save(self):
        # mov rax, rsp; sub rsp, 0x18; mov [rsp+8], rax; mov rax, [rsp+8]; mov [rdi], rax; add rsp, 0x18; ret
        dec = self._decompile(bytes.fromhex("4889e04883ec184889442408488b4424084889074883c418c3"))
        assert "saved_bp" not in {item.name for item in dec.clinic.stack_items.values()}
        lines = [ln.strip() for ln in dec.codegen.text.splitlines()]
        stored = next(ln for ln in lines if ln.startswith("*a0 = "))
        slot = stored[len("*a0 = ") : -1]
        assert any(ln.startswith(f"{slot} = &") for ln in lines), dec.codegen.text

    def test_bp_save_read_only_by_the_restore(self):
        p = angr.Project(os.path.join(test_location, "x86_64", "fauxware"), auto_load_libs=False)
        cfg = p.analyses.CFGFast(normalize=True)
        dec = p.analyses.Decompiler(p.kb.functions["main"], cfg=cfg)
        assert "saved_bp" in {item.name for item in dec.clinic.stack_items.values()}


if __name__ == "__main__":
    unittest.main()

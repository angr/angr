#!/usr/bin/env python3
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import unittest
from types import SimpleNamespace

import archinfo

import angr
from angr import ailment
from angr.analyses.decompiler import Decompiler
from angr.analyses.decompiler.clinic import Clinic
from tests.common import bin_location, load_project_with_scoped_cfg, print_decompilation_result

test_location = os.path.join(bin_location, "tests")
openssh_scp = os.path.join(test_location, "x86_64", "decompiler", "openssh_scp_O2_noinline")


@unittest.skipUnless(os.path.isfile(openssh_scp), f"missing test binary: {openssh_scp}")
class TestX87CallUsedClearing(unittest.TestCase):
    @staticmethod
    def _convert(block):
        return ailment.IRSBConverter.convert(block.vex, ailment.Manager(arch=block.arch))

    @staticmethod
    def _globexp2_return_block(proj):
        # Compiled with GCC 11.4.0 -O2 -fzero-call-used-regs=all.
        return proj.factory.block(0x4326CC, size=145, cross_insn_opt=False)

    @staticmethod
    def _block_view(block, *, arch=None, data=None):
        return SimpleNamespace(
            addr=block.addr,
            arch=block.arch if arch is None else arch,
            bytes=block.bytes if data is None else data,
            size=block.size,
        )

    @staticmethod
    def _x87_ins_addrs(block):
        return {
            insn.address
            for insn in block.capstone.insns
            if (insn.mnemonic, insn.op_str) in {("fldz", ""), ("fstp", "st(0)")}
        }

    def test_globexp2_decompilation_has_no_unsupported_x87_clear(self):
        proj, cfg = load_project_with_scoped_cfg(
            openssh_scp,
            0x432550,
            window=0x600,
            expand_call_tree=False,
            run_ccc=False,
            project_kwargs={"auto_load_libs": False},
        )
        func = proj.kb.functions[0x432550]
        assert func.name == "globexp2"
        for structurer in ("sailr", "phoenix"):
            with self.subTest(structurer=structurer):
                dec = proj.analyses[Decompiler].prep(fail_fast=True)(
                    func,
                    cfg=cfg.model,
                    preset="full",
                    options=[("structurer_cls", structurer)],
                    use_cache=False,
                )
                assert dec.codegen is not None and dec.codegen.text is not None
                print_decompilation_result(dec)

                assert "unsupported instruction" not in dec.codegen.text

    def test_only_expected_dirty_statements_are_removed(self):
        proj = angr.Project(openssh_scp, auto_load_libs=False)
        block = self._globexp2_return_block(proj)
        converted = self._convert(block)
        before = list(converted.statements)
        x87_ins_addrs = self._x87_ins_addrs(block)
        x87_stmts = [stmt for stmt in before if stmt.tags.get("ins_addr") in x87_ins_addrs]
        x87_dirty_stmts = [stmt for stmt in x87_stmts if isinstance(stmt, ailment.Stmt.DirtyStatement)]
        x87_semantic_stmts = [stmt for stmt in x87_stmts if not isinstance(stmt, ailment.Stmt.DirtyStatement)]
        return_stmt = converted.statements[-1]

        assert len(x87_ins_addrs) == 16
        assert len(x87_stmts) == 184
        assert len(x87_dirty_stmts) == 40
        assert len(x87_semantic_stmts) == 144
        assert isinstance(return_stmt, ailment.Stmt.Return)

        Clinic._remove_call_used_x87_clearing(block, converted)

        assert all(id(stmt) not in {id(candidate) for candidate in converted.statements} for stmt in x87_dirty_stmts)
        assert all(any(stmt is candidate for candidate in converted.statements) for stmt in x87_semantic_stmts)
        assert any(return_stmt is candidate for candidate in converted.statements)

    def test_ordinary_x87_semantics_are_preserved(self):
        proj = angr.Project(os.path.join(test_location, "x86_64", "calc"), auto_load_libs=False)

        blocks = (
            proj.factory.block(0x401F00, size=0x11, cross_insn_opt=False),
            proj.factory.block(0x401F25, size=5, cross_insn_opt=False),
            proj.factory.block(0x4020F2, size=0x25, cross_insn_opt=False),
        )
        for block in blocks:
            with self.subTest(block_addr=block.addr):
                converted = self._convert(block)
                before = list(converted.statements)
                assert any(isinstance(stmt, ailment.Stmt.DirtyStatement) for stmt in before)

                Clinic._remove_call_used_x87_clearing(block, converted)

                assert converted.statements == before

    def test_nonmatch_does_not_materialize_vex(self):
        proj = angr.Project(openssh_scp, auto_load_libs=False)
        block = proj.factory.block(0x432550, size=16, cross_insn_opt=False)
        assert block._vex is None
        assert block._capstone is None

        converted = ailment.Block(block.addr, block.size)
        Clinic._remove_call_used_x87_clearing(block, converted)

        assert block._vex is None
        assert block._capstone is None

    def test_near_matches_are_preserved(self):
        proj = angr.Project(openssh_scp, auto_load_libs=False)
        block = self._globexp2_return_block(proj)
        data = block.bytes
        x87_start = len(data) - 125
        block_views = {"wrong architecture": self._block_view(block, arch=archinfo.ArchX86())}
        for name, byte_idx in {
            "seven fldz": x87_start,
            "seven fstp": x87_start + 16,
            "intervening x87 operation": x87_start + 2,
            "incomplete clearing suffix": x87_start + 34,
            "reordered clearing suffix": x87_start + 32,
        }.items():
            altered_data = bytearray(data)
            altered_data[byte_idx] ^= 1
            block_views[name] = self._block_view(block, data=bytes(altered_data))

        for name, block_view in block_views.items():
            with self.subTest(name=name):
                converted = self._convert(block)
                before_ids = [id(stmt) for stmt in converted.statements]

                Clinic._remove_call_used_x87_clearing(block_view, converted)

                assert [id(stmt) for stmt in converted.statements] == before_ids

        converted = self._convert(block)
        converted.statements[-1] = ailment.Stmt.Jump(
            None, ailment.Expr.Const(None, 0xDEADBEEF, proj.arch.bits), ins_addr=block.addr + block.size - 1
        )
        before_ids = [id(stmt) for stmt in converted.statements]
        Clinic._remove_call_used_x87_clearing(block, converted)
        assert [id(stmt) for stmt in converted.statements] == before_ids

    def test_unexpected_ail_shape_is_preserved(self):
        proj = angr.Project(openssh_scp, auto_load_libs=False)
        block = self._globexp2_return_block(proj)
        x87_ins_addrs = self._x87_ins_addrs(block)

        converted = self._convert(block)
        dirty_idx = next(
            i
            for i, stmt in enumerate(converted.statements)
            if isinstance(stmt, ailment.Stmt.DirtyStatement) and stmt.tags.get("ins_addr") in x87_ins_addrs
        )
        converted.statements.pop(dirty_idx)
        before_ids = [id(stmt) for stmt in converted.statements]
        Clinic._remove_call_used_x87_clearing(block, converted)
        assert [id(stmt) for stmt in converted.statements] == before_ids

        converted = self._convert(block)
        dirty_stmt = next(
            stmt
            for stmt in converted.statements
            if isinstance(stmt, ailment.Stmt.DirtyStatement) and stmt.tags.get("ins_addr") in x87_ins_addrs
        )
        dirty_idx = next(i for i, stmt in enumerate(converted.statements) if stmt is dirty_stmt)
        unexpected_dirty = ailment.Expr.DirtyExpression(
            dirty_stmt.dirty.idx,
            "PutI(904:F64x8)[unexpected] = value",
            [],
            bits=0,
            **dirty_stmt.dirty.tags,
        )
        converted.statements[dirty_idx] = ailment.Stmt.DirtyStatement(
            dirty_stmt.idx, unexpected_dirty, **dirty_stmt.tags
        )
        before_ids = [id(stmt) for stmt in converted.statements]
        Clinic._remove_call_used_x87_clearing(block, converted)
        assert [id(stmt) for stmt in converted.statements] == before_ids


if __name__ == "__main__":
    unittest.main()

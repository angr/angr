#!/usr/bin/env python3
__package__ = __package__ or "tests.analyses"  # pylint:disable=redefined-builtin

import types
import unittest

from angr import ailment
import archinfo

from angr.analyses.decompiler.block_simplifier import BlockSimplifier
from angr.analyses.propagator.engine_ail import SimEnginePropagatorAIL
from angr.analyses.propagator.stack_load_staleness import has_stale_stack_load_source
from angr.code_location import CodeLocation


class _FakeDefinition:
    def __init__(self, codeloc):
        self.codeloc = codeloc


class _FakeRDA:
    def __init__(self, codeloc):
        self._definition = _FakeDefinition(codeloc)

    def get_defs(self, *_, **__):  # pylint:disable=unused-argument
        return {self._definition}


class TestStackLoadStaleness(unittest.TestCase):
    @staticmethod
    def _block(overwrite_offset=-0x30):
        arch = archinfo.arch_from_id("AMD64")
        load_offset = -0x30
        dst_offset = -0x20
        load_expr = ailment.Expr.Load(
            None,
            ailment.Expr.StackBaseOffset(None, arch.bits, load_offset),
            arch.bytes,
            arch.memory_endness,
        )
        tmp0 = ailment.Expr.Tmp(None, None, 0, arch.bits)
        tmp1 = ailment.Expr.Tmp(None, None, 1, arch.bits)
        block = ailment.Block(
            0x400000,
            4,
            statements=[
                ailment.Stmt.Assignment(0, tmp0, load_expr),
                ailment.Stmt.Assignment(1, tmp1, tmp0),
                ailment.Stmt.Store(
                    2,
                    ailment.Expr.StackBaseOffset(None, arch.bits, overwrite_offset),
                    ailment.Expr.Const(None, None, 0x1234, arch.bits),
                    arch.bytes,
                    arch.memory_endness,
                ),
                ailment.Stmt.Store(
                    3,
                    ailment.Expr.StackBaseOffset(None, arch.bits, dst_offset),
                    tmp1,
                    arch.bytes,
                    arch.memory_endness,
                ),
            ],
        )
        return arch, block, load_expr, tmp0, tmp1

    @staticmethod
    def _transitive_copy_block(overwrite_offset=-0x30):
        arch = archinfo.arch_from_id("AMD64")
        source_offset = -0x30
        copy_offset = -0x20
        dst_offset = -0x10
        load_copy = ailment.Expr.Load(
            None,
            ailment.Expr.StackBaseOffset(None, arch.bits, copy_offset),
            arch.bytes,
            arch.memory_endness,
        )
        tmp0 = ailment.Expr.Tmp(None, None, 0, arch.bits)
        block = ailment.Block(
            0x401000,
            5,
            statements=[
                ailment.Stmt.Store(
                    0,
                    ailment.Expr.StackBaseOffset(None, arch.bits, source_offset),
                    ailment.Expr.Const(None, None, 0x1234, arch.bits),
                    arch.bytes,
                    arch.memory_endness,
                ),
                ailment.Stmt.Store(
                    1,
                    ailment.Expr.StackBaseOffset(None, arch.bits, copy_offset),
                    ailment.Expr.Load(
                        None,
                        ailment.Expr.StackBaseOffset(None, arch.bits, source_offset),
                        arch.bytes,
                        arch.memory_endness,
                    ),
                    arch.bytes,
                    arch.memory_endness,
                ),
                ailment.Stmt.Store(
                    2,
                    ailment.Expr.StackBaseOffset(None, arch.bits, overwrite_offset),
                    ailment.Expr.Const(None, None, 0x5678, arch.bits),
                    arch.bytes,
                    arch.memory_endness,
                ),
                ailment.Stmt.Assignment(3, tmp0, load_copy),
                ailment.Stmt.Store(
                    4,
                    ailment.Expr.StackBaseOffset(None, arch.bits, dst_offset),
                    tmp0,
                    arch.bytes,
                    arch.memory_endness,
                ),
            ],
        )
        return block, load_copy

    @staticmethod
    def _introduced_load_replacement_block(overwrite_offset=-0x30):
        arch = archinfo.arch_from_id("AMD64")
        source_offset = -0x30
        copy_offset = -0x20
        dst_offset = -0x10
        tmp0 = ailment.Expr.Tmp(None, None, 0, arch.bits)
        load_copy = ailment.Expr.Load(
            None,
            ailment.Expr.StackBaseOffset(None, arch.bits, copy_offset),
            arch.bytes,
            arch.memory_endness,
        )
        block = ailment.Block(
            0x402000,
            4,
            statements=[
                ailment.Stmt.Store(
                    0,
                    ailment.Expr.StackBaseOffset(None, arch.bits, source_offset),
                    ailment.Expr.Const(None, None, 0x1234, arch.bits),
                    arch.bytes,
                    arch.memory_endness,
                ),
                ailment.Stmt.Store(
                    1,
                    ailment.Expr.StackBaseOffset(None, arch.bits, copy_offset),
                    ailment.Expr.Load(
                        None,
                        ailment.Expr.StackBaseOffset(None, arch.bits, source_offset),
                        arch.bytes,
                        arch.memory_endness,
                    ),
                    arch.bytes,
                    arch.memory_endness,
                ),
                ailment.Stmt.Store(
                    2,
                    ailment.Expr.StackBaseOffset(None, arch.bits, overwrite_offset),
                    ailment.Expr.Const(None, None, 0x5678, arch.bits),
                    arch.bytes,
                    arch.memory_endness,
                ),
                ailment.Stmt.Store(
                    3,
                    ailment.Expr.StackBaseOffset(None, arch.bits, dst_offset),
                    tmp0,
                    arch.bytes,
                    arch.memory_endness,
                ),
            ],
        )
        return block, tmp0, load_copy

    def test_detects_stale_stack_load_through_tmp_chain(self):
        _, block, _, tmp0, _ = self._block()

        assert has_stale_stack_load_source(
            block,
            tmp0,
            CodeLocation(block.addr, 1),
            CodeLocation(block.addr, 3),
        )

    def test_allows_stack_load_when_no_overlapping_store_intervenes(self):
        _, block, _, tmp0, _ = self._block(overwrite_offset=-0x100)

        assert not has_stale_stack_load_source(
            block,
            tmp0,
            CodeLocation(block.addr, 1),
            CodeLocation(block.addr, 3),
        )

    def test_detects_stale_transitive_stack_copy_source(self):
        block, load_copy = self._transitive_copy_block()

        assert has_stale_stack_load_source(
            block,
            load_copy,
            CodeLocation(block.addr, 3),
            CodeLocation(block.addr, 4),
        )

    def test_detects_stale_transitive_stack_copy_with_out_of_range_current_stmt_idx(self):
        block, load_copy = self._transitive_copy_block()

        assert has_stale_stack_load_source(
            block,
            load_copy,
            CodeLocation(block.addr, 3),
            CodeLocation(block.addr, 100),
        )

    def test_allows_transitive_stack_copy_when_source_is_not_overwritten(self):
        block, load_copy = self._transitive_copy_block(overwrite_offset=-0x100)

        assert not has_stale_stack_load_source(
            block,
            load_copy,
            CodeLocation(block.addr, 3),
            CodeLocation(block.addr, 4),
        )

    def test_outdated_definition_uses_stale_stack_load_check(self):
        arch, block, load_expr, _, _ = self._block()
        engine = SimEnginePropagatorAIL(
            arch=arch,
            reaching_definitions=_FakeRDA(CodeLocation(block.addr, 0)),
        )
        engine.block = block
        engine.state = types.SimpleNamespace(register_expressions={})

        outdated, has_avoid = engine.is_using_outdated_def(
            load_expr,
            CodeLocation(block.addr, 0),
            CodeLocation(block.addr, 3),
        )

        assert outdated
        assert not has_avoid

    def test_replace_and_build_rejects_stale_tmp_to_stack_load_replacement(self):
        _, block, load_expr, _, tmp1 = self._block()
        replacements = {CodeLocation(block.addr, 3): {tmp1: load_expr}}

        replaced, new_block = BlockSimplifier._replace_and_build(block, replacements, replace_loads=True)

        assert not replaced
        assert new_block is block
        assert block.statements[3].data is tmp1

    def test_replace_and_build_allows_fresh_tmp_to_stack_load_replacement(self):
        _, block, load_expr, _, tmp1 = self._block(overwrite_offset=-0x100)
        replacements = {CodeLocation(block.addr, 3): {tmp1: load_expr}}

        replaced, new_block = BlockSimplifier._replace_and_build(block, replacements, replace_loads=True)

        assert replaced
        assert new_block is not block
        assert new_block.statements[3].data == load_expr

    def test_replace_and_build_rejects_replacement_introducing_stale_stack_copy_load(self):
        block, tmp0, load_copy = self._introduced_load_replacement_block()
        replacements = {CodeLocation(block.addr, 3): {tmp0: load_copy}}

        replaced, new_block = BlockSimplifier._replace_and_build(block, replacements, replace_loads=True)

        assert not replaced
        assert new_block is block
        assert block.statements[3].data is tmp0

    def test_replace_and_build_allows_replacement_introducing_fresh_stack_copy_load(self):
        block, tmp0, load_copy = self._introduced_load_replacement_block(overwrite_offset=-0x100)
        replacements = {CodeLocation(block.addr, 3): {tmp0: load_copy}}

        replaced, new_block = BlockSimplifier._replace_and_build(block, replacements, replace_loads=True)

        assert replaced
        assert new_block is not block
        assert new_block.statements[3].data == load_copy


if __name__ == "__main__":
    unittest.main()

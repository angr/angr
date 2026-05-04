#!/usr/bin/env python3
"""Unit tests for ``StructBuilder``'s pure rebase helper.

Most of ``StructInstantiationSimplifier`` lives in walker callbacks tightly
coupled to ``self.context.project``. The one extractable static helper —
``StructBuilder._rebase_field_exprs`` — is a pure offset arithmetic routine
and can be tested directly.
"""

from __future__ import annotations

from angr.ailment.expression import Const

from angr.rust.optimization_passes.struct_instantiation_simplifier import StructBuilder


def _const(value: int = 0, bits: int = 64) -> Const:
    return Const(0, None, value, bits)


def test_rebase_field_exprs_subtracts_field_offset_from_each_key():
    a, b, c = _const(1), _const(2), _const(3)
    fields = {0: a, 8: b, 16: c}
    rebased = StructBuilder._rebase_field_exprs(fields, field_offset=8)
    # offsets shift down by 8; the entry whose original offset was 0 falls out
    # because rebasing it would give a negative offset.
    assert rebased == {0: b, 8: c}


def test_rebase_field_exprs_drops_offsets_that_become_negative():
    # 0 - 4 = -4, must be dropped; 4 - 4 = 0, kept.
    fields = {0: _const(1), 4: _const(2)}
    rebased = StructBuilder._rebase_field_exprs(fields, field_offset=4)
    assert set(rebased) == {0}


def test_rebase_field_exprs_zero_offset_is_identity():
    fields = {0: _const(1), 8: _const(2), 16: _const(3)}
    rebased = StructBuilder._rebase_field_exprs(fields, field_offset=0)
    assert rebased == fields


def test_rebase_field_exprs_returns_empty_for_empty_input():
    result = StructBuilder._rebase_field_exprs({}, field_offset=8)
    assert isinstance(result, dict)
    assert len(result) == 0


def test_rebase_field_exprs_drops_all_when_offset_exceeds_every_key():
    fields = {0: _const(1), 8: _const(2)}
    result = StructBuilder._rebase_field_exprs(fields, field_offset=100)
    assert isinstance(result, dict)
    assert len(result) == 0

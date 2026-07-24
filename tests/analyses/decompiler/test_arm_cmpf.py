from __future__ import annotations

import angr
from angr import ailment
from angr.ailment.expression import (
    BinaryOp,
    Const,
    Convert,
    Register,
    Tmp,
    UnaryOp,
    VirtualVariable,
    VirtualVariableCategory,
)
from angr.ailment.statement import Assignment, ConditionalJump
from angr.analyses.decompiler.peephole_optimizations import ARMCmpF


def _const(manager, value, bits=32):
    return Const(manager.next_atom(), value, bits)


def _binop(manager, op, lhs, rhs, *, bits=32, signed=False):
    return BinaryOp(manager.next_atom(), op, (lhs, rhs), signed, bits=bits)


def _scale(manager, expr, shift, *, use_multiplication):
    if use_multiplication:
        return _binop(manager, "Mul", expr, _const(manager, 1 << shift))
    return _binop(manager, "Shl", expr, _const(manager, shift, 8))


def _fpscr_high_bits(manager, *, use_multiplication):
    lhs = Convert(manager.next_atom(), 32, 64, False, Register(manager.next_atom(), 184, 32))
    rhs = Convert(manager.next_atom(), 32, 64, False, Register(manager.next_atom(), 188, 32))
    cmpf = _binop(manager, "CmpF", lhs, rhs)

    ix = _binop(
        manager,
        "Or",
        _binop(manager, "And", _binop(manager, "Shr", cmpf, _const(manager, 5, 8)), _const(manager, 3)),
        _binop(manager, "And", cmpf, _const(manager, 1)),
    )
    term_l = _binop(
        manager,
        "Add",
        _binop(
            manager,
            "Shr",
            _binop(
                manager,
                "Sub",
                _scale(
                    manager,
                    _binop(manager, "Xor", ix, _const(manager, 1)),
                    30,
                    use_multiplication=use_multiplication,
                ),
                _const(manager, 1),
            ),
            _const(manager, 29, 8),
        ),
        _const(manager, 1),
    )
    term_r = _binop(
        manager,
        "And",
        _binop(manager, "And", ix, _binop(manager, "Shr", ix, _const(manager, 1, 8))),
        _const(manager, 1),
    )
    nzcv = _binop(manager, "Sub", term_l, term_r)
    fpscr = _binop(
        manager,
        "Or",
        _binop(manager, "And", Register(manager.next_atom(), 384, 32), _const(manager, 0x0FFF_FFFF)),
        _scale(manager, nzcv, 28, use_multiplication=use_multiplication),
    )
    return _binop(manager, "And", fpscr, _const(manager, 0xF000_0000)), cmpf


def _optimize_condition(condition_builder, *, use_multiplication=False):
    project = angr.load_shellcode(b"\x00\xbf", "ARMCortexM")
    manager = ailment.Manager(arch=project.arch)
    high_bits, cmpf = _fpscr_high_bits(manager, use_multiplication=use_multiplication)

    high_tmp = Tmp(manager.next_atom(), 0, 32)
    high_vvar = VirtualVariable(
        manager.next_atom(),
        1,
        32,
        VirtualVariableCategory.TMP,
        oident=0,
    )
    condition = condition_builder(manager, high_vvar)
    block = ailment.Block(
        0x1000,
        0,
        statements=[
            Assignment(manager.next_atom(), high_tmp, high_bits),
            Assignment(manager.next_atom(), high_vvar, high_tmp),
            ConditionalJump(
                manager.next_atom(),
                condition,
                _const(manager, 0x1010),
                _const(manager, 0x1020),
            ),
        ],
    )

    optimized = ARMCmpF(project, project.kb, manager).optimize(condition, stmt_idx=2, block=block)
    return optimized, cmpf


def test_arm_fpscr_mi_becomes_ordered_less_than():
    def mi(manager, high_bits):
        negative = _binop(manager, "And", high_bits, _const(manager, 0x8000_0000))
        return _binop(manager, "CmpNE", negative, _const(manager, 0), bits=1)

    optimized, cmpf = _optimize_condition(mi)

    assert isinstance(optimized, BinaryOp)
    assert optimized.op == "CmpLT"
    assert optimized.floating_point
    assert all(actual.likes(expected) for actual, expected in zip(optimized.operands, cmpf.operands))


def test_arm_fpscr_le_keeps_unordered_case():
    def le(manager, high_bits):
        zero = _binop(
            manager,
            "CmpNE",
            _binop(manager, "And", high_bits, _const(manager, 0x4000_0000)),
            _const(manager, 0),
            bits=1,
        )
        negative = _binop(
            manager,
            "And",
            _binop(manager, "Shr", high_bits, _const(manager, 31, 8)),
            _const(manager, 1),
        )
        overflow = _binop(
            manager,
            "And",
            _binop(manager, "Shr", high_bits, _const(manager, 28, 8)),
            _const(manager, 1),
        )
        return _binop(
            manager,
            "LogicalOr",
            zero,
            _binop(manager, "CmpNE", negative, overflow, bits=1),
            bits=1,
        )

    optimized, cmpf = _optimize_condition(le, use_multiplication=True)

    assert isinstance(optimized, UnaryOp)
    assert optimized.op == "Not"
    assert isinstance(optimized.operand, BinaryOp)
    assert optimized.operand.op == "CmpGT"
    assert optimized.operand.floating_point
    assert all(actual.likes(expected) for actual, expected in zip(optimized.operand.operands, cmpf.operands))


def test_arm_cmpf_ignores_unrelated_floating_constant_conditions():
    project = angr.load_shellcode(b"\x00\xbf", "ARMCortexM")
    manager = ailment.Manager(arch=project.arch)
    condition = _binop(
        manager,
        "CmpLT",
        Register(manager.next_atom(), 0, 32),
        Const(manager.next_atom(), 1.0, 32),
        bits=1,
    )
    block = ailment.Block(
        0x1000,
        0,
        statements=[
            ConditionalJump(
                manager.next_atom(),
                condition,
                _const(manager, 0x1010),
                _const(manager, 0x1020),
            )
        ],
    )

    assert ARMCmpF(project, project.kb, manager).optimize(condition, stmt_idx=0, block=block) is None

#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import re
import unittest

import angr
from angr import claripy
from angr.ailment import Expr, Manager
from angr.analyses.decompiler.ccall_rewriters.arm64_ccalls import ARM64CCallRewriter
from angr.engines.vex.claripy.ccall import ARM64G_CC_OP_NUMBER, arm64g_calculate_condition
from tests.common import bin_location, load_project_with_scoped_cfg

test_location = os.path.join(bin_location, "tests")

_CMP = {
    "CmpEQ": lambda a, b, s: a == b,
    "CmpNE": lambda a, b, s: a != b,
    "CmpLT": lambda a, b, s: a.SLT(b) if s else a.ULT(b),
    "CmpLE": lambda a, b, s: a.SLE(b) if s else a.ULE(b),
    "CmpGT": lambda a, b, s: a.SGT(b) if s else a.UGT(b),
    "CmpGE": lambda a, b, s: a.SGE(b) if s else a.UGE(b),
}
_ARITH = {
    "Add": lambda a, b: a + b,
    "Sub": lambda a, b: a - b,
    "And": lambda a, b: a & b,
    "Or": lambda a, b: a | b,
    "Xor": lambda a, b: a ^ b,
}


def _to_claripy(expr, regs: dict):
    """Evaluate the AIL a rewriter produces over claripy values, reading registers from ``regs``."""
    if isinstance(expr, Expr.Const):
        return claripy.BVV(expr.value_int, expr.bits)
    if isinstance(expr, Expr.Register):
        return regs[expr.reg_offset]
    if isinstance(expr, Expr.Convert):
        v = _to_claripy(expr.operand, regs)
        if expr.to_bits <= expr.from_bits:
            return v[expr.to_bits - 1 : 0]
        extend = v.sign_extend if expr.is_signed else v.zero_extend
        return extend(expr.to_bits - expr.from_bits)
    assert isinstance(expr, Expr.BinaryOp), expr
    a, b = (_to_claripy(o, regs) for o in expr.operands)
    one, zero = claripy.BVV(1, 1), claripy.BVV(0, 1)
    if expr.op in _CMP:
        return claripy.If(_CMP[expr.op](a, b, expr.signed), one, zero)
    if expr.op in {"LogicalAnd", "LogicalOr"}:
        both = (claripy.And if expr.op == "LogicalAnd" else claripy.Or)(a != 0, b != 0)
        return claripy.If(both, one, zero)
    if expr.op == "Shr":
        return a.LShR(b.zero_extend(a.size() - b.size()))
    return _ARITH[expr.op](a, b)


class TestARM64CCallRewriterSemantics(unittest.TestCase):
    """For register and constant operands, every condition the rewriter produces equals the symbolic engine's
    arm64g_calculate_condition."""

    def test_rewrites_match_vex_semantics(self):
        proj = angr.Project(os.path.join(test_location, "aarch64", "test_division"), auto_load_libs=False)
        x0, x1, x2 = (proj.arch.registers[name][0] for name in ("x0", "x1", "x2"))
        deps = {off: claripy.BVS(name, 64) for off, name in ((x0, "dep1"), (x1, "dep2"), (x2, "dep3"))}
        carries = (Expr.Register(3, x2, 64), Expr.Const(3, 0, 64), Expr.Const(3, 1, 64))
        # immediate forms (`cmp x0, #k`, `cmn w0, #k`); a 32-bit operation ignores the upper half of its operands
        immediates = (0, 1, 0xDEADBEEF_80000000, 1 << 63, (1 << 64) - 1)
        rewritten = set()
        for op in range(ARM64G_CC_OP_NUMBER):
            for cond in range(16):
                # the carry-in operand of ADC and SBC is 0 or 1; constants select the ADD/SUB-equivalent paths
                operands = [(Expr.Register(2, x1, 64), dep3) for dep3 in carries]
                operands += [(Expr.Const(2, imm, 64), carries[0]) for imm in immediates]
                for dep2, dep3 in operands:
                    cond_n_op = (cond << 4) | op
                    ccall = Expr.VEXCCallExpression(
                        0,
                        "arm64g_calculate_condition",
                        (Expr.Const(0, cond_n_op, 64), Expr.Register(1, x0, 64), dep2, dep3),
                        64,
                    )
                    result = ARM64CCallRewriter(ccall, proj, Manager()).result
                    if result is None:
                        continue
                    if isinstance(dep2, Expr.Register):
                        rewritten.add((cond, op))
                    carry = _to_claripy(dep3, deps)
                    expected = arm64g_calculate_condition(
                        None, claripy.BVV(cond_n_op, 64), deps[x0], _to_claripy(dep2, deps), carry
                    )
                    solver = claripy.Solver()
                    solver.add(claripy.Or(carry == 0, carry == 1))
                    solver.add(_to_claripy(result, deps) != expected)
                    assert not solver.satisfiable(), (cond, op, dep2, dep3, result)
        # comparisons, copied flags and tests of registers are rewritten for every condition code but VS and VC
        for op in (0, 3, 4, 9, 10):  # COPY, SUB32, SUB64, LOGIC32, LOGIC64
            assert {cond for cond, o in rewritten if o == op} >= set(range(16)) - {6, 7}, op

    def test_symbolic_cond_n_op_is_left_alone(self):
        proj = angr.Project(os.path.join(test_location, "aarch64", "test_division"), auto_load_libs=False)
        x0, x1 = proj.arch.registers["x0"][0], proj.arch.registers["x1"][0]
        ccall = Expr.VEXCCallExpression(
            0,
            "arm64g_calculate_condition",
            (Expr.Register(0, x0, 64), Expr.Register(1, x1, 64), Expr.Const(2, 0, 64), Expr.Const(3, 0, 64)),
            64,
        )
        assert ARM64CCallRewriter(ccall, proj, Manager()).result is None


class TestARM64CCallRewritingOnBinaries(unittest.TestCase):
    """Decompile real functions whose conditions libVEX leaves as arm64g_calculate_condition calls."""

    @staticmethod
    def _decompile(rel_path: str, addr: int) -> str:
        proj, cfg = load_project_with_scoped_cfg(
            os.path.join(test_location, rel_path),
            addr,
            project_kwargs={"auto_load_libs": False},
            cfg_kwargs={"normalize": True, "data_references": True},
            run_ccc=False,
        )
        dec = proj.analyses.Decompiler(proj.kb.functions[addr], cfg=cfg.model)
        assert dec.codegen is not None and dec.codegen.text is not None
        return dec.codegen.text

    def test_go_darwin_test_and_branch_in_different_blocks(self):
        # flag.(*boolValue).String: one `tst` feeds two `csel`s; once the first becomes an if, the second reads the
        # flags from another block (NE | LOGIC32)
        text = self._decompile("aarch64/go/corpus/age-v1.3.1-darwin-arm64", 0x1000CB700)
        assert "arm64g_calculate" not in text and "_ccall(" not in text, text
        assert len(re.findall(r"if \(!\(v\d+ & 1\)\)", text)) == 2, text

    def test_go_type_hash_search_with_cmn(self):
        # main.dispatch searches type hashes with `cmn`, whose conditions libVEX does not fold (HI and NE | ADD32)
        text = self._decompile("aarch64/go/go1.27.1/typeswitch", 0xA68A0)
        assert "arm64g_calculate" not in text and "_ccall(" not in text, text
        # cmn w3, w4 with w4 = 0x7527be5a, then b.hi: the hash is above -0x7527be5a, which is 2329428390
        assert re.search(r"\bv\d+ (<=|>) 2329428390\b", text) is not None, text


if __name__ == "__main__":
    unittest.main()

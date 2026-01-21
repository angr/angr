#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import unittest

import angr
from angr.ailment.expression import BinaryOp, Const, Convert, Register
from angr.analyses.decompiler.peephole_optimizations import ConcatSimplifier

from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


class TestPeepholeConcatSimplifier(unittest.TestCase):
    def setUp(self):
        self.proj = angr.load_shellcode(b"\x90", "AMD64")
        self.opt = ConcatSimplifier(self.proj, self.proj.kb)

    def test_zero_extend_concat(self):
        # 0 CONCAT a  =>  Convert(a, unsigned, 2*bits)
        low = Register(None, None, 0, 32)
        high = Const(None, None, 0, 32)
        concat = BinaryOp(None, "Concat", [high, low], False, bits=64)

        result = self.opt.optimize(concat)
        assert isinstance(result, Convert)
        assert result.from_bits == 32
        assert result.to_bits == 64
        assert result.is_signed is False
        assert result.operand is low

    def test_sign_extend_concat(self):
        # (a >> 31) CONCAT a  =>  Convert(a, signed, 64)
        low = Register(None, None, 0, 32)
        high = BinaryOp(None, "Sar", [low, Const(None, None, 31, 8)], False, bits=32)
        concat = BinaryOp(None, "Concat", [high, low], False, bits=64)

        result = self.opt.optimize(concat)
        assert isinstance(result, Convert)
        assert result.from_bits == 32
        assert result.to_bits == 64
        assert result.is_signed is True
        assert result.operand is low

    def test_high_part_extraction(self):
        # (a CONCAT b) >> 32  =>  a
        high = Register(None, None, 0, 32)
        low = Register(None, None, 8, 32)
        concat = BinaryOp(None, "Concat", [high, low], False, bits=64)
        shr = BinaryOp(None, "Shr", [concat, Const(None, None, 32, 8)], False, bits=64)

        result = self.opt.optimize(shr)
        assert result is high

    def test_low_part_extraction_and(self):
        # (a CONCAT b) & 0xFFFFFFFF  =>  b
        high = Register(None, None, 0, 32)
        low = Register(None, None, 8, 32)
        concat = BinaryOp(None, "Concat", [high, low], False, bits=64)
        and_expr = BinaryOp(None, "And", [concat, Const(None, None, 0xFFFFFFFF, 64)], False, bits=64)

        result = self.opt.optimize(and_expr)
        # Result should be low, possibly with zero-extension
        if isinstance(result, Convert):
            assert result.operand is low
            assert result.is_signed is False
        else:
            assert result is low

    def test_truncate_concat(self):
        # Convert(a CONCAT b, 64->32)  =>  b
        high = Register(None, None, 0, 32)
        low = Register(None, None, 8, 32)
        concat = BinaryOp(None, "Concat", [high, low], False, bits=64)
        conv = Convert(None, 64, 32, False, concat)

        result = self.opt.optimize(conv)
        assert result is low

    def test_no_optimization_non_matching_shift(self):
        # (a CONCAT b) >> 16  should NOT be optimized (not extracting high part exactly)
        high = Register(None, None, 0, 32)
        low = Register(None, None, 8, 32)
        concat = BinaryOp(None, "Concat", [high, low], False, bits=64)
        shr = BinaryOp(None, "Shr", [concat, Const(None, None, 16, 8)], False, bits=64)

        result = self.opt.optimize(shr)
        assert result is None

    def test_no_optimization_non_matching_mask(self):
        # (a CONCAT b) & 0xFF  should NOT be optimized (not full low part mask)
        high = Register(None, None, 0, 32)
        low = Register(None, None, 8, 32)
        concat = BinaryOp(None, "Concat", [high, low], False, bits=64)
        and_expr = BinaryOp(None, "And", [concat, Const(None, None, 0xFF, 64)], False, bits=64)

        result = self.opt.optimize(and_expr)
        assert result is None

    def test_doom_g_deathmatchspawnplayer_no_concat(self):
        bin_path = os.path.join(test_location, "x86_64", "g_game.o")
        proj = angr.Project(bin_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True)

        func = cfg.functions[0x401AB8]  # G_DeathMatchSpawnPlayer

        dec = proj.analyses.Decompiler(func, cfg=cfg)
        assert dec.codegen is not None
        assert dec.codegen.text is not None
        code = dec.codegen.text

        assert "CONCAT" not in code, f"CONCAT found in decompiled code:\n{code}"
        # P_Random() % selections
        assert "P_Random() %" in code, f"Modulo not found:\n{code}"

    def test_doom_d_net_netupdate_no_concat(self):
        bin_path = os.path.join(test_location, "x86_64", "d_net.o")
        proj = angr.Project(bin_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True)

        func = cfg.functions[0x400B0E]  # NetUpdate

        dec = proj.analyses.Decompiler(func, cfg=cfg)
        assert dec.codegen is not None
        assert dec.codegen.text is not None
        code = dec.codegen.text

        assert "CONCAT" not in code, f"CONCAT found in decompiled code:\n{code}"

        # I_GetTime()/ticdup, gametic/ticdup
        assert "/ ticdup" in code, f"'/ ticdup' not found:\n{code}"

    def test_doom_d_net_tryruntics_no_concat(self):
        bin_path = os.path.join(test_location, "x86_64", "d_net.o")
        proj = angr.Project(bin_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True)

        func = cfg.functions[0x401474]  # TryRunTics
        dec = proj.analyses.Decompiler(func, cfg=cfg)
        assert dec.codegen is not None
        assert dec.codegen.text is not None
        code = dec.codegen.text

        assert "CONCAT" not in code, f"CONCAT found in decompiled code:\n{code}"
        # gametic/ticdup division
        assert "/ ticdup" in code, f"'/ ticdup' not found:\n{code}"
        # while (lowtic < gametic/ticdup + counts))
        assert " + gametic / ticdup" in code, f"while loop not simplified:\n{code}"


if __name__ == "__main__":
    unittest.main()

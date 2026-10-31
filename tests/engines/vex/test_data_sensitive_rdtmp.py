#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.engines.vex"  # pylint:disable=redefined-builtin

import unittest

import pyvex

import angr
from angr import ailment
from angr.ailment.manager import Manager
from angr.analyses.variable_recovery.irsb_scanner import VEXIRSBScanner
from angr.analyses.vm_deobfuscation.deobf_writer import _Writer
from angr.engines.vex import VEXMixin
from angr.engines.vex.data_sensitive import DataSensitiveRdTmp


class _VEXRecorder(VEXMixin):
    def _handle_vex_expr_RdTmp(self, expr):
        return "RdTmp"

    def _handle_vex_expr_DataSensitiveRdTmp(self, expr):
        return "DataSensitiveRdTmp"


class _LightRecorder(VEXIRSBScanner):
    def _handle_expr_RdTmp(self, expr):
        return "RdTmp"

    def _handle_expr_DataSensitiveRdTmp(self, expr):
        return "DataSensitiveRdTmp"


class TestDataSensitiveRdTmp(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.proj = angr.load_shellcode(b"\x48\x89\xc3\xff\xe0", "AMD64")  # mov rbx, rax; jmp rax

    def test_own_tag(self):
        assert DataSensitiveRdTmp.tag != pyvex.expr.RdTmp.tag
        assert DataSensitiveRdTmp.tag_int not in {
            cls.tag_int
            for cls in vars(pyvex.expr).values()
            if isinstance(cls, type) and issubclass(cls, pyvex.expr.IRExpr) and cls is not DataSensitiveRdTmp
        }

    def test_vex_engine_dispatch(self):
        engine = _VEXRecorder(self.proj)
        assert engine._handle_vex_expr(pyvex.expr.RdTmp(3)) == "RdTmp"
        assert engine._handle_vex_expr(DataSensitiveRdTmp(3, None)) == "DataSensitiveRdTmp"

    def test_light_engine_dispatch(self):
        engine = _LightRecorder(self.proj)
        assert engine._expr(pyvex.expr.RdTmp(3)) == "RdTmp"
        assert engine._expr(DataSensitiveRdTmp(3, None)) == "DataSensitiveRdTmp"

    def test_ail_conversion(self):
        irsb = self.proj.factory.block(0).vex
        expected = ailment.IRSBConverter.convert(irsb, Manager()).statements[-1]
        irsb.next = DataSensitiveRdTmp(irsb.next.tmp, None)
        stmt = ailment.IRSBConverter.convert(irsb, Manager()).statements[-1]
        assert "unsupported" not in str(stmt)
        assert str(stmt) == str(expected)

    def test_dump_encoding(self):
        assert _Writer(self.proj)._expr(DataSensitiveRdTmp(3, None)) == {"e": "RdTmp", "tmp": 3, "block_id": None}


if __name__ == "__main__":
    unittest.main()

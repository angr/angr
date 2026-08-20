#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,no-member,protected-access
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import unittest

import angr
from angr.ailment import Expr, Manager, Stmt
from angr.ailment.expression import VirtualVariableCategory
from angr.analyses.decompiler import CStructuredCodeGenerator
from angr.analyses.decompiler.variable_map import VariableMap
from angr.sim_type import SimTypeChar, SimTypePointer
from angr.sim_variable import SimRegisterVariable, SimStackVariable


def _make_codegen() -> CStructuredCodeGenerator:
    proj = angr.load_shellcode(b"\x31\xc0\xc3", arch="AMD64")
    cfg = proj.analyses.CFGFast(normalize=True)
    codegen = proj.analyses.Decompiler(cfg.functions[0], cfg=cfg).codegen
    assert isinstance(codegen, CStructuredCodeGenerator)
    return codegen


class TestConvertRendering(unittest.TestCase):
    """How CStructuredCodeGenerator renders Convert expressions of assorted widths."""

    @classmethod
    def setUpClass(cls):
        # any decompilation will do; all we need is a codegen instance to render expressions with
        cls.codegen = _make_codegen()

    def _render(self, from_bits: int, to_bits: int, value: int = 0x1234) -> str:
        conv = Expr.Convert(0, from_bits, to_bits, False, Expr.Const(0, value, from_bits))
        return self.codegen._handle(conv).c_repr()

    def test_truncation_to_unrepresentable_width_is_masked(self):
        # No C type is 5, 3 or 1 bits wide. A cast would round up to the next real type and keep
        # bits the conversion discards, so these have to be spelled as a mask instead.
        assert self._render(32, 5) == "4660 & 31"
        assert self._render(32, 3) == "4660 & 7"
        assert self._render(32, 1) == "4660 & 1"

    def test_truncation_to_representable_width_is_a_cast(self):
        assert self._render(32, 8) == "(char)4660"
        assert self._render(32, 16) == "(unsigned short)4660"

    def test_widening_is_always_a_cast(self):
        # Rounding up only loses information when truncating, so widening keeps casting even to a
        # width no C type has.
        assert self._render(1, 5, value=1) == "(char)1"
        assert self._render(8, 12, value=3) == "(unsigned short)3"
        assert self._render(32, 64, value=3) == "(unsigned long long)3"


class TestStoreRendering(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.codegen = _make_codegen()

    def test_mismatched_store_cast_distinguishes_pointer_from_storage(self):
        manager = Manager(arch=self.codegen.project.arch)
        addr = Expr.VirtualVariable(
            manager.next_atom(), 1, self.codegen.project.arch.bits, VirtualVariableCategory.REGISTER
        )
        data = Expr.Const(manager.next_atom(), 0x11223344, 32)
        pointer_store = Stmt.Store(
            manager.next_atom(), addr, data, 4, self.codegen.project.arch.memory_endness, ins_addr=0x401000
        )
        direct_store = Stmt.Store(
            manager.next_atom(), addr, data, 4, self.codegen.project.arch.memory_endness, ins_addr=0x401004
        )
        addr_variable = SimRegisterVariable(0x28, self.codegen.project.arch.bytes, ident="ir_test", name="iter")
        storage_variable = SimStackVariable(-0x10, 4, ident="is_test", name="storage")
        variable_map = VariableMap()
        variable_map.set_variable(addr, addr_variable)
        variable_map.set_variable(direct_store, storage_variable)

        variable_manager = self.codegen.kb.dec_variables[self.codegen._func.addr]
        variable_manager.set_unified_variable(addr_variable, addr_variable)
        variable_manager.set_unified_variable(storage_variable, storage_variable)
        variable_manager.set_variable_type(
            addr_variable, SimTypePointer(SimTypeChar()).with_arch(self.codegen.project.arch)
        )
        variable_manager.set_variable_type(storage_variable, SimTypeChar().with_arch(self.codegen.project.arch))
        old_variable_map = self.codegen._variable_map
        self.codegen._variable_map = variable_map
        try:
            pointer_rendered = self.codegen._handle(pointer_store, is_expr=False).c_repr()
            direct_rendered = self.codegen._handle(direct_store, is_expr=False).c_repr()
        finally:
            self.codegen._variable_map = old_variable_map

        assert direct_rendered == "*((unsigned int *)&storage) = 287454020;\n"
        assert pointer_rendered == "*((unsigned int *)iter) = 287454020;\n"


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os.path
import unittest

import networkx

import angr
from angr.ailment import Block, Const
from angr.ailment.expression import BinaryOp, VirtualVariable, VirtualVariableCategory
from angr.ailment.statement import Assignment, Return
from angr.sim_variable import SimConstantVariable
from tests.common import bin_location, load_project_with_scoped_cfg, print_decompilation_result

test_location = os.path.join(bin_location, "tests")


# pylint: disable=missing-class-docstring, no-self-use
class TestConstNotPointer(unittest.TestCase):
    def test_bitwise_operands_are_not_global_addresses(self):
        # USB_OTG_EPStartXfer() ORs the DMA flags 0x10000000 and 0x20000000 into a register value. On Cortex-M those
        # are also the CCM-RAM and SRAM base addresses, so they used to print as &_sccmbss / &SRAM_BASE.
        bin_path = os.path.join(test_location, "armel", "decompiler", "cf2.elf")
        proj, cfg = load_project_with_scoped_cfg(bin_path, 0x801E6E1, window=0x200, expand_call_tree=False)

        func = cfg.functions[0x801E6E1]
        dec = proj.analyses.Decompiler(func, cfg=cfg.model, fail_fast=True)
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)

        text = dec.codegen.text
        assert "&SRAM_BASE" not in text
        assert "&_sccmbss" not in text
        assert "0x20000000" in text
        assert "0x10000000" in text

    def test_variable_recovery_does_not_load_a_global_for_a_mask(self):
        def v(i: int) -> VirtualVariable:
            return VirtualVariable(i, i, 64, VirtualVariableCategory.REGISTER, oident=16)

        # 0x400008 is mapped: as an Or operand it is a mask, as an Add operand it may be a pointer
        proj = angr.load_shellcode(b"\x90" * 16, arch="AMD64", load_address=0x400000)
        mask = Const(10, 0x400008, 64)
        ptr = Const(11, 0x400008, 64)
        block = Block(
            0x400000,
            3,
            statements=[
                Assignment(0, v(1), BinaryOp(0, "Or", [v(0), mask], bits=64), ins_addr=0x400000),
                Assignment(1, v(2), BinaryOp(1, "Add", [v(0), ptr], bits=64), ins_addr=0x400001),
                Return(2, [v(1), v(2)], ins_addr=0x400002),
            ],
        )
        graph = networkx.DiGraph()
        graph.add_node(block)
        func = proj.kb.functions.function(addr=0x400000, name="dummy", create=True)
        vr = proj.analyses.VariableRecoveryFast(func, func_graph=graph, entry_node_addr=0x400000)

        global_manager = vr.variable_manager.global_manager
        assert global_manager.find_variables_by_atom(0x400000, 0, mask, block_idx=block.idx) == set()
        assert global_manager.find_variables_by_atom(0x400000, 1, ptr, block_idx=block.idx)
        mask_vars = vr.variable_manager[0x400000].find_variables_by_atom(0x400000, 0, mask, block_idx=block.idx)
        assert len(mask_vars) == 1
        assert isinstance(next(iter(mask_vars))[0], SimConstantVariable)


if __name__ == "__main__":
    unittest.main()

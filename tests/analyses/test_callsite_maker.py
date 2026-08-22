#!/usr/bin/env python3
from __future__ import annotations

__package__ = __package__ or "tests.analyses"  # pylint:disable=redefined-builtin

import os
import unittest

import angr
from angr import ailment
from angr.analyses.decompiler.block_simplifier import BlockSimplifier
from angr.calling_conventions import SimCCCdecl
from angr.knowledge_plugins.functions.function import PrototypeSource
from angr.sim_type import SimTypeBottom, SimTypeFunction
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


# pylint: disable=missing-class-docstring
# pylint: disable=no-self-use
class TestCallsiteMaker(unittest.TestCase):
    def test_proven_unused_inferred_void_call_drops_synthetic_return(self):
        project = angr.load_shellcode(b"\xc3", arch="x86", load_address=0x100)
        manager = ailment.Manager(arch=project.arch)
        cc = SimCCCdecl(project.arch)
        void_prototype = SimTypeFunction([], SimTypeBottom(label="void")).with_arch(project.arch)
        callee = project.kb.functions.function(addr=0x100, create=True)
        callee.calling_convention = cc
        callee.prototype = void_prototype
        callee.prototype_source = PrototypeSource.CCA_LOW

        call = ailment.Expr.Call(
            manager.next_atom(),
            ailment.Expr.Const(manager.next_atom(), 0x100, project.arch.bits),
            args=[],
            bits=project.arch.bits,
            ins_addr=0x200,
        )
        block = ailment.Block(
            0x200,
            5,
            statements=[
                ailment.Stmt.SideEffectStatement(
                    manager.next_atom(),
                    call,
                    ret_expr=ailment.Expr.Register(
                        manager.next_atom(),
                        project.arch.get_register_offset("eax"),
                        project.arch.bits,
                        reg_name="eax",
                        ins_addr=0x200,
                    ),
                    ins_addr=0x200,
                )
            ],
        )
        project.kb.callsite_prototypes.set_prototype(block.addr, cc, void_prototype)

        result = project.analyses.AILCallSiteMaker(block, ail_manager=manager).result_block

        self.assertIsNotNone(result)
        self.assertIsInstance(result.statements[-1], ailment.Stmt.SideEffectStatement)
        self.assertIsNone(result.statements[-1].ret_expr)

    def test_proven_unused_custom_intrinsic_preserves_metadata_arguments(self):
        project = angr.load_shellcode(b"\xc3", arch="x86", load_address=0x100)
        manager = ailment.Manager(arch=project.arch)
        cc = SimCCCdecl(project.arch)
        void_prototype = SimTypeFunction([], SimTypeBottom(label="void")).with_arch(project.arch)
        vector = ailment.Expr.Const(manager.next_atom(), 0x21, 8, ins_addr=0x200)
        call = ailment.Expr.Call(
            manager.next_atom(),
            "__pcode_swi",
            args=[vector],
            bits=project.arch.bits,
            ins_addr=0x200,
        )
        block = ailment.Block(
            0x200,
            2,
            statements=[
                ailment.Stmt.SideEffectStatement(
                    manager.next_atom(),
                    call,
                    ret_expr=ailment.Expr.Register(
                        manager.next_atom(),
                        project.arch.get_register_offset("eax"),
                        project.arch.bits,
                        reg_name="eax",
                        ins_addr=0x200,
                    ),
                    ins_addr=0x200,
                )
            ],
        )
        project.kb.callsite_prototypes.set_prototype(block.addr, cc, void_prototype)

        result = project.analyses.AILCallSiteMaker(block, ail_manager=manager).result_block

        self.assertIsNotNone(result)
        statement = result.statements[-1]
        self.assertIsInstance(statement, ailment.Stmt.SideEffectStatement)
        self.assertIsNone(statement.ret_expr)
        self.assertEqual(statement.expr.target, "__pcode_swi")
        self.assertEqual(statement.expr.args, (vector,))

    def test_untyped_custom_intrinsic_is_left_unchanged(self):
        project = angr.load_shellcode(b"\xc3", arch="x86", load_address=0x100)
        manager = ailment.Manager(arch=project.arch)
        call = ailment.Expr.Call(
            manager.next_atom(),
            "opaque_intrinsic",
            args=[ailment.Expr.Const(manager.next_atom(), 1, 8)],
            bits=project.arch.bits,
            ins_addr=0x200,
        )
        block = ailment.Block(
            0x200,
            2,
            statements=[
                ailment.Stmt.SideEffectStatement(
                    manager.next_atom(),
                    call,
                    ret_expr=ailment.Expr.Register(
                        manager.next_atom(),
                        project.arch.get_register_offset("eax"),
                        project.arch.bits,
                        reg_name="eax",
                        ins_addr=0x200,
                    ),
                    ins_addr=0x200,
                )
            ],
        )

        result = project.analyses.AILCallSiteMaker(block, ail_manager=manager).result_block

        self.assertIs(result, block)

    def test_callsite_maker(self):
        project = angr.Project(
            os.path.join(test_location, "x86_64", "all"),
            auto_load_libs=False,
        )

        manager = ailment.Manager(arch=project.arch)

        # Generate a CFG
        cfg = project.analyses.CFG()

        new_cc_found = True
        while new_cc_found:
            new_cc_found = False
            for func in cfg.kb.functions.values():
                if func.calling_convention is None:
                    # determine the calling convention of each function
                    project.analyses.VariableRecoveryFast(func)
                    cc_analysis = project.analyses.CallingConvention(func)
                    if cc_analysis.cc is not None:
                        func.calling_convention = cc_analysis.cc
                        func.prototype = cc_analysis.prototype
                        new_cc_found = True

        main_func = cfg.kb.functions["main"]

        for block in sorted(main_func.blocks, key=lambda x: x.addr):
            print(block.vex.pp())
            ail_block = ailment.IRSBConverter.convert(block.vex, manager)
            simp = BlockSimplifier(project, ail_block, manager, main_func.addr)

            csm = project.analyses.AILCallSiteMaker(simp.result_block, ail_manager=manager)
            if csm.result_block:
                ail_block = csm.result_block
                simp = BlockSimplifier(project, ail_block, manager, main_func.addr)

            print(simp.result_block)


if __name__ == "__main__":
    unittest.main()

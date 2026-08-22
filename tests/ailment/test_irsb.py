# pylint:disable=broad-exception-caught,missing-class-docstring,no-self-use,protected-access
from __future__ import annotations

import os
import pickle
import unittest

import archinfo
import pypcode
import pyvex
from pyvex.enums import irop_enums_to_ints

import angr
from angr import ailment
from angr.engines.pcode.cc import SimCCPCodeX86Win16NearCdecl
from angr.engines.vex.claripy import irop
from angr.knowledge_plugins.functions.function import PrototypeSource
from angr.rustylib.ailment import RoundingMode, VEXIRSBConverter, _vexop_debug
from angr.sim_type import SimTypeFunction, SimTypeShort

# pylint: disable=missing-class-docstring
# pylint: disable=line-too-long


class TestIrsb(unittest.TestCase):
    block_bytes = bytes.fromhex(
        "554889E54883EC40897DCC488975C048C745F89508400048C745F0B6064000488B45C04883C008488B00BEA70840004889C7E883FEFFFF"
    )
    block_addr = 0x4006C6

    def test_convert_from_vex_irsb(self):
        arch = archinfo.arch_from_id("AMD64")
        manager = ailment.Manager(arch=arch)
        irsb = pyvex.IRSB(self.block_bytes, self.block_addr, arch, opt_level=0)
        ablock = ailment.IRSBConverter.convert(irsb, manager)
        assert ablock  # TODO: test if this conversion is valid

    def test_convert_from_pcode_irsb(self):
        arch = archinfo.arch_from_id("AMD64")
        manager = ailment.Manager(arch=arch)
        p = angr.load_shellcode(
            self.block_bytes, arch, self.block_addr, self.block_addr, engine=angr.engines.UberEnginePcode
        )
        irsb = p.factory.block(self.block_addr).vex
        ablock = ailment.IRSBConverter.convert(irsb, manager)
        assert ablock  # TODO: test if this conversion is valid

    @staticmethod
    def _convert_x86_16_control_transfer(code: bytes):
        arch = archinfo.ArchPcode("x86:LE:16:Protected Mode")
        project = angr.load_shellcode(
            code,
            arch,
            0,
            0,
            engine=angr.engines.UberEnginePcode,
            rebase_granularity=0x10,
        )
        irsb = project.factory.block(0, size=len(code)).vex
        return ailment.IRSBConverter.convert(irsb, ailment.Manager(arch=arch))

    def test_convert_pcode_x86_16_preserves_near_and_far_transfer_kinds(self):
        cases = (
            (bytes.fromhex("e80200"), ailment.Stmt.SideEffectStatement, "near"),  # call +2
            (bytes.fromhex("9a78563412"), ailment.Stmt.SideEffectStatement, "far"),  # callf 1234:5678
            (bytes.fromhex("ffd0"), ailment.Stmt.SideEffectStatement, "near"),  # call ax
            (bytes.fromhex("ff1f"), ailment.Stmt.SideEffectStatement, "far"),  # callf [bx]
            (bytes.fromhex("e90200"), ailment.Stmt.Jump, "near"),  # jmp +2
            (bytes.fromhex("ea78563412"), ailment.Stmt.Jump, "far"),  # jmpf 1234:5678
            (bytes.fromhex("ffe0"), ailment.Stmt.Jump, "near"),  # jmp ax
            (bytes.fromhex("ff2f"), ailment.Stmt.Jump, "far"),  # jmpf [bx]
        )
        for code, statement_type, expected_kind in cases:
            with self.subTest(code=code.hex()):
                block = self._convert_x86_16_control_transfer(code)
                statement = next(item for item in block.statements if isinstance(item, statement_type))
                transfer = statement.expr if isinstance(statement, ailment.Stmt.SideEffectStatement) else statement

                assert transfer.transfer_kind == expected_kind
                restored = pickle.loads(pickle.dumps(statement))
                restored_transfer = (
                    restored.expr if isinstance(restored, ailment.Stmt.SideEffectStatement) else restored
                )
                assert restored_transfer.transfer_kind == expected_kind

    def test_convert_pcode_x86_16_direct_far_target_preserves_selector_and_offset(self):
        for code in (bytes.fromhex("9a78563412"), bytes.fromhex("ea78563412")):
            with self.subTest(code=code.hex()):
                block = self._convert_x86_16_control_transfer(code)
                statement = next(
                    item
                    for item in block.statements
                    if isinstance(item, (ailment.Stmt.SideEffectStatement, ailment.Stmt.Jump))
                )
                transfer = statement.expr if isinstance(statement, ailment.Stmt.SideEffectStatement) else statement

                assert isinstance(transfer.target, ailment.Expr.SegmentedAddress)
                assert transfer.target.address_kind == "x86-protected-16:16"
                assert transfer.target.selector.value == 0x1234
                assert transfer.target.offset.value == 0x5678

    def test_convert_pcode_x86_16_far_call_consumes_inline_frame_setup(self):
        for code in (bytes.fromhex("9a78563412"), bytes.fromhex("ff1f")):
            with self.subTest(code=code.hex()):
                block = self._convert_x86_16_control_transfer(code)

                assert not any(isinstance(statement, ailment.Stmt.Store) for statement in block.statements)
                assert not any(
                    isinstance(statement, ailment.Stmt.Assignment)
                    and isinstance(statement.dst, ailment.Expr.Register)
                    and statement.dst.tags.get("reg_name", "").lower() in {"cs", "sp", "esp", "rsp"}
                    for statement in block.statements
                )
                call = next(
                    statement.expr
                    for statement in block.statements
                    if isinstance(statement, ailment.Stmt.SideEffectStatement)
                )
                assert call.transfer_kind == "far"

    def test_convert_pcode_x86_16_return_consumes_inline_frame_setup(self):
        for return_instruction in (
            bytes.fromhex("c3"),  # ret
            bytes.fromhex("c20a00"),  # ret 10
            bytes.fromhex("cb"),  # retf
            bytes.fromhex("ca0a00"),  # retf 10
        ):
            code = b"\x43" + return_instruction  # inc bx; return
            with self.subTest(code=code.hex()):
                block = self._convert_x86_16_control_transfer(code)
                return_statement = block.statements[-1]

                assert isinstance(return_statement, ailment.Stmt.Return)
                assert return_statement.tags["ins_addr"] == 1
                assert any(statement.tags.get("ins_addr") == 0 for statement in block.statements[:-1])
                assert all(statement.tags.get("ins_addr") != 1 for statement in block.statements[:-1])

    def test_convert_pcode_x86_16_operand_override_preserves_16_32_transfers(self):
        cases = (
            (bytes.fromhex("669a785634129abc"), ailment.Stmt.SideEffectStatement, "far"),
            (bytes.fromhex("66ffd0"), ailment.Stmt.SideEffectStatement, "near"),
            (bytes.fromhex("66ff1f"), ailment.Stmt.SideEffectStatement, "far"),
            (bytes.fromhex("66ea785634129abc"), ailment.Stmt.Jump, "far"),
            (bytes.fromhex("66ffe0"), ailment.Stmt.Jump, "near"),
            (bytes.fromhex("66ff2f"), ailment.Stmt.Jump, "far"),
        )
        for code, statement_type, expected_kind in cases:
            with self.subTest(code=code.hex()):
                block = self._convert_x86_16_control_transfer(code)
                statement = next(item for item in block.statements if isinstance(item, statement_type))
                transfer = statement.expr if isinstance(statement, ailment.Stmt.SideEffectStatement) else statement

                assert transfer.transfer_kind == expected_kind
                assert isinstance(transfer.target, ailment.Expr.SegmentedAddress)
                assert transfer.target.address_kind == "x86-protected-16:32"
                assert transfer.target.selector.bits == 16
                assert transfer.target.offset.bits == 32
                assert not any(isinstance(item, ailment.Stmt.Store) for item in block.statements)
                assert not any(
                    isinstance(item, ailment.Stmt.Assignment)
                    and isinstance(item.dst, ailment.Expr.Register)
                    and item.dst.tags.get("reg_name", "").lower() in {"cs", "sp", "esp", "rsp"}
                    for item in block.statements
                )

        direct_far = self._convert_x86_16_control_transfer(bytes.fromhex("669a785634129abc"))
        call = next(
            statement.expr
            for statement in direct_far.statements
            if isinstance(statement, ailment.Stmt.SideEffectStatement)
        )
        assert call.target.selector.value == 0xBC9A
        assert call.target.offset.value == 0x12345678

    def test_convert_pcode_real_mode_segment_userop(self):
        arch = archinfo.ArchPcode("x86:LE:16:Real Mode")
        manager = ailment.Manager(arch=arch)  # pyright: ignore[reportArgumentType]
        project = angr.load_shellcode(
            bytes.fromhex("a10010"),
            arch,
            0,
            0,
            engine=angr.engines.UberEnginePcode,
            rebase_granularity=0x10,
        )

        irsb = project.factory.block(0, size=3).vex
        block = ailment.IRSBConverter.convert(irsb, manager)

        segment = next(
            statement.src
            for statement in block.statements
            if isinstance(statement, ailment.Stmt.Assignment)
            and isinstance(statement.src, ailment.Expr.BinaryOp)
            and statement.src.op == "And"
        )
        linear_address, address_mask = segment.operands
        assert segment.bits == 32
        assert isinstance(address_mask, ailment.Expr.Const)
        assert address_mask.value == 0xFFFFF
        assert isinstance(linear_address, ailment.Expr.BinaryOp)
        assert linear_address.op == "Add"

        shifted_segment, offset = linear_address.operands
        assert isinstance(shifted_segment, ailment.Expr.BinaryOp)
        assert shifted_segment.op == "Shl"
        segment_value, shift = shifted_segment.operands
        assert isinstance(segment_value, ailment.Expr.Convert)
        assert (segment_value.from_bits, segment_value.to_bits, segment_value.is_signed) == (16, 32, False)
        assert isinstance(segment_value.operand, ailment.Expr.Register)
        assert segment_value.operand.reg_offset == arch.get_register_offset("ds")
        assert segment_value.operand.bits == 16
        assert isinstance(shift, ailment.Expr.Const)
        assert shift.value == 4
        assert isinstance(offset, ailment.Expr.Convert)
        assert (offset.from_bits, offset.to_bits, offset.is_signed) == (16, 32, False)

        assert not any(
            isinstance(statement, ailment.Stmt.Assignment)
            and isinstance(statement.src, ailment.Expr.DirtyExpression)
            and statement.src.callee == "CALLOTHER"
            for statement in block.statements
        )

    def test_convert_pcode_protected_mode_segment_userop(self):
        arch = archinfo.ArchPcode("x86:LE:16:Protected Mode")
        manager = ailment.Manager(arch=arch)  # pyright: ignore[reportArgumentType]
        project = angr.load_shellcode(
            bytes.fromhex("a10010"),
            arch,
            0,
            0,
            engine=angr.engines.UberEnginePcode,
            rebase_granularity=0x10,
        )

        irsb = project.factory.block(0, size=3).vex
        block = ailment.IRSBConverter.convert(irsb, manager)

        load = next(
            statement.src
            for statement in block.statements
            if isinstance(statement, ailment.Stmt.Assignment)
            and isinstance(statement.src, ailment.Expr.Load)
            and isinstance(statement.src.addr, ailment.Expr.SegmentedAddress)
        )
        segment = load.addr
        assert segment.bits == 32
        assert segment.address_kind == "x86-protected-16:16"
        assert isinstance(segment.selector, ailment.Expr.Register)
        assert segment.selector.reg_offset == arch.get_register_offset("ds")
        assert segment.selector.bits == 16
        assert isinstance(segment.offset, ailment.Expr.Const)
        assert segment.offset.value == 0x1000
        assert segment.offset.bits == 16
        assert pickle.loads(pickle.dumps(segment)) == segment
        assert not any(
            isinstance(statement, ailment.Stmt.Assignment)
            and isinstance(statement.src, ailment.Expr.DirtyExpression)
            and statement.src.callee == "CALLOTHER"
            for statement in block.statements
        )

    def test_convert_pcode_protected_mode_stack_segment_preserves_selector(self):
        arch = archinfo.ArchPcode("x86:LE:16:Protected Mode")
        manager = ailment.Manager(arch=arch)  # pyright: ignore[reportArgumentType]
        project = angr.load_shellcode(
            bytes.fromhex("368b4604"),  # mov ax, word ptr ss:[bp+4]
            arch,
            0,
            0,
            engine=angr.engines.UberEnginePcode,
            rebase_granularity=0x10,
        )

        irsb = project.factory.block(0, size=4).vex
        block = ailment.IRSBConverter.convert(irsb, manager)
        ss_offset = arch.get_register_offset("ss")

        segment = next(
            statement.src.addr
            for statement in block.statements
            if isinstance(statement, ailment.Stmt.Assignment)
            and isinstance(statement.src, ailment.Expr.Load)
            and isinstance(statement.src.addr, ailment.Expr.SegmentedAddress)
        )
        assert isinstance(segment.selector, ailment.Expr.Register)
        assert segment.selector.reg_offset == ss_offset
        assert segment.tags["segment_register"] == "ss"

    def test_convert_pcode_protected_segment_constant_offsets_preserve_selector_and_copy_origin(self):
        arch = archinfo.ArchPcode("x86:LE:16:Protected Mode")
        manager = ailment.Manager(arch=arch)  # pyright: ignore[reportArgumentType]
        # mov ax,ss; mov es,ax; fstenv es:[bp-0x1a]. FSTENV expands to seven p-code stores whose addresses are one
        # SEGMENTOP result plus constant displacements.
        code = bytes.fromhex("8cd08ec026d976e6")
        project = angr.load_shellcode(
            code,
            arch,
            0,
            0,
            engine=angr.engines.UberEnginePcode,
            rebase_granularity=0x10,
        )

        irsb = project.factory.block(0, size=len(code)).vex
        block = ailment.IRSBConverter.convert(irsb, manager)
        stores = [statement for statement in block.statements if isinstance(statement, ailment.Stmt.Store)]

        assert len(stores) == 7
        assert all(isinstance(store.addr, ailment.Expr.SegmentedAddress) for store in stores)
        assert all(store.addr.address_kind == "x86-protected-16:16" for store in stores)
        assert all(store.addr.tags.get("segment_register") == "es" for store in stores)
        assert all(store.addr.tags.get("segment_register_origin") == "ss" for store in stores)
        assert all(store.addr.offset.bits == 16 for store in stores)
        assert not any(
            isinstance(statement, ailment.Stmt.Assignment) and isinstance(statement.src, ailment.Expr.SegmentedAddress)
            for statement in block.statements
        )

        # An intervening write invalidates the exact copy fact; ES must not retain stale SS provenance.
        invalidated_code = bytes.fromhex("8cd0408ec026d976e6")  # mov ax,ss; inc ax; mov es,ax; fstenv es:[bp-0x1a]
        invalidated_project = angr.load_shellcode(
            invalidated_code,
            arch,
            0,
            0,
            engine=angr.engines.UberEnginePcode,
            rebase_granularity=0x10,
        )
        invalidated = ailment.IRSBConverter.convert(
            invalidated_project.factory.block(0, size=len(invalidated_code)).vex,
            ailment.Manager(arch=arch),  # pyright: ignore[reportArgumentType]
        )
        invalidated_stores = [
            statement for statement in invalidated.statements if isinstance(statement, ailment.Stmt.Store)
        ]
        assert len(invalidated_stores) == 7
        assert all(store.addr.tags.get("segment_register_origin") != "ss" for store in invalidated_stores)

    def test_convert_pcode_lock_markers_preserves_sequential_memory_update(self):
        arch = archinfo.ArchPcode("x86:LE:16:Protected Mode")
        manager = ailment.Manager(arch=arch)  # pyright: ignore[reportArgumentType]
        project = angr.load_shellcode(
            bytes.fromhex("f0ff07"),  # lock inc word ptr [bx]
            arch,
            0,
            0,
            engine=angr.engines.UberEnginePcode,
            rebase_granularity=0x10,
        )

        irsb = project.factory.block(0, size=3).vex
        marker_names = [
            op.inputs[0].getUserDefinedOpName() for op in irsb._ops if op.opcode == pypcode.OpCode.CALLOTHER
        ]
        assert marker_names == ["LOCK", "segment", "UNLOCK"]

        block = ailment.IRSBConverter.convert(irsb, manager)
        assert any(isinstance(statement, ailment.Stmt.Store) for statement in block.statements)
        assert not any(
            isinstance(statement, ailment.Stmt.Assignment) and isinstance(statement.src, ailment.Expr.DirtyExpression)
            for statement in block.statements
        )

    def test_convert_pcode_integer_operations_used_by_x86_16(self):
        arch = archinfo.ArchPcode("x86:LE:16:Protected Mode")
        manager = ailment.Manager(arch=arch)  # pyright: ignore[reportArgumentType]
        code = bytes.fromhex(
            "f7d0"  # not ax
            "f7d8"  # neg ax
            "f7ef"  # imul di
            "f7f9"  # idiv cx
            "01d8"  # add ax, bx
            "29d8"  # sub ax, bx
        )
        project = angr.load_shellcode(
            code,
            arch,
            0,
            0,
            engine=angr.engines.UberEnginePcode,
            rebase_granularity=0x10,
        )

        irsb = project.factory.block(0, size=len(code)).vex
        block = ailment.IRSBConverter.convert(irsb, manager)
        sources = [statement.src for statement in block.statements if isinstance(statement, ailment.Stmt.Assignment)]

        assert any(isinstance(expr, ailment.Expr.UnaryOp) and expr.op == "BitwiseNeg" for expr in sources)
        assert any(isinstance(expr, ailment.Expr.UnaryOp) and expr.op == "Neg" for expr in sources)
        assert any(isinstance(expr, ailment.Expr.Extract) for expr in sources)
        assert any(
            isinstance(expr, ailment.Expr.Convert) and (expr.from_bits, expr.to_bits, expr.is_signed) == (16, 32, True)
            for expr in sources
        )
        assert any(isinstance(expr, ailment.Expr.BinaryOp) and expr.op == "Div" and expr.signed for expr in sources)
        assert any(isinstance(expr, ailment.Expr.BinaryOp) and expr.op == "Mod" and expr.signed for expr in sources)

        # All operations exercised by this regression lower to ordinary AIL.
        dirty_callees = {expr.callee for expr in sources if isinstance(expr, ailment.Expr.DirtyExpression)}
        assert dirty_callees == set()
        assert any(isinstance(expr, ailment.Expr.UnaryOp) and expr.op == "PopCount" for expr in sources)
        rendered = "\n".join(repr(statement) for statement in block.statements)
        for operation in ("INT_2COMP", "SUBPIECE", "INT_SDIV", "INT_SREM", "Carry", "SCarry", "SBorrow"):
            assert operation not in rendered

    def test_convert_pcode_software_interrupt_to_explicit_call(self):
        for language_id in ("x86:LE:16:Protected Mode", "x86:LE:16:Real Mode"):
            with self.subTest(language_id=language_id):
                arch = archinfo.ArchPcode(language_id)
                manager = ailment.Manager(arch=arch)  # pyright: ignore[reportArgumentType]
                project = angr.load_shellcode(
                    bytes.fromhex("cd21"),
                    arch,
                    0,
                    0,
                    engine=angr.engines.UberEnginePcode,
                    rebase_granularity=0x10,
                )

                irsb = project.factory.block(0, size=2).vex
                block = ailment.IRSBConverter.convert(irsb, manager)

                call_statement = next(
                    statement
                    for statement in block.statements
                    if isinstance(statement, ailment.Stmt.SideEffectStatement)
                )
                assert isinstance(call_statement.expr, ailment.Expr.Call)
                assert call_statement.expr.target == "__pcode_swi"
                assert len(call_statement.expr.args) == 16
                vector, *registers = call_statement.expr.args
                assert isinstance(vector, ailment.Expr.Const)
                assert vector.value == 0x21
                assert vector.bits == 8
                assert all(isinstance(register, ailment.Expr.Register) for register in registers)
                assert [register.tags["reg_name"] for register in registers] == [
                    "ax",
                    "bx",
                    "cx",
                    "dx",
                    "si",
                    "di",
                    "ds",
                    "es",
                    "cf",
                    "pf",
                    "af",
                    "zf",
                    "sf",
                    "of",
                    "df",
                ]
                assert [register.reg_offset for register in registers] == [
                    arch.get_register_offset(name)
                    for name in (
                        "ax",
                        "bx",
                        "cx",
                        "dx",
                        "si",
                        "di",
                        "ds",
                        "es",
                        "cf",
                        "pf",
                        "af",
                        "zf",
                        "sf",
                        "of",
                        "df",
                    )
                ]
                assert [register.bits for register in registers] == [16] * 8 + [8] * 7
                assert isinstance(call_statement.ret_expr, ailment.Expr.Register)
                assert call_statement.ret_expr.reg_offset == arch.get_register_offset("ax")
                assert call_statement.ret_expr.bits == 16
                assert not any(
                    isinstance(statement, ailment.Stmt.Assignment)
                    and isinstance(statement.src, ailment.Expr.DirtyExpression)
                    for statement in block.statements
                )

    def test_decompile_pcode_software_interrupt_preserves_live_register_arguments(self):
        # Generate signed overflow, use SAHF to set CF/PF/AF/ZF/SF, then establish DS, ES, and every general-purpose
        # register immediately before INT 21h. AX is deliberately updated through AH after a full-width write: the
        # untouched AL byte must remain live across the partial-register definition. This source-free fixture proves
        # SSA and code generation retain the exact values consumed by the runtime boundary.
        code = bytes.fromhex(
            "b8ff7f 050100 b4d5 9e b81111 8ed8 b82222 8ec0 b83412 b42a bb7856 b9bc9a baf0de be5713 bf6824 fd cd21 c3"
        )
        expected_call_prefix = "__pcode_swi(33, 10804, 22136, 39612, 57072, 4951, 9320, 0x1111, 0x2222, 1, 1, 1, 1, 1, "

        for language_id in ("x86:LE:16:Protected Mode", "x86:LE:16:Real Mode"):
            with self.subTest(language_id=language_id):
                arch = archinfo.ArchPcode(language_id)
                project = angr.load_shellcode(
                    code,
                    arch,
                    0,
                    0,
                    engine=angr.engines.UberEnginePcode,
                    rebase_granularity=0x10,
                )
                project.simos.name = "Win16"
                cfg = project.analyses.CFGFast(
                    function_starts=[0],
                    regions=[(0, len(code))],
                    start_at_entry=False,
                    force_complete_scan=False,
                    force_smart_scan=False,
                    normalize=True,
                    resolve_indirect_jumps=False,
                )
                function = cfg.functions[0]
                function.calling_convention = SimCCPCodeX86Win16NearCdecl(arch)
                function.prototype = SimTypeFunction([], SimTypeShort(signed=False)).with_arch(arch)
                function.prototype_source = PrototypeSource.SIGNATURES

                decompilation = project.analyses.Decompiler(
                    function,
                    cfg=cfg.model,
                    fail_fast=False,
                    use_cache=False,
                    update_cache=False,
                )

                assert not decompilation.errors
                assert decompilation.codegen is not None
                assert expected_call_prefix in decompilation.codegen.text
                assert ", 1)" in decompilation.codegen.text  # DF is the final canonical input.
                assert decompilation.codegen.text.count("__pcode_swi(") == 1

    def test_convert_pcode_unknown_userop_preserves_dataflow(self):
        arch = archinfo.ArchPcode("x86:LE:16:Real Mode")
        manager = ailment.Manager(arch=arch)  # pyright: ignore[reportArgumentType]
        project = angr.load_shellcode(b"\xec", arch, 0, 0, engine=angr.engines.UberEnginePcode, rebase_granularity=0x10)

        irsb = project.factory.block(0, size=1).vex
        block = ailment.IRSBConverter.convert(irsb, manager)

        unsupported = next(
            statement
            for statement in block.statements
            if isinstance(statement, ailment.Stmt.Assignment)
            and isinstance(statement.src, ailment.Expr.DirtyExpression)
        )
        assert getattr(unsupported.src, "callee", None) == "CALLOTHER"
        assert unsupported.src.bits == 8
        assert len(getattr(unsupported.src, "operands", ())) == 2
        assert isinstance(unsupported.dst, ailment.Expr.Register)
        assert unsupported.dst.reg_offset == arch.get_register_offset("al")
        assert unsupported.dst.bits == 8

        reaching_definitions = project.analyses.ReachingDefinitions(subject=block)
        assert block in reaching_definitions.visited_blocks

    def test_convert_pcode_unsupported_unary_preserves_operand_and_location(self):
        arch = archinfo.ArchPcode("x86:LE:32:default")
        manager = ailment.Manager(arch=arch)  # pyright: ignore[reportArgumentType]
        project = angr.load_shellcode(
            bytes.fromhex("f30fbdc1"),
            arch,
            0x100,
            0x100,
            engine=angr.engines.UberEnginePcode,
            rebase_granularity=0x10,
        )

        block = ailment.IRSBConverter.convert(project.factory.block(0x100, size=4).vex, manager)
        unsupported = next(
            statement.src
            for statement in block.statements
            if isinstance(statement, ailment.Stmt.Assignment)
            and isinstance(statement.src, ailment.Expr.DirtyExpression)
            and statement.src.callee == "LZCOUNT"
        )

        assert len(unsupported.operands) == 1
        assert isinstance(unsupported.operands[0], ailment.Expr.Register)
        assert unsupported.tags["ins_addr"] == 0x100
        assert unsupported.tags["vex_block_addr"] == 0x100
        assert type(unsupported.tags["vex_stmt_idx"]) is int

    def test_convert_pcode_float_add_preserves_semantics_and_location(self):
        arch = archinfo.ArchPcode("x86:LE:32:default")
        manager = ailment.Manager(arch=arch)  # pyright: ignore[reportArgumentType]
        project = angr.load_shellcode(
            bytes.fromhex("d8c1"),
            arch,
            0x200,
            0x200,
            engine=angr.engines.UberEnginePcode,
            rebase_granularity=0x10,
        )

        block = ailment.IRSBConverter.convert(project.factory.block(0x200, size=2).vex, manager)
        assignment = next(
            statement
            for statement in block.statements
            if isinstance(statement, ailment.Stmt.Assignment)
            and isinstance(statement.dst, ailment.Expr.Register)
            and statement.dst.tags.get("reg_name") == "ST0"
        )
        assert isinstance(assignment.src, ailment.Expr.Reinterpret)
        assert assignment.src.from_type == "F"
        assert assignment.src.to_type == "I"
        operation = assignment.src.operand
        assert isinstance(operation, ailment.Expr.BinaryOp)
        assert operation.op == "Add"
        assert operation.bits == 80
        assert operation.floating_point
        assert len(operation.operands) == 2
        assert all(isinstance(operand, ailment.Expr.Reinterpret) for operand in operation.operands)
        assert all(operand.from_type == "I" and operand.to_type == "F" for operand in operation.operands)
        assert operation.tags["ins_addr"] == 0x200
        assert assignment.src.tags["vex_block_addr"] == 0x200
        assert type(assignment.src.tags["vex_stmt_idx"]) is int
        assert not any(
            statement.src
            for statement in block.statements
            if isinstance(statement, ailment.Stmt.Assignment)
            and isinstance(statement.src, ailment.Expr.DirtyExpression)
            and statement.src.callee == "FLOAT_ADD"
        )

    def test_decompile_pcode_x87_add_preserves_extended_precision(self):
        # fld qword ptr [0x20]; fadd qword ptr [0x28]; fstp qword ptr [0x30]; ret
        # This is a raw-byte regression fixture, not compiled from source. The
        # addition happens in x87 extended precision and is rounded to double
        # only by the final store.
        code = bytes.fromhex("dd062000 dc062800 dd1e3000 c3")
        arch = archinfo.ArchPcode("x86:LE:16:Real Mode")
        project = angr.load_shellcode(
            code,
            arch,
            0,
            0,
            engine=angr.engines.UberEnginePcode,
            rebase_granularity=0x10,
        )
        cfg = project.analyses.CFGFast(
            function_starts=[0],
            regions=[(0, len(code))],
            force_complete_scan=False,
            force_smart_scan=False,
            normalize=True,
            resolve_indirect_jumps=False,
        )

        decompilation = project.analyses.Decompiler(
            cfg.kb.functions[0],
            cfg=cfg.model,
            fail_fast=False,
            use_cache=False,
            update_cache=False,
        )

        assert not decompilation.errors
        assert decompilation.codegen is not None
        text = decompilation.codegen.text
        assert text is not None
        assert "pbr_f64_to_bits((double)((long double)" in text
        assert text.count("(long double)pbr_f64_from_bits") == 2
        assert "(long long)" not in text

    def test_decompile_pcode_x87_reused_register_has_exact_carrier_type(self):
        # fld qword ptr [0x20]; fst qword ptr [0x30]; fstp qword ptr [0x38]; ret
        # Keeping ST0 live across two uses prevents expression folding and
        # exercises declaration typing for its raw 80-bit carrier.
        code = bytes.fromhex("dd062000 dd163000 dd1e3800 c3")
        arch = archinfo.ArchPcode("x86:LE:16:Real Mode")
        project = angr.load_shellcode(
            code,
            arch,
            0,
            0,
            engine=angr.engines.UberEnginePcode,
            rebase_granularity=0x10,
        )
        cfg = project.analyses.CFGFast(
            function_starts=[0],
            regions=[(0, len(code))],
            force_complete_scan=False,
            force_smart_scan=False,
            normalize=True,
            resolve_indirect_jumps=False,
        )

        decompilation = project.analyses.Decompiler(
            cfg.kb.functions[0],
            cfg=cfg.model,
            fail_fast=False,
            use_cache=False,
            update_cache=False,
        )

        assert not decompilation.errors
        assert decompilation.codegen is not None
        text = decompilation.codegen.text
        assert text is not None
        assert "uint80_t " in text
        assert "int v1;  // st0" not in text
        assert text.count("pbr_f80_from_bits") == 2

    def test_convert_pcode_call_return_expressions_are_unique(self):
        arch = archinfo.ArchPcode("x86:LE:16:Real Mode")
        manager = ailment.Manager(arch=arch)  # pyright: ignore[reportArgumentType]
        project = angr.load_shellcode(
            bytes.fromhex("e80900 90 e80500 9090909090 c3"),
            arch,
            0,
            0,
            engine=angr.engines.UberEnginePcode,
            rebase_granularity=0x10,
        )

        ret_exprs = []
        for addr in (0, 4):
            irsb = project.factory.block(addr, size=3).vex
            block = ailment.IRSBConverter.convert(irsb, manager)
            call = next(
                statement for statement in block.statements if isinstance(statement, ailment.Stmt.SideEffectStatement)
            )
            assert isinstance(call.ret_expr, ailment.Expr.Register)
            ret_exprs.append(call.ret_expr)

        assert ret_exprs[0].idx != ret_exprs[1].idx
        assert ret_exprs[0] != ret_exprs[1]

    def test_decompile_pcode_real_mode_stack_operations(self):
        arch = archinfo.ArchPcode("x86:LE:16:Real Mode")
        project = angr.load_shellcode(
            b"\x1e\xc3",
            arch,
            0,
            0,
            engine=angr.engines.UberEnginePcode,
            rebase_granularity=0x10,
        )
        cfg = project.analyses.CFGFast(
            function_starts=[0],
            regions=[(0, 2)],
            force_complete_scan=False,
            force_smart_scan=False,
            normalize=True,
            resolve_indirect_jumps=False,
        )

        decompilation = project.analyses.Decompiler(
            cfg.kb.functions[0],
            cfg=cfg.model,
            fail_fast=False,
            use_cache=False,
            update_cache=False,
        )

        assert decompilation.codegen is not None
        assert not any("Unsupported bits 16" in str(error) for error in decompilation.errors)
        assert not any(
            construct.kind == "dirty_expression" and construct.operation == "CALLOTHER"
            for construct in decompilation.codegen.unsupported_constructs
        )
        assert decompilation.codegen.text is not None
        assert "CALLOTHER" not in decompilation.codegen.text

    def test_convert_pcode_uppercase_memory_space(self):
        arch = archinfo.ArchPcode("6502:LE:16:default")
        manager = ailment.Manager(arch=arch)  # pyright: ignore[reportArgumentType]
        translation = pypcode.Context(arch.name).translate(bytes.fromhex("ad34128d7856"), base_address=0)
        load_varnode = translation.ops[1].inputs[0]
        store_varnode = translation.ops[5].output
        assert load_varnode is not None
        assert store_varnode is not None
        assert load_varnode.space.name == store_varnode.space.name == "RAM"

        converter = object.__new__(ailment.PCodeIRSBConverter)
        converter._manager = manager
        converter._statement_idx = 0

        load = converter._get_value(load_varnode)
        store = converter._set_value(store_varnode, ailment.Expr.Const(None, 0xAA, 8))

        assert isinstance(load, ailment.Expr.Load)
        assert isinstance(load.addr, ailment.Expr.Const)
        assert load.addr.value == 0x1234
        assert load.size == 1
        assert isinstance(store, ailment.Stmt.Store)
        assert isinstance(store.addr, ailment.Expr.Const)
        assert store.addr.value == 0x5678
        assert store.size == 1

    def test_lift_path_matches_python_path(self):
        """The direct libVEX-lift fast path must produce the same AIL block as
        converting a cached pyvex Python IRSB."""
        arch = archinfo.arch_from_id("AMD64")
        irsb = pyvex.IRSB(self.block_bytes, self.block_addr, arch, opt_level=0)
        from_py = VEXIRSBConverter.convert(irsb, ailment.Manager(arch=arch))
        from_lift = VEXIRSBConverter.convert_from_lift(
            arch, self.block_addr, self.block_bytes, ailment.Manager(arch=arch), opt_level=0
        )
        assert from_py == from_lift
        assert from_py.statements  # non-empty


class TestNonConstRoundingMode(unittest.TestCase):
    """VEX sometimes carries the rounding mode in a tmp (e.g. ARM ``vcvtr``
    reads it from FPSCR); the converter must pass it through as an AIL
    ``Expression`` rather than dropping it, so the decompilation pipeline can
    resolve it to a constant later."""

    # vcvtr.s32.f64 s0, d1 ; bx lr -- F64toI32S(t_rm, t_val) with a computed rm
    block_bytes = bytes.fromhex("410bbdee1eff2fe1")

    @staticmethod
    def _find_convert(expr):
        if isinstance(expr, ailment.Expr.Convert):
            return expr
        for attr in ("operand", "src"):
            inner = getattr(expr, attr, None)
            if inner is not None:
                found = TestNonConstRoundingMode._find_convert(inner)
                if found is not None:
                    return found
        return None

    def test_tmp_rounding_mode_is_expression(self):
        arch = archinfo.arch_from_id("armel")
        irsb = pyvex.IRSB(self.block_bytes, 0x1000, arch, opt_level=1)
        from_py = VEXIRSBConverter.convert(irsb, ailment.Manager(arch=arch))
        from_lift = VEXIRSBConverter.convert_from_lift(
            arch, 0x1000, self.block_bytes, ailment.Manager(arch=arch), opt_level=1
        )
        assert from_py == from_lift

        conv = next(c for c in (self._find_convert(getattr(s, "src", s)) for s in from_py.statements) if c is not None)
        rm = conv.rounding_mode
        assert isinstance(rm, ailment.expression.Expression)
        assert isinstance(rm, ailment.Expr.Tmp)
        # a rebuilt Convert accepts the expression form back
        rebuilt = ailment.Expr.Convert(
            conv.idx,
            conv.from_bits,
            conv.to_bits,
            conv.is_signed,
            conv.operand,
            from_type=conv.from_type,
            to_type=conv.to_type,
            rounding_mode=rm,
            **dict(conv.tags),
        )
        assert rebuilt == conv
        # serde round-trip keeps the expression form
        assert pickle.loads(pickle.dumps(from_py)) == from_py

    def test_const_rounding_mode_still_enum(self):
        arch = archinfo.arch_from_id("i386")
        irsb = pyvex.IRSB(bytes.fromhex("d8c1c3"), 0x1000, arch, opt_level=1)  # fadd st0, st1 ; ret
        blk = VEXIRSBConverter.convert(irsb, ailment.Manager(arch=arch))
        binop = next(
            s.src
            for s in blk.statements
            if isinstance(getattr(s, "src", None), ailment.Expr.BinaryOp) and s.src.floating_point
        )
        assert isinstance(binop.rounding_mode, RoundingMode)


class TestVectorSignedness(unittest.TestCase):
    @staticmethod
    def _find_haddv(block):
        return next(
            stmt.src
            for stmt in block.statements
            if isinstance(getattr(stmt, "src", None), ailment.Expr.BinaryOp) and stmt.src.op == "HAddV"
        )

    def test_haddv_signedness(self):
        arch = archinfo.arch_from_id("armel")

        for name, block_bytes, expected_signed in (
            ("sadd8", bytes.fromhex("920f11e6"), True),
            ("uadd8", bytes.fromhex("920f51e6"), False),
        ):
            with self.subTest(instruction=name):
                irsb = pyvex.IRSB(block_bytes, 0x1000, arch, opt_level=0)
                from_py = VEXIRSBConverter.convert(irsb, ailment.Manager(arch=arch))
                from_lift = VEXIRSBConverter.convert_from_lift(
                    arch, 0x1000, block_bytes, ailment.Manager(arch=arch), opt_level=0
                )

                assert from_py == from_lift
                for block in (from_py, from_lift):
                    haddv = self._find_haddv(block)
                    assert haddv.signed is expected_signed
                    assert haddv.vector_count == 4
                    assert haddv.vector_size == 8


class TestVexConverterAcrossArches(unittest.TestCase):
    """Convert real blocks from test binaries through both the Python-IRSB path
    and the libVEX-lift path, and assert the two agree."""

    BINARIES = [
        ("x86_64", "x86_64/1after909"),
        ("i386", "i386/fauxware"),
        ("armel", "armel/fauxware"),
        ("ppc", "ppc/fauxware"),
        ("mips", "mips/fauxware"),
        ("s390x", "s390x/fauxware"),
    ]

    def _check_binary(self, path):
        if not os.path.exists(path):
            self.skipTest(f"missing binary {path}")
        p = angr.Project(path, auto_load_libs=False)
        arch = p.arch
        cfg = p.analyses.CFGFast(normalize=True)
        checked = 0
        for node in cfg.model.nodes():
            if not node.size:
                continue
            thumb = bool(getattr(node, "thumb", False))
            lift_addr = (node.addr | 1) if thumb else node.addr
            bytes_offset = 1 if thumb else 0
            try:
                # Generous trailing bytes so thumb boundary decode is deterministic.
                data = bytes(p.loader.memory.load(node.addr, node.size + 32))
            except Exception:
                continue
            try:
                irsb = pyvex.IRSB(data, lift_addr, arch, opt_level=1, bytes_offset=bytes_offset)
            except Exception:
                continue
            if irsb.size == 0:
                continue
            try:
                from_py = VEXIRSBConverter.convert(
                    pyvex.IRSB(data, lift_addr, arch, opt_level=1, bytes_offset=bytes_offset),
                    ailment.Manager(arch=arch),
                )
            except Exception:
                continue
            try:
                from_lift = VEXIRSBConverter.convert_from_lift(
                    arch, lift_addr, data, ailment.Manager(arch=arch), opt_level=1, bytes_offset=bytes_offset
                )
            except Exception:
                # The fast path defers blocks with statements/expressions it can't
                # render byte-identically (MBE/LLSC/PutI, GetI/Qop, ...) to the
                # Python-IRSB path; those are exercised by the fallback.
                continue
            assert from_py == from_lift, f"mismatch at {node.addr:#x} in {path}"
            checked += 1
        assert checked > 0, f"no blocks checked in {path}"

    def test_arches(self):
        base = os.path.join(os.path.dirname(__file__), "..", "..", "..", "binaries", "tests")
        for _name, rel in self.BINARIES:
            with self.subTest(binary=rel):
                self._check_binary(os.path.normpath(os.path.join(base, rel)))


class TestLiftWindowOverread(unittest.TestCase):
    """libVEX decoders may read the full length of an instruction that starts
    inside the lift window, i.e. a few bytes past ``max_bytes`` -- and past the
    end of the buffer when the window ends at it. The fast path must pad such
    windows with NULs (mirroring pyvex) instead of lifting adjacent heap
    garbage, which made the block content (jumpkind, temp numbering)
    nondeterministic."""

    # 38 bytes at 0x400b5a in s390x/fauxware: nopr padding + function prologue,
    # ending with the first 4 bytes of a 6-byte `lg` at 0x400b7c. The last two
    # bytes of the `lg` fall outside the window; whether it decodes depends
    # entirely on out-of-window bytes.
    window = bytes.fromhex("070707070707eb6ff0300024b904001fa7fbff60e310f0000024c0c000000a060707e340f110")
    addr = 0x400B5A

    def test_lift_does_not_read_past_window(self):
        arch = archinfo.arch_from_id("s390x")
        from_py = VEXIRSBConverter.convert(
            pyvex.IRSB(self.window, self.addr, arch, opt_level=1), ailment.Manager(arch=arch)
        )
        # 0x04 completes the truncated `lg`: an unguarded overread decodes it
        # and ends the block Ijk_Boring instead of Ijk_NoDecode.
        backing = bytearray(self.window + b"\x04" * 8)
        from_lift_mv = VEXIRSBConverter.convert_from_lift(
            arch, self.addr, memoryview(backing)[: len(self.window)], ailment.Manager(arch=arch), opt_level=1
        )
        from_lift_bytes = VEXIRSBConverter.convert_from_lift(
            arch, self.addr, self.window, ailment.Manager(arch=arch), opt_level=1
        )
        assert from_py == from_lift_mv
        assert from_py == from_lift_bytes


class TestVexOpParity(unittest.TestCase):
    """The Rust vexop classifier must match Python ``vexop_to_simop`` for every
    VEX op (guards against drift in the hand-ported claripy/irop name-sets)."""

    def test_vexop_parity(self):
        mismatches = []
        for name, op_int in irop_enums_to_ints.items():
            if name in ("Iop_INVALID", "Iop_LAST"):
                continue
            rust = _vexop_debug(op_int)
            try:
                simop = irop.vexop_to_simop(name)
            except Exception:
                # Python considers it unsupported; Rust must too.
                if rust is not None:
                    mismatches.append((name, "python-unsupported but rust-supported"))
                continue
            if rust is None:
                mismatches.append((name, "rust-unsupported but python-supported"))
                continue
            checks = {
                "generic_name": simop._generic_name,
                "output_size_bits": simop._output_size_bits,
                "is_signed": simop.is_signed,
                "is_conversion": simop._conversion is not None,
                "float": simop._float,
                "from_size": simop._from_size,
                "to_size": simop._to_size,
                "vector_count": simop._vector_count,
                "vector_size": simop._vector_size,
            }
            for key, expected in checks.items():
                if rust[key] != expected:
                    mismatches.append((name, f"{key}: rust={rust[key]!r} py={expected!r}"))

        assert not mismatches, "vexop parity mismatches:\n" + "\n".join(f"  {n}: {m}" for n, m in mismatches[:50])


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import struct
import unittest

import archinfo
import pyvex

import angr
from angr.blade import Blade
from angr.slicer import SimSlicer


class TestLightSlicing(unittest.TestCase):
    def test_overlapping_register_writes(self):
        arch = archinfo.ArchX86()
        eax = arch.registers["eax"][0]
        statements = [
            pyvex.IRStmt.Put(pyvex.IRExpr.Const(pyvex.IRConst.U32(0)), eax),
            pyvex.IRStmt.Put(pyvex.IRExpr.Const(pyvex.IRConst.U8(1)), eax),
            pyvex.IRStmt.Put(pyvex.IRExpr.Const(pyvex.IRConst.U8(2)), eax + 1),
        ]
        for needed, expected in [
            ({eax}, [1]),
            ({eax + 1}, [2]),
            ({eax, eax + 1}, [1, 2]),
            (set(range(eax, eax + 4)), [0, 1, 2]),
        ]:
            with self.subTest(needed=needed):
                slicer = SimSlicer(arch, statements, target_reg_bytes=needed)
                assert slicer.stmt_indices == expected
                assert slicer.final_reg_bytes == set()
        slicer = SimSlicer(arch, statements, target_regs={eax})
        assert slicer.stmt_indices == [0, 1, 2]

    def test_partial_read_does_not_require_other_bytes(self):
        arch = archinfo.ArchX86()
        eax = arch.registers["eax"][0]
        tyenv = pyvex.IRTypeEnv(arch, types=["Ity_I8"])
        statements = [
            pyvex.IRStmt.Put(pyvex.IRExpr.Const(pyvex.IRConst.U8(2)), eax + 1),
            pyvex.IRStmt.WrTmp(0, pyvex.IRExpr.Get(eax, "Ity_I8")),
        ]
        slicer = SimSlicer(arch, statements, target_tmps={0}, tyenv=tyenv)
        assert slicer.stmt_indices == [1]
        assert slicer.final_reg_bytes == {eax}
        assert slicer.final_regs == {eax}

    def test_temporary_write_sizes(self):
        arch = archinfo.ArchX86()
        eax = arch.registers["eax"][0]
        for typ, const, expected in [
            ("Ity_I8", pyvex.IRConst.U8(1), [0, 1, 2]),
            ("Ity_I16", pyvex.IRConst.U16(1), [0, 1, 2]),
            ("Ity_I32", pyvex.IRConst.U32(1), [1, 2]),
        ]:
            with self.subTest(typ=typ):
                statements = [
                    pyvex.IRStmt.Put(pyvex.IRExpr.Const(pyvex.IRConst.U32(0)), eax),
                    pyvex.IRStmt.WrTmp(0, pyvex.IRExpr.Const(const)),
                    pyvex.IRStmt.Put(pyvex.IRExpr.RdTmp(0), eax),
                ]
                slicer = SimSlicer(arch, statements, target_regs={eax}, tyenv=pyvex.IRTypeEnv(arch, types=[typ]))
                assert slicer.stmt_indices == expected
                conservative = SimSlicer(arch, statements, target_regs={eax})
                assert conservative.stmt_indices == [0, 1, 2]

    def test_architecture_write_semantics(self):
        for arch, code, register, expected_offsets in [
            ("amd64", "48b8112233445566778866b80100ffe0", "rax", {0, 10}),
            ("amd64", "48b81122334455667788b801000000ffe0", "rax", {10}),
            ("aarch64", "000080d22000805200001fd6", "x0", {4}),
        ]:
            with self.subTest(arch=arch, code=code):
                project = angr.load_shellcode(bytes.fromhex(code), arch=arch, load_address=0x400000)
                block = project.factory.block(0x400000, cross_insn_opt=False).vex
                slicer = SimSlicer(
                    project.arch,
                    block.statements,
                    target_regs={project.arch.registers[register][0]},
                    tyenv=block.tyenv,
                    include_imarks=False,
                )
                address = None
                addresses = set()
                for index, stmt in enumerate(block.statements):
                    if isinstance(stmt, pyvex.IRStmt.IMark):
                        address = stmt.addr
                    elif index in slicer.stmt_indices:
                        assert address is not None
                        addresses.add(address - block.addr)
                assert addresses == expected_offsets

    def test_blade_carries_exact_bytes_across_blocks(self):
        # Full EAX initialization, then AL in a successor, then an EAX consumer.
        code = bytes.fromhex("b800000000eb00b001eb00ffe0")
        project = angr.load_shellcode(code, arch="x86", load_address=0x400000)
        cfg = project.analyses.CFGFast(normalize=True, resolve_indirect_jumps=False, force_complete_scan=False)
        blade = Blade(cfg.graph, 0x40000B, -1, project=project, cfg=cfg, include_imarks=False)
        assert {addr for addr, _ in blade.slice} == {0x400000, 0x400007, 0x40000B}

    def test_unknown_upper_bytes_survive(self):
        for arch, register, code, remaining in [
            ("x86", "eax", "b001ffe0", {1, 2, 3}),
            ("x86", "eax", "b401ffe0", {0, 2, 3}),
            ("x86", "eax", "66b80100ffe0", {2, 3}),
            ("amd64", "rax", "66b80100ffe0", {2, 3, 4, 5, 6, 7}),
            ("x86", "eax", "31c0b00189d0ffe0", None),
        ]:
            with self.subTest(arch=arch, code=code):
                project = angr.load_shellcode(bytes.fromhex(code), arch=arch, load_address=0x400000)
                irsb = project.factory.block(0x400000, cross_insn_opt=False).vex
                offset = project.arch.registers[register][0]
                slicer = SimSlicer(project.arch, irsb.statements, target_regs={offset}, tyenv=irsb.tyenv)
                if remaining is None:
                    source, size = project.arch.registers["edx"]
                    expected = set(range(source, source + size))
                else:
                    expected = {offset + byte for byte in remaining}
                assert slicer.final_reg_bytes == expected
                assert slicer.final_regs == {project.arch.registers["edx"][0] if remaining is None else offset}

    def test_blade_ignores_all_register_bytes(self):
        for ignore_sp, ignored_regs in ((True, None), (False, ["esp"]), (False, ["sp"])):
            with self.subTest(ignore_sp=ignore_sp, ignored_regs=ignored_regs):
                project = angr.load_shellcode(bytes.fromhex("89d4eb0089e0ffe0"), arch="x86", load_address=0x400000)
                cfg = project.analyses.CFGFast(normalize=True, resolve_indirect_jumps=False, force_complete_scan=False)
                blade = Blade(
                    cfg.graph, 0x400004, -1, project=project, cfg=cfg, ignore_sp=ignore_sp, ignored_regs=ignored_regs
                )
                assert {addr for addr, _ in blade.slice} == {0x400004}

    def test_boolean_selector_targets(self):
        for prefix, opcode in [
            ("31c085f60f94c0", "ff2485"),
            ("31c0837c2404000f9fc0", "ff2485"),
            ("31c985c00f95c1", "ff248d"),
            ("31c085f60f94c00fb6c0", "ff2485"),
        ]:
            with self.subTest(prefix=prefix):
                base, table = 0x400000, 0x400200
                caller = bytes.fromhex(prefix + opcode) + struct.pack("<I", table)
                targets = [base + len(caller) + index * 6 for index in range(3)]
                code = caller + b"".join(b"\xb8" + struct.pack("<I", i) + b"\xc3" for i in range(3))
                blob = code.ljust(table - base, b"\0") + struct.pack("<III", *targets)
                project = angr.load_shellcode(blob.ljust(0x600, b"\0"), arch="x86", load_address=base)
                cfg = project.analyses.CFGFast(
                    normalize=True, force_complete_scan=False, regions=[(base, base + len(code))]
                )
                assert not cfg.errors
                jump = cfg.indirect_jumps[base]
                assert set(jump.resolved_targets) == set(targets[:2])
                assert not jump.jumptable_entries_guessed
                node = cfg.model.get_any_node(base)
                assert node is not None
                assert {n.addr for n in cfg.graph.successors(node)} == set(targets[:2])


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use,protected-access
from __future__ import annotations

__package__ = __package__ or "tests.analyses.cfg"  # pylint:disable=redefined-builtin

import os
import unittest
from unittest import mock

import pyvex
from archinfo.arch_arm import ArchARM
from pyvex.lifting.libvex import _libvex_lock

import angr
from angr.analyses.cfg.cfg_fast import CFGFast
from angr.rustylib.vexlift import (
    LiftSummary,
    VexLifter,
    deregister_all_readonly_regions,
    register_readonly_region,
)
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")

BINARIES = [
    "x86_64/fauxware",
    "i386/fauxware",
    "armel/fauxware",
    "armel/arm_thumb_filter_jump_successors",
    "mips/fauxware",
    "aarch64/test_arrays",
    "ppc/fauxware",
]


def _make_lifter(proj: angr.Project) -> VexLifter:
    proj.loader.gen_ro_memview()
    memory = proj.loader.memory_ro_view
    assert memory is not None
    return VexLifter(
        proj.arch.vex_arch,
        proj.arch.vex_archinfo,
        isinstance(proj.arch, ArchARM),
        memory._flattened_backers,
        _libvex_lock,
    )


def _pyvex_nostmt(proj: angr.Project, addr: int, const_prop: bool = False, initial_regs=None) -> pyvex.IRSB:
    """The lift CFGFast._generate_cfgnode performs through the Python path."""
    block = proj.factory.block(
        addr,
        opt_level=1,
        cross_insn_opt=False,
        collect_data_refs=True,
        strict_block_end=True,
        load_from_ro_regions=True,
        const_prop=const_prop,
        initial_regs=initial_regs,
        skip_stmts=True,
    )
    return block.vex_nostmt


def _py_successors(irsb: pyvex.IRSB, branch_delay_slot: bool) -> list[tuple[int, int, int, str]]:
    """The statement-less successor enumeration of CFGFast._scan_irsb."""
    successors = []
    for ins_addr, stmt_idx, exit_stmt in irsb.exit_statements:
        branch_ins_addr = ins_addr
        if branch_delay_slot and irsb.instruction_addresses and ins_addr in irsb.instruction_addresses:
            idx_ = irsb.instruction_addresses.index(ins_addr)
            if idx_ > 0:
                next_ins_addr = (
                    irsb.instruction_addresses[idx_ + 1]
                    if idx_ + 1 < len(irsb.instruction_addresses)
                    else irsb.addr + irsb.size
                )
                if next_ins_addr - ins_addr <= ins_addr - irsb.instruction_addresses[idx_ - 1]:
                    branch_ins_addr = irsb.instruction_addresses[idx_ - 1]
        elif (
            not branch_delay_slot
            and irsb.instruction_addresses
            and branch_ins_addr != irsb.instruction_addresses[-1]
            and exit_stmt.dst.value == branch_ins_addr
            and exit_stmt.jumpkind == "Ijk_Boring"
        ):
            continue
        successors.append((stmt_idx, branch_ins_addr, exit_stmt.dst.value, exit_stmt.jumpkind))
    return successors


def _assert_summary_matches(tc: unittest.TestCase, summary: LiftSummary, irsb: pyvex.IRSB, branch_delay_slot: bool):
    tc.assertEqual(summary.addr, irsb.addr)
    tc.assertEqual(summary.size, irsb.size)
    tc.assertEqual(summary.jumpkind, irsb.jumpkind)
    tc.assertEqual(summary.instructions, irsb.instructions)
    tc.assertEqual(summary.instruction_addresses, irsb.instruction_addresses)
    tc.assertEqual(summary.is_noop_block, irsb.is_noop_block)
    tc.assertEqual(summary.default_exit_target, irsb.default_exit_target)
    if isinstance(irsb.next, pyvex.IRExpr.Const):
        tc.assertEqual(summary.next, irsb.next.con.value)
        tc.assertIsNone(summary.next_tmp)
    elif isinstance(irsb.next, pyvex.IRExpr.RdTmp):
        tc.assertIsNone(summary.next)
        tc.assertEqual(summary.next_tmp, irsb.next.tmp)
    else:
        tc.assertIsNone(summary.next)
        tc.assertIsNone(summary.next_tmp)
    tc.assertEqual(
        [(e.ins_addr, e.stmt_idx, e.dst, e.jumpkind) for e in summary.exits],
        [(ins_addr, stmt_idx, ex.dst.value, ex.jumpkind) for ins_addr, stmt_idx, ex in irsb.exit_statements],
    )
    tc.assertEqual(
        [(ins_addr, stmt_idx, e.dst) for ins_addr, stmt_idx, e in summary.exit_statements],
        [(ins_addr, stmt_idx, ex.dst.value) for ins_addr, stmt_idx, ex in irsb.exit_statements],
    )
    tc.assertEqual(
        [(d.data_addr, d.data_size, d.data_type, d.data_type_str, d.stmt_idx, d.ins_addr) for d in summary.data_refs],
        [
            (d.data_addr, d.data_size, d.data_type, d.data_type_str, d.stmt_idx, d.ins_addr)
            for d in (irsb.data_refs or [])
        ],
    )
    tc.assertEqual(
        [(c.tmp, c.stmt_idx, c.value) for c in summary.const_vals],
        [(c.tmp, c.stmt_idx, c.value) for c in (irsb.const_vals or [])],
    )
    tc.assertEqual(summary.conditional_successors(branch_delay_slot), _py_successors(irsb, branch_delay_slot))
    tc.assertIsNone(summary.statements)
    tc.assertFalse(summary.has_statements)


class TestVexLiftSummary(unittest.TestCase):
    def _check_binary(self, binary: str):
        proj = angr.Project(os.path.join(test_location, binary), auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=False, show_progressbar=False)
        self.assertGreater(cfg._lift_stats["rust"], 0)
        lifter = _make_lifter(proj)
        branch_delay_slot = proj.arch.branch_delay_slot
        checked = 0
        for node in cfg.model.graph.nodes():
            if node.is_simprocedure or node.size == 0:
                continue
            result = lifter.lift(node.addr, 400)
            irsb = _pyvex_nostmt(proj, node.addr)
            if result is None:
                # the Python path also lifts nothing here
                self.assertTrue(irsb.size == 0 or irsb.jumpkind == "Ijk_NoDecode", (node, lifter.last_fallback))
                continue
            summary, block_bytes = result
            _assert_summary_matches(self, summary, irsb, branch_delay_slot)
            if block_bytes is not None:
                real_addr = node.addr & ~1 if isinstance(proj.arch, ArchARM) else node.addr
                self.assertEqual(block_bytes, proj.loader.memory_ro_view.load(real_addr, summary.size))
            if node.thumb:
                self.assertTrue(summary.addr & 1)
                self.assertTrue(all(a & 1 for a in summary.instruction_addresses))
            checked += 1
        self.assertGreater(checked, 5)

    def test_amd64(self):
        self._check_binary("x86_64/fauxware")

    def test_x86(self):
        self._check_binary("i386/fauxware")

    def test_armel_arm_and_thumb(self):
        self._check_binary("armel/fauxware")

    def test_armel_thumb(self):
        self._check_binary("armel/arm_thumb_filter_jump_successors")

    def test_mips(self):
        self._check_binary("mips/fauxware")

    def test_aarch64(self):
        self._check_binary("aarch64/test_arrays")

    def test_ppc(self):
        self._check_binary("ppc/fauxware")

    def test_lift_jumpkind(self):
        # the jumpkind of CFGBase._lift(addr).vex, for block starts and for addresses inside blocks
        for name in ("x86_64/fauxware", "armel/fauxware", "mips/fauxware"):
            proj = angr.Project(os.path.join(test_location, name), auto_load_libs=False)
            cfg = proj.analyses.CFGFast(normalize=True)
            lifter = _make_lifter(proj)
            addrs = sorted({n.addr for n in cfg.model.graph.nodes() if not proj.is_hooked(n.addr)})
            lifted = 0
            for addr in addrs + [a + 1 for a in addrs]:
                jumpkind = lifter.lift_jumpkind(addr)
                if jumpkind is None:
                    continue
                lifted += 1
                assert jumpkind == proj.factory.block(addr, opt_level=1, cross_insn_opt=False).vex.jumpkind, hex(addr)
            assert lifted > len(addrs) // 2

    def test_fallbacks(self):
        proj = angr.Project(os.path.join(test_location, "x86_64/fauxware"), auto_load_libs=False)
        lifter = _make_lifter(proj)
        self.assertIsNone(lifter.lift(0x10, 400))
        self.assertEqual(lifter.last_fallback, "no_backer")
        self.assertIsNone(lifter.lift(proj.entry, 0))
        self.assertEqual(lifter.last_fallback, "empty_window")
        self.assertIsNotNone(lifter.lift(proj.entry, 400))
        self.assertIsNone(lifter.last_fallback)
        # a max_size smaller than the block truncates exactly like VEXLifter's size cap
        summary, _ = lifter.lift(proj.entry, 6)
        irsb = proj.factory.block(proj.entry, size=6, opt_level=1, cross_insn_opt=False, strict_block_end=True).vex
        self.assertEqual(summary.size, irsb.size)
        self.assertEqual(summary.instruction_addresses, irsb.instruction_addresses)

    def test_mutation(self):
        proj = angr.Project(os.path.join(test_location, "x86_64/fauxware"), auto_load_libs=False)
        lifter = _make_lifter(proj)
        summary, _ = lifter.lift(proj.entry, 400)
        summary.size = 4
        summary.jumpkind = "Ijk_Ret"
        summary.next = 0x1234
        summary.instruction_addresses = (proj.entry,)
        summary.exits = []
        summary.data_refs = []
        self.assertEqual((summary.size, summary.jumpkind, summary.next), (4, "Ijk_Ret", 0x1234))
        self.assertEqual(summary.instruction_addresses, (proj.entry,))
        self.assertEqual(summary.exits, [])
        self.assertEqual(summary.conditional_successors(False), [])
        with self.assertRaises(ValueError):
            summary.jumpkind = "Ijk_Bogus"

    def test_readonly_regions_const_prop(self):
        # an AMD64 PLT stub jumps through a GOT slot: with the segment registered as read-only, libVEX folds the
        # loaded pointer into const_vals on both the pyvex path and the Rust path
        proj = angr.Project(os.path.join(test_location, "x86_64/fauxware"), auto_load_libs=False)
        plt_addr = next(iter(proj.loader.main_object.reverse_plt))
        regions = []
        for segment in proj.loader.main_object.segments:
            if segment.is_readable and segment.memsize >= 8:
                content = proj.loader.memory.load(segment.vaddr, segment.memsize)
                regions.append((segment.vaddr, segment.memsize, content))
        try:
            for start, size, content in regions:
                self.assertTrue(register_readonly_region(start, size, content))
            lifter = _make_lifter(proj)
            summary, _ = lifter.lift(plt_addr, 400, None, True)
            irsb = _pyvex_nostmt(proj, plt_addr, const_prop=True)
            _assert_summary_matches(self, summary, irsb, False)
            self.assertIsNotNone(summary.next_tmp)
            folded = [cv.value for cv in summary.const_vals if cv.tmp == summary.next_tmp]
            self.assertEqual(len(folded), 1)
            # the folded value is the pointer stored in the GOT slot the stub reads
            slots = [d.data_addr for d in summary.data_refs if d.data_size == 8]
            self.assertIn(folded[0], [proj.loader.memory.unpack_word(slot) for slot in slots])
        finally:
            deregister_all_readonly_regions()
        # without regions nothing is folded, and the two paths still agree
        summary, _ = lifter.lift(plt_addr, 400, None, True)
        irsb = _pyvex_nostmt(proj, plt_addr, const_prop=True)
        _assert_summary_matches(self, summary, irsb, False)
        self.assertEqual(summary.const_vals, [])

    def test_initial_registers_mips(self):
        # CFGFast seeds t9 (and gp) so that gp-relative data references resolve; the Rust path must register the
        # same values and reset them after every lift
        proj = angr.Project(os.path.join(test_location, "mips/fauxware"), auto_load_libs=False)
        lifter = _make_lifter(proj)
        main_addr = proj.loader.find_symbol("main").rebased_addr
        t9 = proj.arch.registers["t9"]
        gp = proj.arch.registers["gp"]
        initial_regs = [(t9[0], t9[1], main_addr), (gp[0], gp[1], 0x418000)]
        summary, _ = lifter.lift(main_addr, 400, initial_regs)
        irsb = _pyvex_nostmt(proj, main_addr, initial_regs=initial_regs)
        _assert_summary_matches(self, summary, irsb, True)
        self.assertTrue(summary.data_refs)
        # the registered values are reset: a lift without them matches the no-register pyvex lift
        summary_plain, _ = lifter.lift(main_addr, 400)
        _assert_summary_matches(self, summary_plain, _pyvex_nostmt(proj, main_addr), True)

    def test_initial_registers_shellcode(self):
        # lw $t9, 0x10($gp); jr $t9; nop -- the load address is a data reference only when gp is seeded
        code = bytes.fromhex("8f9900100320000800000000")
        proj = angr.load_shellcode(code, "MIPS32", load_address=0x400000)
        lifter = _make_lifter(proj)
        gp = proj.arch.registers["gp"]
        initial_regs = [(gp[0], gp[1], 0x418000)]
        summary, _ = lifter.lift(0x400000, 400, initial_regs)
        _assert_summary_matches(self, summary, _pyvex_nostmt(proj, 0x400000, initial_regs=initial_regs), True)
        self.assertIn(0x418010, [d.data_addr for d in summary.data_refs])
        summary_plain, _ = lifter.lift(0x400000, 400)
        _assert_summary_matches(self, summary_plain, _pyvex_nostmt(proj, 0x400000), True)
        self.assertNotIn(0x418010, [d.data_addr for d in summary_plain.data_refs])

    def test_cfgfast_matches_python_path(self):
        path = os.path.join(test_location, "x86_64/fauxware")

        def digest(cfg):
            nodes = sorted((n.addr, n.size, n.function_address, tuple(n.instruction_addrs)) for n in cfg.model.graph)
            edges = sorted(
                (s.addr, d.addr, data["jumpkind"], data.get("ins_addr"), str(data.get("stmt_idx")))
                for s, d, data in cfg.model.graph.edges(data=True)
            )
            funcs = sorted((f.addr, f.returning, sorted(f.block_addrs_set)) for f in cfg.kb.functions.values())
            xrefs = sorted(
                (x.ins_addr, x.block_addr, str(x.stmt_idx), x.dst)
                for xs in cfg.kb.xrefs.xrefs_by_ins_addr.values()
                for x in xs
            )
            return nodes, edges, funcs, xrefs

        proj = angr.Project(path, auto_load_libs=False)
        cfg_rust = proj.analyses.CFGFast(normalize=False, show_progressbar=False, data_references=True)
        self.assertGreater(cfg_rust._lift_stats["rust"], 0)
        self.assertEqual(cfg_rust._lift_stats["python"], 0)
        self.assertIsNone(cfg_rust._rust_lifter)  # released with the read-only regions

        proj = angr.Project(path, auto_load_libs=False)
        with mock.patch.object(CFGFast, "_init_rust_lifter", return_value=None):
            cfg_py = proj.analyses.CFGFast(normalize=False, show_progressbar=False, data_references=True)
        self.assertEqual(cfg_py._lift_stats["rust"], 0)
        self.assertEqual(digest(cfg_rust), digest(cfg_py))


if __name__ == "__main__":
    unittest.main()

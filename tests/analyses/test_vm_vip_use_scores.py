#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use,protected-access
from __future__ import annotations

__package__ = __package__ or "tests.analyses"  # pylint:disable=redefined-builtin

import itertools
import os
import types
import unittest

import angr
from angr.engines.vex.light.light import VEXMixin

from ..common import bin_location


def _reference_use_scores(self, candidate_vips):
    # the unmemoized scoring as it was before the per-block cache
    bbl = self.state.globals.get("cur_bbl", None)
    if bbl is None or not candidate_vips:
        return {}
    scores = {reg_tup: 0 for reg_tup in candidate_vips}
    reg_to_tups = {}
    for reg_tup in candidate_vips:
        reg_name = self._vip_reg_name_from_tup(reg_tup)
        if reg_name is None:
            continue
        reg_to_tups.setdefault(reg_name, set()).add(reg_tup)
    if not reg_to_tups:
        return scores
    capstone_insns = getattr(getattr(bbl, "capstone", None), "insns", None)
    disassembly = getattr(bbl, "disassembly", None)
    insns = capstone_insns or getattr(disassembly, "insns", [])

    def add_score(reg_name, score):
        for reg_tup in reg_to_tups.get(reg_name, ()):
            scores[reg_tup] = scores.get(reg_tup, 0) + score

    def operand_reg(cap_insn, operand):
        reg_name_func = getattr(cap_insn, "reg_name", None)
        if reg_name_func is None or getattr(operand, "type", None) != 1:
            return None
        return self._vip_canonical_reg_name(reg_name_func(operand.reg))

    def mem_regs(cap_insn, mem):
        reg_name_func = getattr(cap_insn, "reg_name", None)
        if reg_name_func is None or mem is None:
            return []
        regs = []
        if getattr(mem, "base", 0):
            regs.append(self._vip_canonical_reg_name(reg_name_func(mem.base)))
        if getattr(mem, "index", 0):
            regs.append(self._vip_canonical_reg_name(reg_name_func(mem.index)))
        return [reg for reg in regs if reg is not None]

    def first_operand_is_written(operands, mnemonic):
        if not operands or getattr(operands[0], "type", None) != 1:
            return False
        access = getattr(operands[0], "access", None)
        if access:
            return bool(access & 2)
        return mnemonic not in {"cmp", "test", "jmp", "call", "push"}

    for ins in insns:
        cap_insn = getattr(ins, "insn", ins)
        operands = getattr(cap_insn, "operands", [])
        mnemonic = getattr(cap_insn, "mnemonic", "")
        if not operands:
            continue
        dest_reg = operand_reg(cap_insn, operands[0])
        dest_is_write = first_operand_is_written(operands, mnemonic)
        for op_idx, operand in enumerate(operands):
            mem = getattr(operand, "mem", None)
            if mem is None:
                continue
            for reg_name in mem_regs(cap_insn, mem):
                if reg_name not in reg_to_tups:
                    continue
                add_score(reg_name, 36)
                if op_idx > 0 or not dest_is_write:
                    add_score(reg_name, 24)
                if mnemonic in ("mov", "movsxd", "movzx", "lods", "lodsb", "lodsd", "lodsq"):
                    add_score(reg_name, 10)
        if dest_reg is None or dest_reg not in reg_to_tups:
            continue
        if mnemonic == "lea" and len(operands) >= 2:
            mem = getattr(operands[1], "mem", None)
            regs = mem_regs(cap_insn, mem)
            if dest_reg in regs:
                add_score(dest_reg, 30)
            elif not regs:
                add_score(dest_reg, -50)
            continue
        if mnemonic in ("add", "sub") and len(operands) >= 2 and dest_is_write:
            add_score(dest_reg, 18)
            continue
        if mnemonic in ("inc", "dec") and dest_is_write:
            add_score(dest_reg, 12)
            continue
        if mnemonic in ("mov", "movabs") and len(operands) >= 2 and getattr(operands[1], "type", None) == 2:
            add_score(dest_reg, -40)
    return scores


class _Eng:
    pass


for _name in (
    "_vip_candidate_use_scores",
    "_vip_block_use_scores",
    "_vip_reg_name_from_tup",
    "_vip_canonical_reg_name",
    "_ctf_reg_name_from_tup",
    "_ctf_canonical_reg_name",
):
    setattr(_Eng, _name, getattr(VEXMixin, _name))


class TestVipUseScores(unittest.TestCase):
    def _check(self, arch_dir, regs):
        proj = angr.Project(os.path.join(bin_location, "tests", arch_dir, "fauxware"), auto_load_libs=False)
        text = proj.loader.main_object.sections_map[".text"]
        tups = [proj.arch.registers[r] for r in regs]
        subsets = [tuple(tups)] + [tuple(c) for c in itertools.combinations(tups, 2)][:20] + [(t,) for t in tups]
        eng = _Eng()
        eng.project = proj
        checked = 0
        for addr in range(text.vaddr, text.vaddr + text.memsize, 3):
            try:
                bbl = proj.factory.block(addr)
            except Exception:  # pylint:disable=broad-except
                continue
            eng.state = types.SimpleNamespace(globals={"cur_bbl": bbl})
            for cands in subsets:
                cvips = {t: (0,) for t in cands}
                expected = _reference_use_scores(eng, cvips)
                assert eng._vip_candidate_use_scores(cvips) == expected
                # a fresh Block object of the same code hits the cache
                eng.state.globals["cur_bbl"] = proj.factory.block(addr)
                assert eng._vip_candidate_use_scores(cvips) == expected
                checked += any(expected.values())
        assert checked > 50

    def test_amd64(self):
        self._check("x86_64", ["rbx", "rcx", "rdx", "rax", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11"])

    def test_i386(self):
        self._check("i386", ["eax", "ebx", "ecx", "edx", "esp", "esi", "edi", "ebp"])


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.reaching_definitions"  # pylint:disable=redefined-builtin

from unittest import TestCase, main, mock

import angr
from angr.analyses.reaching_definitions import rd_state
from angr.knowledge_plugins.key_definitions import atoms
from angr.knowledge_plugins.key_definitions.constants import OP_AFTER

# mov rax, rbx; add rax, 4; mov [rsp+8], rax; mov ecx, [rsp+8]; lea rdx, [rcx+rax]; ret
CODE = bytes.fromhex("4889d8" "4883c004" "4889442408" "8b4c2408" "488d1401" "c3")


def _summary(rd, block):
    defs = sorted(repr(d) for d in rd.all_definitions)
    uses = sorted((repr(d), sorted(map(repr, rd.all_uses.get_uses(d)))) for d in rd.all_definitions)
    live = rd.one_result
    regs = {}
    for name in ("rax", "rcx", "rdx", "rsp"):
        off, size = block.arch.registers[name]
        mv = live.registers.load(off, size=size)
        regs[name] = sorted(repr(d) for vs in mv.values() for v in vs for d in live.extract_defs(v))
    tmps = sorted((t, sorted(map(repr, u))) for t, u in live.tmp_uses.items())
    return defs, uses, regs, tmps


class TestRDABlockFastPaths(TestCase):
    def _run(self):
        proj = angr.load_shellcode(CODE, "amd64", load_address=0x400000)
        block = proj.factory.block(0x400000, len(CODE), opt_level=1)
        _ = block.vex  # a Block with its IRSB is analysed as given
        rd = proj.analyses.ReachingDefinitions(
            block, track_tmps=True, track_consts=False, observation_points=[("node", 0x400000, OP_AFTER)]
        )
        return rd, block

    def test_ail_engine_not_built_for_vex(self):
        rd, _ = self._run()
        assert rd._engine_ail_obj is None
        assert rd._engine_vex_obj is not None

    def test_tmp_fast_path_matches_annotating_path(self):
        rd, block = self._run()
        fast = _summary(rd, block)

        class _NotTmp:  # disables the `type(atom) is Tmp` fast path
            pass

        with mock.patch.object(rd_state, "Tmp", _NotTmp):
            rd2, block2 = self._run()
        assert _summary(rd2, block2) == fast
        tmp_defs = [d for d in rd.all_definitions if isinstance(d.atom, atoms.Tmp)]
        assert len(tmp_defs) == sum(1 for s in block.vex.statements if s.tag == "Ist_WrTmp")


class TestRDAUnsupportedOperands(TestCase):
    def test_operands_of_unhandled_binop_are_used(self):
        # mov rax, [rbx+8]; xor edx, edx; div rcx; ret -- div lifts to 64HLto128, which has no RDA handler
        code = bytes.fromhex("488b4308" "31d2" "48f7f1" "c3")
        proj = angr.load_shellcode(code, "amd64", load_address=0x400000)
        block = proj.factory.block(0x400000, len(code), opt_level=1)
        _ = block.vex
        rd = proj.analyses.ReachingDefinitions(
            block, track_tmps=True, track_consts=False, observation_points=[("node", 0x400000, OP_AFTER)]
        )
        hl_args = [
            a.tmp
            for s in block.vex.statements
            if s.tag == "Ist_WrTmp" and getattr(s.data, "op", None) == "Iop_64HLto128"
            for a in s.data.args
            if a.tag == "Iex_RdTmp"
        ]
        assert hl_args
        for tmp in hl_args:
            assert rd.one_result.tmp_uses.get(tmp), f"t{tmp} has no use"


if __name__ == "__main__":
    main()

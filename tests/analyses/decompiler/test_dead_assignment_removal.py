#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use,protected-access
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import time
import unittest

import archinfo

import angr
from angr.ailment.block import Block
from angr.ailment.expression import Call, Const, VirtualVariable, VirtualVariableCategory
from angr.ailment.statement import Assignment, Return
from angr.analyses.decompiler.ail_simplifier import AILSimplifier
from angr.analyses.s_reaching_definitions.s_rda_model import SRDAModel, populate_model

BLOCK_ADDR = 0x400000
BLOCK_KEY = (BLOCK_ADDR, None)


def _vvar(varid: int) -> VirtualVariable:
    return VirtualVariable(varid, varid, 32, VirtualVariableCategory.REGISTER, oident=16)


def _find_dead_vvars(statements):
    """
    Run AILSimplifier._find_dead_vvars over a single block made of ``statements``.
    """
    blocks = {BLOCK_KEY: Block(BLOCK_ADDR, 1, statements=statements, idx=None)}
    model = SRDAModel(None, None, archinfo.ArchAMD64())
    populate_model(model, blocks, None)

    simplifier = AILSimplifier.__new__(AILSimplifier)
    simplifier._removed_vvar_ids = set()
    simplifier._propagator_dead_vvar_ids = set()
    simplifier._remove_dead_memdefs = False
    simplifier._stackarg_offset_manager = None

    to_remove, to_keep, dead_vvar_ids = simplifier._find_dead_vvars(model, blocks, set())
    return to_remove[BLOCK_KEY], to_keep[BLOCK_KEY], dead_vvar_ids


class TestDeadAssignmentRemoval(unittest.TestCase):
    def test_dead_copy_chain_is_removed_in_linear_time(self):
        # issue #6968: deadness propagates backwards along use-def edges, so the old re-scan fixed point retired only
        # one link of a copy chain per scan. 20,000 links took minutes; the worklist takes a fraction of a second.
        chain_length = 20000
        statements = [Assignment(i, _vvar(i + 1), _vvar(i), ins_addr=BLOCK_ADDR + i) for i in range(chain_length)]
        statements.append(Return(chain_length, [], ins_addr=BLOCK_ADDR + chain_length))

        start = time.time()
        to_remove, to_keep, _ = _find_dead_vvars(statements)
        elapsed = time.time() - start

        assert to_remove == set(range(chain_length))
        assert not to_keep
        assert elapsed < 5.0, f"the dead copy chain took {elapsed:.1f}s to retire"

    def test_copy_chain_with_a_live_tail_is_kept(self):
        statements = [
            Assignment(0, _vvar(1), _vvar(0), ins_addr=BLOCK_ADDR),
            Assignment(1, _vvar(2), _vvar(1), ins_addr=BLOCK_ADDR + 1),
            Return(2, [_vvar(2)], ins_addr=BLOCK_ADDR + 2),
        ]
        to_remove, to_keep, dead_vvar_ids = _find_dead_vvars(statements)
        assert not to_remove
        assert to_keep == {0, 1}
        assert not dead_vvar_ids

    def test_uses_inside_a_call_statement_still_count(self):
        # the return value of the call is unused, so the call statement is retired, but the call itself survives, which
        # means its arguments keep the definitions they read alive
        statements = [
            Assignment(0, _vvar(1), _vvar(0), ins_addr=BLOCK_ADDR),
            Assignment(
                1,
                _vvar(2),
                Call(100, Const(101, 0x400500, 64), args=[_vvar(1)], bits=32, ins_addr=BLOCK_ADDR + 1),
                ins_addr=BLOCK_ADDR + 1,
            ),
            Return(2, [], ins_addr=BLOCK_ADDR + 2),
        ]
        to_remove, to_keep, dead_vvar_ids = _find_dead_vvars(statements)
        assert to_remove == {1}
        assert to_keep == {0}
        assert dead_vvar_ids == {2}


class TestPackerFillerDecompilation(unittest.TestCase):
    def test_xchg_filler_decompiles_quickly(self):
        # issue #6968: 0x91 (xchg ecx, eax) filler decodes cleanly, so CFGFast happily builds one long chain of
        # 99-instruction blocks out of it. Every instruction turns into a pair of dead virtual variables, and retiring
        # that chain used to be quadratic: 41 blocks took ~16s and the reported binary (5,068 blocks) never finished.
        block_count = 40
        code = b"\x91" * (99 * block_count) + b"\xc3"

        start = time.time()
        proj = angr.load_shellcode(code, arch="x86", load_address=0x400000)
        # repeating_byte_run_threshold=0: CFGFast refuses to decode this filler by default (the CFG-side fix for the
        # same issue). This test targets the decompiler, so the chain has to be built anyway.
        cfg = proj.analyses.CFGFast(
            normalize=True, cross_references=False, function_starts=[0x400000], repeating_byte_run_threshold=0
        )
        dec = proj.analyses.Decompiler(proj.kb.functions[0x400000], cfg=cfg.model, preset="malware")
        elapsed = time.time() - start

        assert dec.codegen is not None and dec.codegen.text is not None
        assert elapsed < 8.0, f"decompiling {block_count} blocks of filler took {elapsed:.1f}s"


if __name__ == "__main__":
    unittest.main()

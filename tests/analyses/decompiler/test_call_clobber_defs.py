#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

import unittest

import angr
from angr.ailment.block import Block
from angr.ailment.expression import Phi
from angr.ailment.statement import Assignment
from angr.analyses.s_liveness import SLivenessAnalysis
from angr.utils.ssa import clobber_def_ids, clobber_def_vvars, get_vvar_deflocs
from angr.utils.ssa.vvar_uses_collector import VVarUsesCollector

RDI = 72
RBX = 40


def _decompile(code: bytes):
    proj = angr.load_shellcode(code, "AMD64", load_address=0x400000, start_offset=0)
    cfg = proj.analyses.CFGFast(normalize=True, function_starts=[0x400000], fail_fast=True, show_progressbar=False)
    proj.analyses.CompleteCallingConventions(recover_variables=False)
    func = cfg.functions[0x400000]
    dec = proj.analyses.Decompiler(func, cfg=cfg, fail_fast=True)
    assert dec.codegen is not None and dec.codegen.text is not None
    assert dec.clinic is not None and dec.clinic.cc_graph is not None
    return dec


def _used_and_defined(graph):
    collector = VVarUsesCollector()
    used: set[int] = set()
    for block in graph.nodes():
        for stmt in block.statements:
            collector.reset()
            collector.walk_statement(stmt)
            used |= collector.vvars
    return used, set(get_vvar_deflocs(list(graph.nodes())))


def _clobber_tagged(graph):
    return [stmt for block in graph.nodes() for stmt in block.statements if clobber_def_ids(stmt)]


def _clobber_tagged_block(block):
    return [stmt for stmt in block.statements if clobber_def_ids(stmt)]


def _reg_reads(graph, reg_offset: int) -> set[int]:
    """vvar ids of every use of a register vvar with the given offset."""
    collector = VVarUsesCollector()
    ids: set[int] = set()
    for block in graph.nodes():
        for stmt_idx, stmt in enumerate(block.statements):
            collector.reset()
            collector.walk_statement(stmt, block, stmt_idx)
            for vid, uses in collector.vvar_and_uselocs.items():
                if any(v.was_reg and v.reg_offset == reg_offset for v, _ in uses):
                    ids.add(vid)
    return ids


class TestCallClobberDefs(unittest.TestCase):
    """
    A call defines the caller-saved registers it clobbers. A later read of such a register must resolve to a vvar
    defined at the call, not to an undefined vvar that liveness would consider live from the function entry.
    """

    def test_read_after_call_is_defined_by_the_call(self):
        # _start: call helper; call helper; ret      helper: mov eax, edi; ret
        # the second call passes rdi, which the first call clobbered
        dec = _decompile(bytes.fromhex("e806000000e801000000c389f8c3"))
        graph = dec.clinic.cc_graph
        used, defined = _used_and_defined(graph)
        args = {vvar.varid for vvar, _ in dec.clinic.arg_vvars.values()}
        assert not (used - defined - args), "every used vvar must be defined or be an argument"

        tagged = _clobber_tagged(graph)
        assert len(tagged) == 1
        clobbers = clobber_def_vvars(tagged[0])
        assert [v.reg_offset for v in clobbers] == [RDI]
        assert _reg_reads(graph, RDI) - args == {clobbers[0].varid}

        liveness = SLivenessAnalysis(dec.func, func_graph=graph, entry=next(b for b in graph if b.addr == 0x400000))
        assert sum(len(v) for v in liveness.model.live_outs.values()) <= 2

        # the first call defines rdi for the second one, so it must stay a statement of its own: folding it into
        # the second call's argument list would emit the call twice
        assert dec.codegen.text.count("sub_40000b(") == 2

    def test_reads_on_two_paths_share_the_definition(self):
        # _start: call helper; test eax, eax; jz L; call helper; ret; L: call helper; ret   helper: mov eax, edi; ret
        # both branches pass rdi to helper after the first call clobbered it
        code = bytes.fromhex("e81000000085c07406e807000000c3e801000000c389f8c3")
        dec = _decompile(code)
        graph = dec.clinic.cc_graph
        tagged = _clobber_tagged(graph)
        assert len(tagged) == 1
        clobbers = clobber_def_vvars(tagged[0])
        assert [v.reg_offset for v in clobbers] == [RDI]
        # both branches read rdi after the same call: one shared vvar, no undefined reads
        assert _reg_reads(graph, RDI) == {clobbers[0].varid}

    def test_reads_after_two_calls_merge_through_a_phi(self):
        # _start: test edi, edi; jz L; call helper; jmp M; L: call helper; M: call helper; ret   helper: mov eax, edi; ret
        # the call at M passes rdi, clobbered by a different call on each incoming path
        code = bytes.fromhex("85ff7407e80d000000eb05e806000000e801000000c389f8c3")
        dec = _decompile(code)
        graph = dec.clinic.cc_graph
        tagged = _clobber_tagged(graph)
        assert len(tagged) == 2
        clobber_ids = {clobber_def_vvars(stmt)[0].varid for stmt in tagged}
        phis = [
            stmt
            for block in graph.nodes()
            for stmt in block.statements
            if isinstance(stmt, Assignment) and isinstance(stmt.src, Phi) and stmt.dst.was_reg
        ]
        assert len(phis) == 1
        assert {vvar.varid for _, vvar in phis[0].src.src_and_vvars if vvar is not None} == clobber_ids
        assert _reg_reads(graph, RDI) - clobber_ids == {phis[0].dst.varid}

    def test_clobbered_path_merges_with_an_assigned_path(self):
        # _start: test edi, edi; jz L; call helper; jmp M; L: mov edi, 5; M: call helper; ret   helper: mov eax, edi; ret
        # at M rdi is either the clobber definition of the call or the constant assignment: a phi of both
        code = bytes.fromhex("85ff7407e80d000000eb05bf05000000e801000000c389f8c3")
        dec = _decompile(code)
        graph = dec.clinic.cc_graph
        tagged = _clobber_tagged(graph)
        assert len(tagged) == 1
        clobber_id = clobber_def_vvars(tagged[0])[0].varid
        phis = [
            stmt
            for block in graph.nodes()
            for stmt in block.statements
            if isinstance(stmt, Assignment) and isinstance(stmt.src, Phi) and stmt.dst.was_reg
        ]
        assert len(phis) == 1
        phi_srcs = {vvar.varid for _, vvar in phis[0].src.src_and_vvars if vvar is not None}
        assert clobber_id in phi_srcs and len(phi_srcs) == 2
        used, defined = _used_and_defined(graph)
        args = {vvar.varid for vvar, _ in dec.clinic.arg_vvars.values()}
        assert not (used - defined - args)

    def test_clobber_defs_tag_survives_block_serialization(self):
        # the tag is a flat int list so that spilled and angrdb-loaded blocks keep the definitions
        dec = _decompile(bytes.fromhex("e806000000e801000000c389f8c3"))
        block = next(b for b in dec.clinic.cc_graph.nodes() if _clobber_tagged_block(b))
        stmt = _clobber_tagged_block(block)[0]
        back = Block.from_bytes(block.to_bytes())
        back_stmt = _clobber_tagged_block(back)[0]
        assert list(back_stmt.tags["clobber_defs"]) == list(stmt.tags["clobber_defs"])
        assert [v.varid for v in clobber_def_vvars(back_stmt)] == clobber_def_ids(stmt)

    def test_call_in_a_block_that_receives_phis(self):
        # _start: test edi, edi; jz L; mov esi, 1; jmp M; L: mov esi, 2; M: call helper; call helper; ret
        # helper: mov eax, edi; ret
        # M gets a phi for rsi prepended, which shifts the statement indices of the call that defines rdi
        code = bytes.fromhex("85ff7407be01000000eb05be02000000e806000000e801000000c389f8c3")
        dec = _decompile(code)
        graph = dec.clinic.cc_graph
        used, defined = _used_and_defined(graph)
        args = {vvar.varid for vvar, _ in dec.clinic.arg_vvars.values()}
        assert not (used - defined - args)
        tagged = _clobber_tagged(graph)
        assert len(tagged) == 1 and [v.reg_offset for v in clobber_def_vvars(tagged[0])] == [RDI]
        assert _reg_reads(graph, RDI) - args == {clobber_def_vvars(tagged[0])[0].varid}

    def test_callee_saved_register_is_not_defined_by_the_call(self):
        # _start: call helper; mov edi, ebx; call helper; ret      helper: mov eax, edi; ret
        # rbx is callee-saved: its value after the first call is still the value at the entry
        dec = _decompile(bytes.fromhex("e80800000089dfe801000000c389f8c3"))
        graph = dec.clinic.cc_graph
        for stmt in _clobber_tagged(graph):
            assert RBX not in [v.reg_offset for v in clobber_def_vvars(stmt)]
        rbx_reads = _reg_reads(graph, RBX)
        assert len(rbx_reads) == 1
        assert not (rbx_reads & set(get_vvar_deflocs(list(graph.nodes())))), "rbx is live-in from the entry"


if __name__ == "__main__":
    unittest.main()

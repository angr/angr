#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses"  # pylint:disable=redefined-builtin

import unittest
import unittest.mock

import archinfo
import networkx
import pyvex

from angr.analyses.vm_deobfuscation.vex_tmps import (
    DanglingTmpError,
    drop_abihints_reading_undefined_tmps,
    find_dangling_tmp_reads,
    join_irsbs,
    vex_stmt_tmp_defs,
)
from angr.analyses.vm_deobfuscation.vm_deobfuscation import VMDeobfuscation, _check_vex_tmps
from angr.engines.vex.data_sensitive import DataSensitiveRdTmp

ARCH = archinfo.ArchAMD64()


def _lift(hexcode, addr):
    return pyvex.lift(bytes.fromhex(hexcode), addr, ARCH, opt_level=1)


def _first():
    # mov rax, rcx; add rax, rbx: defines t0, t1, t3
    return _lift("4889c84801d8", 0x1000)


def _second():
    # mov rax, [rcx+8]; div rcx: defines t3 (collides) and t4..t12
    return _lift("488b410848f7f1", 0x2000)


def _drop(irsb, pred):
    stmts = [s for s in irsb.statements if not pred(s)]
    return pyvex.IRSB.empty_block(
        ARCH, irsb.addr, statements=stmts, tyenv=irsb.tyenv, nxt=irsb.next, jumpkind=irsb.jumpkind
    )


def _reads(stmt):
    return [e.tmp for e in stmt.expressions if isinstance(e, pyvex.expr.RdTmp)]


def _defines(tmp):
    return lambda s: tmp in vex_stmt_tmp_defs(s)


class TestJoinIRSBs(unittest.TestCase):
    def test_renumbering_is_exact(self):
        a, b = _first(), _second()
        b_before = [s.pp_str(arch=ARCH, tyenv=None) for s in b.statements]
        stmts, types, nxt = join_irsbs(a, b, (a.addr, None), (b.addr, None))

        n = len(a.statements)
        assert all(x is y for x, y in zip(stmts[:n], a.statements))
        # t3 is the only collision; it gets max(defs) + 1
        mapping = {t: t for s in b.statements for t in vex_stmt_tmp_defs(s)}
        mapping[3] = 13
        for old, new in zip(b.statements, stmts[n:]):
            assert type(old) is type(new)
            assert [mapping[t] for t in _reads(old)] == _reads(new)
            assert [mapping[t] for t in vex_stmt_tmp_defs(old)] == vex_stmt_tmp_defs(new)
            if isinstance(old, pyvex.stmt.WrTmp):
                assert types[new.tmp] == b.tyenv.lookup(old.tmp)
        assert types[3] == a.tyenv.lookup(3) == "Ity_I64" and types[13] == "Ity_I128"
        assert nxt is b.next
        # the joined block reads only what it defines; the input block is untouched
        joined = pyvex.IRSB.empty_block(
            ARCH,
            a.addr,
            statements=stmts,
            tyenv=pyvex.block.IRTypeEnv(ARCH, types=types),
            nxt=nxt,
            jumpkind=b.jumpkind,
        )
        assert find_dangling_tmp_reads(joined) == []
        assert [s.pp_str(arch=ARCH, tyenv=None) for s in b.statements] == b_before

    def test_next_keeps_block_id(self):
        a = _first()
        b = _lift("ffe0", 0x2000)  # jmp rax: next reads the tmp of GET(rax)
        assert b.next.tmp in {t for s in a.statements for t in vex_stmt_tmp_defs(s)}
        bid = object()
        b.next = DataSensitiveRdTmp(b.next.tmp, bid)
        stmts, _, nxt = join_irsbs(a, b, (a.addr, None), (b.addr, None))
        new_def = vex_stmt_tmp_defs(stmts[-1])[0]
        assert new_def != b.next.tmp
        assert isinstance(nxt, DataSensitiveRdTmp) and nxt.tmp == new_def and nxt.block_id is bid

    def test_dangling_read_is_not_bound_to_first_block(self):
        # the second block reads t3 without defining it; t3 of the first block is an unrelated value
        a, b = _first(), _drop(_second(), _defines(3))
        with self.assertRaises(DanglingTmpError) as cm:
            join_irsbs(a, b, (a.addr, "A"), (b.addr, "B"))
        e = cm.exception
        assert (e.addr, e.block_id, e.tmp) == (0x2000, "B", 3)
        assert 3 in _reads(b.statements[e.stmt_idx])

    def test_dangling_read_in_first_block(self):
        a, b = _drop(_second(), _defines(6)), _first()
        with self.assertRaises(DanglingTmpError) as cm:
            join_irsbs(a, b, (a.addr, None), (b.addr, None))
        assert (cm.exception.addr, cm.exception.tmp) == (0x2000, 6)

    def test_find_dangling(self):
        b = _drop(_second(), _defines(6))
        assert find_dangling_tmp_reads(_second()) == []
        assert [t for _, t in find_dangling_tmp_reads(b)] == [6]

    def test_drop_abihint_with_removed_operand(self):
        b = _lift("ffd0", 0x1000)  # call rax: ends with AbiHint(t7, 128, t4)
        assert drop_abihints_reading_undefined_tmps(b.statements) is b.statements
        hint_base = b.statements[-1].base.tmp
        stmts = [s for s in b.statements if not _defines(hint_base)(s)]
        kept = drop_abihints_reading_undefined_tmps(stmts)
        assert kept == stmts[:-1] and not any(isinstance(s, pyvex.stmt.AbiHint) for s in kept)


class _Node:
    is_simprocedure = False

    def __init__(self, irsb):
        self.addr = irsb.addr
        self.block_id = None
        self.irsb = irsb


class _CFG:
    def __init__(self, graph):
        self.graph = graph


def _analysis():
    self = VMDeobfuscation.__new__(VMDeobfuscation)
    self.project = None
    self._pass_changed = False
    self._change_counter = 0
    self._coarse_epoch = 0
    self._pass_seen = {}
    self._node_dirty = {}
    self._node_seen = {}
    return self


class TestJoinBasicBlocks(unittest.TestCase):
    def _cfg(self, a, b):
        g = networkx.DiGraph()
        n1, n2 = _Node(a), _Node(b)
        g.add_edge(n1, n2, jumpkind="Ijk_Boring")
        return _CFG(g), n1

    def test_join(self):
        cfg, n1 = self._cfg(_first(), _second())
        _analysis().join_basic_blocks(cfg, None, start_addr=0x1000, start_state=None)
        assert list(cfg.graph.nodes()) == [n1]
        assert find_dangling_tmp_reads(n1.irsb) == []
        assert n1.irsb.jumpkind == "Ijk_Boring" and n1.irsb.size == 13

    def test_join_raises_on_dangling_read(self):
        cfg, _ = self._cfg(_first(), _drop(_second(), _defines(3)))
        with self.assertRaises(DanglingTmpError):
            _analysis().join_basic_blocks(cfg, None, start_addr=0x1000, start_state=None)

    def test_pass_check(self):
        cfg, _ = self._cfg(_first(), _drop(_second(), _defines(3)))
        with unittest.mock.patch.dict("os.environ", {"VM_TMP_CHECK": "1"}):
            with self.assertRaises(DanglingTmpError) as cm:
                _check_vex_tmps(cfg, "some_pass")
        assert "some_pass" in str(cm.exception) and cm.exception.tmp == 3
        with unittest.mock.patch.dict("os.environ", {"VM_TMP_CHECK": ""}):
            _check_vex_tmps(cfg, "some_pass")


if __name__ == "__main__":
    unittest.main()

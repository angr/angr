# pylint: disable=missing-class-docstring,no-self-use,protected-access
"""Smoke tests for the Phase D Statement spike marker module.

Locks in the variant coverage and the metaclass dispatch contract for
all 10 Statement variants. The spike module
``angr.ailment._phase_d_stmt_spike`` is staged for migration into the
canonical ``angr.ailment.statement`` module; until then, these tests
guard the spike from regressions.
"""

from __future__ import annotations

import unittest

import angr.ailment._phase_d_spike as eu  # expression markers
import angr.ailment._phase_d_stmt_spike as su  # statement markers
from angr.rustylib.ailment import Statement, StatementKind  # pylint:disable=import-error,no-name-in-module


class TestPhaseDStmtSpike(unittest.TestCase):
    """Per-variant construction + ``isinstance`` dispatch + roundtrip."""

    def _roundtrip(self, stmt) -> Statement:
        return Statement.from_bytes(stmt.to_bytes())

    def _atoms(self):
        return (
            eu.Register(0, 16, 64),
            eu.Const(1, 42, 64),
            eu.Const(2, 0x1000, 64),
        )

    def test_assignment(self):
        dst, src, _ = self._atoms()
        a = su.Assignment(0, dst, src, ins_addr=0x100)
        assert a.kind == StatementKind.Assignment
        assert isinstance(a, su.Assignment)
        assert not isinstance(a, su.WeakAssignment)
        assert dict(a.tags)["ins_addr"] == 0x100

    def test_weak_assignment(self):
        dst, src, _ = self._atoms()
        wa = su.WeakAssignment(0, dst, src)
        assert isinstance(wa, su.WeakAssignment)
        assert not isinstance(wa, su.Assignment)

    def test_label(self):
        lbl = su.Label(0, "L1")
        assert isinstance(lbl, su.Label) and lbl.name == "L1"

    def test_store(self):
        _, _, addr = self._atoms()
        data = eu.Const(1, 7, 32)
        st = su.Store(2, addr, data, 4, "Iend_LE")
        assert isinstance(st, su.Store)
        assert st.size == 4 and st.endness == "Iend_LE"
        assert st.guard is None and "offset" not in dict(st.tags)

    def test_jump(self):
        _, _, addr = self._atoms()
        j = su.Jump(0, addr)
        assert isinstance(j, su.Jump)
        assert j.target_idx is None

    def test_conditional_jump(self):
        dst, src, addr = self._atoms()
        cond = eu.BinaryOp(0, "CmpEQ", (dst, src))
        cj = su.ConditionalJump(1, cond, addr, addr)
        assert isinstance(cj, su.ConditionalJump)
        assert cj.true_target_idx is None and cj.false_target_idx is None

    def test_side_effect_statement(self):
        dst, _, _ = self._atoms()
        ses = su.SideEffectStatement(0, dst)
        assert isinstance(ses, su.SideEffectStatement)
        assert ses.ret_expr is None and ses.fp_ret_expr is None

    def test_return(self):
        dst, src, _ = self._atoms()
        r = su.Return(0, [dst, src])
        assert isinstance(r, su.Return) and len(r.ret_exprs) == 2

    def test_cas(self):
        _, _, addr = self._atoms()
        c1 = eu.Const(1, 1, 32)
        c2 = eu.Const(2, 0, 32)
        cas = su.CAS(0, addr, c1, None, c1, None, c2, None, "Iend_LE")
        assert isinstance(cas, su.CAS) and cas.endness == "Iend_LE"

    def test_dirty_statement(self):
        dst, _, _ = self._atoms()
        dirty_e = eu.DirtyExpression(0, "helper_x86_cf", [dst], bits=32)
        ds = su.DirtyStatement(1, dirty_e)
        assert isinstance(ds, su.DirtyStatement)
        assert ds.dirty is not None

    def test_metaclass_does_not_match_unrelated(self):
        lbl = su.Label(0, "L")
        for marker in [
            su.Assignment,
            su.WeakAssignment,
            su.Store,
            su.Jump,
            su.ConditionalJump,
            su.SideEffectStatement,
            su.Return,
            su.CAS,
            su.DirtyStatement,
        ]:
            assert not isinstance(lbl, marker), f"Label matched {marker.__name__}"

    def test_hash_and_eq(self):
        dst, src, _ = self._atoms()
        a1 = su.Assignment(0, dst, src)
        a2 = su.Assignment(0, dst, src)
        assert a1 == a2
        assert hash(a1) == hash(a2)

    def test_roundtrip_all_variants(self):
        """Every Statement variant must round-trip through to_bytes/from_bytes."""
        dst, src, addr = self._atoms()
        data = eu.Const(1, 7, 32)
        cond = eu.BinaryOp(0, "CmpEQ", (dst, src))
        dirty_e = eu.DirtyExpression(0, "h", [dst], bits=32)

        stmts = [
            su.Assignment(0, dst, src),
            su.WeakAssignment(0, dst, src),
            su.Label(0, "L"),
            su.Store(0, addr, data, 4, "Iend_LE"),
            su.Jump(0, addr),
            su.ConditionalJump(0, cond, addr, addr),
            su.SideEffectStatement(0, dst),
            su.Return(0, [dst]),
            su.CAS(0, addr, dst, None, dst, None, dst, None, "Iend_LE"),
            su.DirtyStatement(0, dirty_e),
        ]
        for s in stmts:
            r = self._roundtrip(s)
            assert r.kind == s.kind, f"kind mismatch: {s.kind} != {r.kind}"


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.cfg"  # pylint:disable=redefined-builtin

import unittest

from angr.analyses.cfg.vm_exploration_memo import ExplorationMemo, live_symbolizations
from angr.engines.successors import SimSuccessors


class _State:
    """Stands in for a SimState: copy() yields a distinct object that remembers its origin."""

    def __init__(self, name, origin=None, globals_=None):
        self.name = name
        self.origin = origin
        self.mutations = []
        # SimState.copy shares the values of globals, as SimStateGlobals.copy does
        self.globals = dict(globals_) if globals_ is not None else {"names": [], "n": 0}

    def copy(self):
        return _State(self.name, origin=self, globals_=self.globals)


def _successors(addr, states, unsat=(), unconstrained=()):
    succ = SimSuccessors(addr, _State("initial"))
    succ.sort = "IRSB"
    succ.processed = True
    succ.artifacts = {"irsb": object(), "irsb_direct_next": True}
    for s in states:
        succ.all_successors.append(s)
        if s in unsat:
            succ.unsat_successors.append(s)
        elif s in unconstrained:
            succ.unconstrained_successors.append(s)
        else:
            succ.successors.append(s)
            succ.flat_successors.append(s)
    return succ


class TestLiveSymbolizations(unittest.TestCase):
    def test_duplicates_are_dead(self):
        once = [("reg", 0, 16, 8), ("mem", 0x1000, 4, 4)]
        twice = once + once
        assert live_symbolizations(once) == live_symbolizations(twice) == tuple(once)

    def test_new_location_is_live(self):
        base = [("reg", 0, 16, 8)]
        assert live_symbolizations(base + [("reg", 0, 24, 8)]) != live_symbolizations(base)

    def test_partial_overlap_keeps_both_and_order(self):
        a = [("reg", 0, 16, 8), ("reg", 0, 17, 7)]
        b = [("reg", 0, 17, 7), ("reg", 0, 16, 8)]
        assert live_symbolizations(a) == tuple(a)
        assert live_symbolizations(b) == (("reg", 0, 16, 8),)  # the first store is fully overwritten
        assert live_symbolizations(a) != live_symbolizations(b)

    def test_kinds_are_separate_address_spaces(self):
        entries = [("reg", 0, 16, 8), ("mem", 0, 16, 8)]
        assert live_symbolizations(entries) == tuple(entries)


class TestExplorationMemo(unittest.TestCase):
    def _lookup(self, memo, job_id, parent_hit, symb=(), block_id="b", hook=None):
        return memo.lookup(job_id, parent_hit, block_id, block_id, "Ijk_Boring", hook, symb)

    def test_job_ids_are_stable_across_passes(self):
        memo = ExplorationMemo()
        memo.begin_pass()
        a = memo.child_id(ExplorationMemo.ROOT, 0)
        b = memo.child_id(a, 1)
        memo.end_pass()
        memo.begin_pass()
        assert memo.child_id(ExplorationMemo.ROOT, 0) == a
        assert memo.child_id(a, 1) == b
        assert memo.child_id(a, 0) not in (a, b)

    def test_unchanged_job_replays_pristine_copies(self):
        memo = ExplorationMemo()
        memo.begin_pass()
        s0, s1 = _State("s0"), _State("s1")
        succ = _successors(0x1000, [s0, s1], unsat=[s1])
        assert self._lookup(memo, 1, True) is None  # first pass: nothing recorded
        memo.record(1, "b", "b", "Ijk_Boring", None, (), succ, None, None)
        s0.mutations.append("post-call mutation")  # what _pre_job_handling does to the originals
        memo.end_pass()

        memo.begin_pass()
        rec = self._lookup(memo, 1, True)
        assert rec is not None
        replayed, exc, swapped = memo.replay(rec)
        assert exc is None and swapped is None
        assert [s.name for s in replayed.all_successors] == ["s0", "s1"]
        assert replayed.unsat_successors[0].name == "s1" and replayed.successors == replayed.flat_successors
        assert replayed.successors[0].name == "s0"
        # fresh copies of the pristine record, never the mutated originals
        assert replayed.all_successors[0] is not s0 and replayed.all_successors[0].origin is not s0
        assert replayed.all_successors[0].mutations == []
        assert replayed.artifacts == succ.artifacts and replayed.artifacts is not succ.artifacts
        again, _, _ = memo.replay(rec)
        assert again.all_successors[0] is not replayed.all_successors[0]
        memo.end_pass()
        assert memo.pass_unchanged()
        assert memo.stats.hits == 1 and memo.stats.misses == 0

    def test_globals_containers_are_isolated_from_later_appends(self):
        memo = ExplorationMemo()
        memo.begin_pass()
        s0 = _State("s0")
        self._lookup(memo, 1, True)
        memo.record(1, "b", "b", "Ijk_Boring", None, (), _successors(0, [s0]), None, None)
        s0.globals["names"].append("mba_state_split_cond_1")  # _pre_job_handling after the record
        s0.globals["n"] = 1
        memo.end_pass()
        memo.begin_pass()
        rec = self._lookup(memo, 1, True)
        replayed, _, _ = memo.replay(rec)
        r0 = replayed.all_successors[0]
        assert r0.globals["names"] == [] and r0.globals["n"] == 0
        r0.globals["names"].append("mba_state_split_cond_2")  # the replayed pass appends again
        again, _, _ = memo.replay(rec)
        assert again.all_successors[0].globals["names"] == []
        # children of a replayed state share its containers, as in the original
        child = r0.copy()
        assert child.globals["names"] is r0.globals["names"]

    def test_changed_symbolization_invalidates_only_that_job_and_its_descendants(self):
        memo = ExplorationMemo()
        chain = [ExplorationMemo.ROOT]
        memo.begin_pass()
        for i in range(4):
            chain.append(memo.child_id(chain[-1], 0))
        for job_id in chain:
            self._lookup(memo, job_id, True)
            memo.record(job_id, "b", "b", "Ijk_Boring", None, (), _successors(0, [_State("s")]), None, None)
        memo.end_pass()

        memo.begin_pass()
        hits = []
        parent_hit = True
        for n, job_id in enumerate(chain):
            symb = (("reg", 0, 16, 8),) if n == 2 else ()
            rec = self._lookup(memo, job_id, parent_hit, symb=symb)
            if rec is None:
                memo.record(job_id, "b", "b", "Ijk_Boring", None, symb, _successors(0, [_State("s")]), None, None)
            hits.append(rec is not None)
            parent_hit = rec is not None  # what _handle_successor propagates to the child
        assert hits == [True, True, False, False, False]
        stats = memo.end_pass()
        assert (stats.hits, stats.symb_misses, stats.parent_misses, stats.new) == (2, 1, 2, 0)
        assert not memo.pass_unchanged()

        # third pass with the same stores: everything replays again
        memo.begin_pass()
        parent_hit = True
        for n, job_id in enumerate(chain):
            symb = (("reg", 0, 16, 8),) if n == 2 else ()
            parent_hit = self._lookup(memo, job_id, parent_hit, symb=symb) is not None
            assert parent_hit
        assert memo.end_pass().misses == 0

    def test_block_id_and_hook_are_part_of_the_key(self):
        memo = ExplorationMemo()
        memo.begin_pass()
        self._lookup(memo, 1, True)
        memo.record(1, "b", "b", "Ijk_Boring", None, (), _successors(0, [_State("s")]), None, None)
        memo.end_pass()
        memo.begin_pass()
        assert self._lookup(memo, 1, True, block_id="other") is None
        assert self._lookup(memo, 1, True, hook=object()) is None
        assert self._lookup(memo, 1, True) is not None

    def test_stale_records_are_dropped_and_swapped_state_copied(self):
        memo = ExplorationMemo()
        memo.begin_pass()
        for job_id in (1, 2):
            self._lookup(memo, job_id, True)
            memo.record(job_id, "b", "b", "Ijk_Boring", None, (), _successors(0, [_State("s")]), None,
                        _State("symbolic") if job_id == 1 else None)
        assert memo.end_pass().records == 2
        memo.begin_pass()
        rec = self._lookup(memo, 1, True)
        _, _, swapped = memo.replay(rec)
        assert swapped.name == "symbolic" and swapped is not rec.swapped_state
        assert memo.end_pass().records == 1
        memo.begin_pass()
        assert self._lookup(memo, 2, True) is None and memo.stats.new == 1


    def test_failed_step_is_replayed_as_none(self):
        memo = ExplorationMemo()
        memo.begin_pass()
        self._lookup(memo, 1, True)
        memo.record(1, "b", "b", "Ijk_Boring", None, (), None, (ValueError, ValueError("x"), object()), None)
        memo.end_pass()
        memo.begin_pass()
        rec = self._lookup(memo, 1, True)
        succ, exc, swapped = memo.replay(rec)
        assert succ is None and swapped is None
        assert exc[0] is ValueError and exc[2] is None


    def test_memory_floor_stops_recording_without_keeping_stale_records(self):
        memo = ExplorationMemo(min_available=0)
        memo.begin_pass()
        for job_id in (1, 2):
            self._lookup(memo, job_id, True)
            memo.record(job_id, "b", "b", "Ijk_Boring", None, (), _successors(0, [_State("s")]), None, None)
        memo.end_pass()
        memo.min_available = 1 << 62  # nothing is ever available
        memo.begin_pass()
        assert self._lookup(memo, 1, True) is not None  # replaying needs no recording
        assert self._lookup(memo, 2, True, symb=(("reg", 0, 16, 8),)) is None
        assert memo.record(2, "b", "b", "Ijk_Boring", None, (("reg", 0, 16, 8),),
                           _successors(0, [_State("s")]), None, None) is None
        stats = memo.end_pass()
        # below the floor at the end of the pass: everything is released before the symbolizer runs
        assert stats.unrecorded == 1 and stats.records == 0
        memo.min_available = 0
        memo.begin_pass()
        assert self._lookup(memo, 1, True) is None and self._lookup(memo, 2, True) is None
        assert memo.stats.new == 2


    def test_record_cap_is_deterministic_and_lets_existing_records_be_replaced(self):
        memo = ExplorationMemo(min_available=0, max_records=2)
        memo.begin_pass()
        stored = []
        for job_id in (1, 2, 3):
            self._lookup(memo, job_id, True)
            stored.append(memo.record(job_id, "b", "b", "Ijk_Boring", None, (), _successors(0, [_State("s")]),
                                      None, None) is not None)
        assert stored == [True, True, False]
        stats = memo.end_pass()
        assert (stats.capped, stats.records, stats.unrecorded) == (1, 2, 0)
        memo.begin_pass()
        # a re-executed job overwrites its own slot even at the cap
        assert self._lookup(memo, 2, True, symb=(("reg", 0, 16, 8),)) is None
        assert memo.record(2, "b", "b", "Ijk_Boring", None, (("reg", 0, 16, 8),),
                           _successors(0, [_State("s")]), None, None) is not None
        assert self._lookup(memo, 3, True) is None and memo.stats.new == 1


if __name__ == "__main__":
    unittest.main()

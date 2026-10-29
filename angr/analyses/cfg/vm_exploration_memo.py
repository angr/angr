"""
Cross-pass memo for the symbolizer loop's VM graph re-exploration.

Every `symbolify_exprs` pass re-runs CFGVMDeobfuscation from the same start state; only the
symbolization stores applied at merge points change between passes. A job's `_get_simsuccessors`
result depends on its input state (a copy of one successor state of its parent) and on those
stores, so it is unchanged whenever the parent's result was replayed from the memo and the live
stores are equal. This module keys jobs by their path from the start job and keeps the recorded
SimSuccessors (with pristine copies of the states) across passes.
"""
from __future__ import annotations

import copy
import logging
from collections import defaultdict

from angr.engines.successors import SimSuccessors

l = logging.getLogger(name=__name__)

_LISTS = ("successors", "flat_successors", "unsat_successors", "unconstrained_successors", "all_successors")


def live_symbolizations(entries):
    """
    Canonical form of a list of symbolization stores [(kind, page, offset, size), ...] in application
    order: the stores that still own at least one byte after all later stores of the same kind.
    Each store writes a fresh unconstrained symbol, so stores fully overwritten later change nothing.
    """
    covered = defaultdict(set)
    live = []
    for kind, page, offset, size in reversed(entries):
        base = page + offset
        span = set(range(base, base + size))
        if span - covered[kind]:
            live.append((kind, page, offset, size))
        covered[kind] |= span
    live.reverse()
    return tuple(live)


def _isolated_copy(state):
    """
    state.copy() with its own copies of the containers held in state.globals. SimState.copy shares
    them, which is how _pre_job_handling's in-place appends (existing_mba_split_constraints) would
    otherwise leak into a record or out of a replay. One level is enough: nothing appends to a
    nested container during the exploration.
    """
    c = state.copy()
    for k, v in list(c.globals.items()):
        if isinstance(v, (list, dict, set)):
            c.globals[k] = copy.copy(v)
    return c


class MemoRecord:
    __slots__ = (
        "entry_block_id", "block_id", "jumpkind", "hook", "symbolizations", "states", "membership",
        "addr", "sort", "engine", "processed", "description", "artifacts", "exception_info", "swapped_state",
        "irsb_clone",
    )

    def __init__(self):
        self.entry_block_id = None
        self.block_id = None
        self.jumpkind = None
        self.hook = None
        self.symbolizations = ()
        self.states = []
        self.membership = []
        self.addr = None
        self.sort = None
        self.engine = None
        self.processed = False
        self.description = None
        self.artifacts = {}
        self.exception_info = None
        self.swapped_state = None
        # the IRSB clone owned by the CFGENode created from this record; the exploration model that
        # held it is discarded after the pass, so the next pass's node can take it over uncloned
        self.irsb_clone = None


class PassStats:
    __slots__ = ("jobs", "hits", "symb_misses", "parent_misses", "new", "records")

    def __init__(self):
        self.jobs = 0
        self.hits = 0
        self.symb_misses = 0  # record exists, parent replayed, but the inputs changed
        self.parent_misses = 0  # record exists but the parent was re-executed
        self.new = 0  # no record for this job id
        self.records = 0

    @property
    def misses(self):
        return self.symb_misses + self.parent_misses + self.new

    def __repr__(self):
        return (f"jobs={self.jobs} hits={self.hits} re-executed: changed-inputs={self.symb_misses} "
                f"parent-changed={self.parent_misses} new={self.new}; records kept={self.records}")


class ExplorationMemo:
    ROOT = 0

    def __init__(self):
        self._key_ids = {}
        self._records = {}
        self._visited = set()
        self.stats = None
        self.history = []

    # job identity

    def child_id(self, parent_id, index):
        key = (parent_id, index)
        job_id = self._key_ids.get(key)
        if job_id is None:
            job_id = len(self._key_ids) + 1
            self._key_ids[key] = job_id
        return job_id

    # pass bookkeeping

    def begin_pass(self):
        self._visited = set()
        self.stats = PassStats()

    def end_pass(self):
        stale = [k for k in self._records if k not in self._visited]
        for k in stale:
            del self._records[k]
        self.stats.records = len(self._records)
        self.history.append(self.stats)
        l.info("exploration memo: %r", self.stats)
        return self.stats

    def pass_unchanged(self):
        """Exact certificate: every job of the last pass replayed its recorded result."""
        return self.stats is not None and self.stats.misses == 0

    def clear(self):
        self._records.clear()
        self._key_ids.clear()
        self._visited.clear()

    # lookup / record

    def lookup(self, job_id, parent_hit, entry_block_id, block_id, jumpkind, hook, symbolizations):
        """
        Return the record to replay, or None (and account for the miss).
        """
        self.stats.jobs += 1
        self._visited.add(job_id)
        record = self._records.get(job_id)
        if record is None:
            self.stats.new += 1
            return None
        if not parent_hit:
            self.stats.parent_misses += 1
            return None
        if (record.entry_block_id != entry_block_id or record.block_id != block_id or record.jumpkind != jumpkind
                or record.hook is not hook or record.symbolizations != symbolizations):
            self.stats.symb_misses += 1
            return None
        self.stats.hits += 1
        return record

    def record(self, job_id, entry_block_id, block_id, jumpkind, hook, symbolizations, sim_successors,
               exception_info, swapped_state):
        rec = MemoRecord()
        rec.entry_block_id = entry_block_id
        rec.block_id = block_id
        rec.jumpkind = jumpkind
        rec.hook = hook
        rec.symbolizations = symbolizations
        rec.addr = sim_successors.addr
        rec.sort = sim_successors.sort
        rec.engine = sim_successors.engine
        rec.processed = sim_successors.processed
        rec.description = sim_successors.description
        rec.artifacts = dict(sim_successors.artifacts)
        rec.exception_info = exception_info
        rec.swapped_state = _isolated_copy(swapped_state) if swapped_state is not None else None
        # one pristine copy per distinct state; remember which lists it sits in (and where)
        index_of = {}
        for name in _LISTS:
            for pos, state in enumerate(getattr(sim_successors, name)):
                idx = index_of.get(id(state))
                if idx is None:
                    idx = len(rec.states)
                    index_of[id(state)] = idx
                    rec.states.append(_isolated_copy(state))
                rec.membership.append((name, pos, idx))
        self._records[job_id] = rec
        return rec

    @staticmethod
    def replay(record):
        """Rebuild the SimSuccessors from the record with fresh copies of the pristine states."""
        succ = SimSuccessors(record.addr, None)
        succ.sort = record.sort
        succ.engine = record.engine
        succ.processed = record.processed
        succ.description = record.description
        succ.artifacts = dict(record.artifacts)
        copies = [_isolated_copy(s) for s in record.states]
        lists = {name: [] for name in _LISTS}
        for name, pos, idx in record.membership:
            assert len(lists[name]) == pos
            lists[name].append(copies[idx])
        for name in _LISTS:
            setattr(succ, name, lists[name])
        swapped = _isolated_copy(record.swapped_state) if record.swapped_state is not None else None
        return succ, record.exception_info, swapped

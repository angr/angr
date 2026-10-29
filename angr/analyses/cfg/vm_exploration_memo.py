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


def _meminfo_bytes(field):
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith(field + ":"):
                    return int(line.split()[1]) * 1024
    except OSError:
        pass
    return None


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
        "irsb_clone", "no_successors",
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
        # _get_simsuccessors returned None (AngrError while stepping)
        self.no_successors = False


class PassStats:
    __slots__ = ("jobs", "hits", "symb_misses", "parent_misses", "new", "records", "unrecorded")

    def __init__(self):
        self.jobs = 0
        self.hits = 0
        self.symb_misses = 0  # record exists, parent replayed, but the inputs changed
        self.parent_misses = 0  # record exists but the parent was re-executed
        self.new = 0  # no record for this job id
        self.records = 0
        self.unrecorded = 0  # executed but not recorded: memory floor reached

    @property
    def misses(self):
        return self.symb_misses + self.parent_misses + self.new

    def __repr__(self):
        return (f"jobs={self.jobs} hits={self.hits} re-executed: changed-inputs={self.symb_misses} "
                f"parent-changed={self.parent_misses} new={self.new}; records kept={self.records}"
                f" not recorded (memory floor)={self.unrecorded}")


class ExplorationMemo:
    """
    Records hold one pass worth of successor states. Recording stops for the rest of a pass once
    MemAvailable drops below `min_available` bytes; a missing record only turns a later replay
    into an execution, so the floor trades speed for memory and never changes results.
    """

    ROOT = 0
    _CHECK_EVERY = 256

    def __init__(self, min_available=None):
        self._key_ids = {}
        self._records = {}
        self._visited = set()
        self.stats = None
        self.history = []
        if min_available is None:
            total = _meminfo_bytes("MemTotal")
            min_available = int(total * 0.35) if total is not None else 0
        self.min_available = min_available
        self._saturated = False
        self._since_check = 0

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
        self._saturated = False
        self._since_check = self._CHECK_EVERY

    def end_pass(self):
        stale = [k for k in self._records if k not in self._visited]
        for k in stale:
            del self._records[k]
        available = _meminfo_bytes("MemAvailable") if self.min_available else None
        if self._saturated or (available is not None and available < self.min_available):
            # the symbolizer pass that follows needs the headroom more than the next exploration needs replays
            l.warning("exploration memo: below the memory floor at the end of the pass, dropping %d records",
                      len(self._records))
            self._records.clear()
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

    def _memory_low(self):
        if self._saturated or not self.min_available:
            return self._saturated
        self._since_check += 1
        if self._since_check >= self._CHECK_EVERY:
            self._since_check = 0
            available = _meminfo_bytes("MemAvailable")
            if available is not None and available < self.min_available:
                l.warning("exploration memo: MemAvailable %.1f GB below %.1f GB, not recording the rest of this pass",
                          available / 2**30, self.min_available / 2**30)
                self._saturated = True
        return self._saturated

    def record(self, job_id, entry_block_id, block_id, jumpkind, hook, symbolizations, sim_successors,
               exception_info, swapped_state):
        """Store this job's result; returns the record, or None when the memory floor stopped recording."""
        if self._memory_low():
            # a stale record from an earlier pass must not survive: the job re-executed
            self._records.pop(job_id, None)
            self.stats.unrecorded += 1
            return None
        rec = MemoRecord()
        rec.entry_block_id = entry_block_id
        rec.block_id = block_id
        rec.jumpkind = jumpkind
        rec.hook = hook
        rec.symbolizations = symbolizations
        # only its None-ness is read; drop the traceback, whose frames would pin the step's states
        rec.exception_info = None if exception_info is None else (exception_info[0], exception_info[1], None)
        rec.swapped_state = _isolated_copy(swapped_state) if swapped_state is not None else None
        self._records[job_id] = rec
        if sim_successors is None:
            rec.no_successors = True
            return rec
        rec.addr = sim_successors.addr
        rec.sort = sim_successors.sort
        rec.engine = sim_successors.engine
        rec.processed = sim_successors.processed
        rec.description = sim_successors.description
        rec.artifacts = dict(sim_successors.artifacts)
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
        return rec

    @staticmethod
    def replay(record):
        """Rebuild the SimSuccessors from the record with fresh copies of the pristine states."""
        swapped = _isolated_copy(record.swapped_state) if record.swapped_state is not None else None
        if record.no_successors:
            return None, record.exception_info, swapped
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
        return succ, record.exception_info, swapped

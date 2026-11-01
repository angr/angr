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
import os
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


def _self_rss_bytes():
    try:
        with open("/proc/self/statm") as f:
            return int(f.read().split()[1]) * os.sysconf("SC_PAGE_SIZE")
    except (OSError, ValueError, IndexError):
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
    __slots__ = ("jobs", "hits", "symb_misses", "parent_misses", "new", "records", "unrecorded", "capped", "final",
                 "over_budget")

    def __init__(self):
        self.jobs = 0
        self.hits = 0
        self.symb_misses = 0  # record exists, parent replayed, but the inputs changed
        self.parent_misses = 0  # record exists but the parent was re-executed
        self.new = 0  # no record for this job id
        self.records = 0
        self.unrecorded = 0  # executed but not recorded: box memory floor reached
        self.over_budget = 0  # executed but not recorded: this process's memory budget reached
        self.capped = 0  # executed but not recorded: record cap reached
        self.final = 0  # executed but not recorded: no later pass replays

    @property
    def misses(self):
        return self.symb_misses + self.parent_misses + self.new

    def __repr__(self):
        return (f"jobs={self.jobs} hits={self.hits} re-executed: changed-inputs={self.symb_misses} "
                f"parent-changed={self.parent_misses} new={self.new}; records kept={self.records}"
                f" not recorded: cap={self.capped} budget={self.over_budget} memory floor={self.unrecorded}"
                f" final pass={self.final}")


class ExplorationMemo:
    """
    Records hold one pass worth of successor states. Three limits bound them; a missing record only
    turns a later replay into an execution, so none changes results:
    - max_records: at most this many records exist at any time;
    - max_growth: recording stops for the rest of a pass once this process's RSS has grown by this much
      since the memo was created. It depends only on this process, so other tenants of the machine do
      not change what is recorded;
    - min_available: emergency floor for the whole machine. Recording stops once MemAvailable drops below
      it, and a pass that ends below it releases all records.
    """

    ROOT = 0
    _CHECK_EVERY = 256
    # ~250 KB/record on libpng-themida, ~410 KB/record on libpng-vmp
    DEFAULT_MAX_RECORDS = 30000
    DEFAULT_MAX_GROWTH = 16 << 30
    # emergency floor: min(32 GiB, a quarter of MemTotal)
    FLOOR_CAP = 32 << 30
    FLOOR_FRACTION = 0.25

    def __init__(self, min_available=None, max_records=None, max_growth=None):
        self._key_ids = {}
        self._records = {}
        self._visited = set()
        self.stats = None
        self.history = []
        if min_available is None:
            min_available = self.default_floor(_meminfo_bytes("MemTotal"))
        self.min_available = min_available
        self.max_records = self.DEFAULT_MAX_RECORDS if max_records is None else max_records
        self.max_growth = self.DEFAULT_MAX_GROWTH if max_growth is None else max_growth
        self._read_rss = _self_rss_bytes
        self._read_available = lambda: _meminfo_bytes("MemAvailable")
        self._rss_base = self._read_rss() if self.max_growth else None
        # None, "budget" (own growth) or "floor" (machine); set once recording stopped in this pass
        self._saturated = None
        self._since_check = 0
        # False during a pass no later pass replays: its records would only cost copies and memory
        self.recording = True

    # policy

    @classmethod
    def default_floor(cls, mem_total):
        return min(cls.FLOOR_CAP, int(mem_total * cls.FLOOR_FRACTION)) if mem_total else 0

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
        self._saturated = None
        self._since_check = self._CHECK_EVERY

    def end_pass(self):
        stale = [k for k in self._records if k not in self._visited]
        for k in stale:
            del self._records[k]
        available = self._read_available() if self.min_available else None
        if self._saturated == "floor" or (available is not None and available < self.min_available):
            # the symbolizer pass that follows needs the headroom more than the next exploration needs replays
            l.warning("exploration memo: below the memory floor at the end of the pass, dropping %d records",
                      len(self._records))
            self._records.clear()
        self.stats.records = len(self._records)
        self.history.append(self.stats)
        l.info("exploration memo: %r", self.stats)
        return self.stats

    def irsb_clone_ids(self):
        """ids of the IRSBs records hand to the next pass's nodes; nothing else may own or edit them."""
        return {id(r.irsb_clone) for r in self._records.values() if r.irsb_clone is not None}

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
        if self._saturated is not None:
            return True
        if not (self.min_available or self.max_growth):
            return False
        self._since_check += 1
        if self._since_check < self._CHECK_EVERY:
            return False
        self._since_check = 0
        if self.max_growth and self._rss_base is not None:
            rss = self._read_rss()
            if rss is not None and rss - self._rss_base >= self.max_growth:
                l.warning("exploration memo: RSS grew by %.1f GB (budget %.1f GB), not recording the rest of this pass",
                          (rss - self._rss_base) / 2**30, self.max_growth / 2**30)
                self._saturated = "budget"
                return True
        if self.min_available:
            available = self._read_available()
            if available is not None and available < self.min_available:
                l.warning("exploration memo: MemAvailable %.1f GB below %.1f GB, not recording the rest of this pass",
                          available / 2**30, self.min_available / 2**30)
                self._saturated = "floor"
                return True
        return False

    def record(self, job_id, entry_block_id, block_id, jumpkind, hook, symbolizations, sim_successors,
               exception_info, swapped_state):
        """Store this job's result; returns the record, or None when a limit or the pass policy stopped recording."""
        if not self.recording:
            self._records.pop(job_id, None)
            self.stats.final += 1
            return None
        if job_id not in self._records and len(self._records) >= self.max_records:
            self.stats.capped += 1
            return None
        if self._memory_low():
            # a stale record from an earlier pass must not survive: the job re-executed
            self._records.pop(job_id, None)
            if self._saturated == "budget":
                self.stats.over_budget += 1
            else:
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

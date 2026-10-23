#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use,protected-access
from __future__ import annotations

__package__ = __package__ or "tests.analyses.cfg"  # pylint:disable=redefined-builtin

import os
import random
import unittest
from collections import defaultdict
from unittest import mock

import angr
from angr.analyses.cfg.cfg_fast import (
    CFGFast,
    FunctionReturn,
    PyCFGJob,
    PyFunctionReturns,
    PyPendingJobs,
)
from angr.errors import SimEngineError, SimMemoryError
from angr.rustylib.cfg_graph import CfgGraph
from angr.rustylib.cfg_jobs import (
    CFGJob,
    CFGJobType,
    FunctionCallEdge,
    FunctionFakeRetEdge,
    FunctionReturnEdge,
    FunctionTransitionEdge,
    ScanState,
    function_return_hash_of,
    set_iteration_order,
)
from angr.rustylib.recovery_functions import RecoveryFunctions
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


class _Func:
    def __init__(self, returning):
        self.returning = returning


class _Functions:
    def __init__(self, returning: dict):
        self.returning = returning

    def function(self, addr):
        if addr not in self.returning:
            return None
        return _Func(self.returning[addr])


class _KB:
    def __init__(self, returning: dict):
        self.functions = _Functions(returning)


class _Accounting:
    """CFGBase's per-function job accounting."""

    def __init__(self):
        self.jobs = defaultdict(set)
        self.without_jobs = {}

    def register(self, func_addr, job):
        jobs = self.jobs[func_addr]
        if not jobs:
            self.without_jobs.pop(func_addr, None)
        jobs.add(job)

    def deregister(self, func_addr, job):
        jobs = self.jobs[func_addr]
        jobs.discard(job)
        if not jobs:
            self.without_jobs[func_addr] = None

    def cleanup(self, func_addrs):
        for f in func_addrs:
            self.jobs.pop(f, None)
            self.without_jobs.pop(f, None)


def _bound_scan(kb) -> ScanState:
    """A ScanState whose function lookups go through `kb.functions` (not a RecoveryFunctionManager)."""
    scan = ScanState()
    scan.bind(CfgGraph(20), RecoveryFunctions(), object(), kb, {}, (SimMemoryError, SimEngineError))
    return scan


def _random_job(rng: random.Random, cls, small: bool = True):
    pick = (lambda: rng.randrange(8)) if small else (lambda: rng.randrange(1 << 40))
    return cls(
        pick() * 16 + 0x400000,
        rng.choice([0x1000, 0x2000, 0x3000]),
        rng.choice(["Ijk_Boring", "Ijk_FakeRet", "Ijk_Call"]),
        last_addr=rng.choice([None, 0x400000]),
        returning_source=rng.choice([None, 0x1000, 0x2000, 0x3000, 0x4000]),
        syscall=rng.random() < 0.1,
        job_type=rng.choice([CFGJobType.NORMAL, CFGJobType.DATAREF_HINTS]),
        gp=rng.choice([None, 0x8000]),
    )


class TestCPythonSetOrder(unittest.TestCase):
    def test_int_sets(self):
        rng = random.Random(1)
        for n in [0, 1, 3, 5, 6, 7, 20, 100, 1000, 30000, 60000]:
            values = list(dict.fromkeys(rng.choice([rng.randrange(64), rng.randrange(1 << 64)]) for _ in range(n)))
            values.append(None)
            s = set()
            for v in values:
                s.add(v)
            hashes = [hash(v) for v in values]
            assert [values[i] for i in set_iteration_order(hashes)] == list(s)

    def test_hash_collisions(self):
        # ints that differ by multiples of 2**61 - 1 share a hash
        m = (1 << 61) - 1
        values = [5, 5 + m, 5 + 2 * m, 13, 13 + m, 21]
        s = set()
        for v in values:
            s.add(v)
        assert [values[i] for i in set_iteration_order([hash(v) for v in values])] == list(s)

    def test_function_return_sets(self):
        rng = random.Random(2)
        for n in [1, 4, 50, 2000]:
            frs = list(
                dict.fromkeys(
                    FunctionReturn(
                        rng.choice([None, rng.randrange(1 << 48)]),
                        rng.randrange(1 << 48),
                        rng.randrange(1 << 48),
                        rng.choice([None, rng.randrange(1 << 48)]),
                    )
                    for _ in range(n)
                )
            )
            s = set()
            for fr in frs:
                s.add(fr)
            hashes = []
            for fr in frs:
                h = function_return_hash_of((fr.callee_func_addr, fr.caller_func_addr, fr.call_site_addr, fr.return_to))
                assert h == hash(fr)
                hashes.append(h)
            assert [frs[i] for i in set_iteration_order(hashes)] == list(s)

    def test_function_returns_take(self):
        rng = random.Random(3)
        scan = ScanState()
        py = PyFunctionReturns()
        for _ in range(3000):
            args = (rng.choice([None, 1, 2, 3]), rng.randrange(4), rng.randrange(1 << 20), rng.randrange(1 << 20))
            scan.add_function_return(*args)
            py.add_function_return(*args)
        for callee in [None, 1, 2, 3, 4]:
            assert scan.has_function_returns(callee) == py.has_function_returns(callee)
            assert scan.take_function_returns(callee) == py.take_function_returns(callee)
            assert not scan.has_function_returns(callee)


class TestScanContainers(unittest.TestCase):
    def test_job_accounting(self):
        rng = random.Random(4)
        scan = ScanState()
        ref = _Accounting()
        tokens = [object() for _ in range(5)]
        for _ in range(20000):
            op = rng.random()
            func_addr = rng.randrange(40)
            if op < 0.45:
                job = rng.choice(tokens) if rng.random() < 0.1 else _random_job(rng, CFGJob)
                scan.register_job(func_addr, job)
                ref.register(func_addr, job)
            elif op < 0.95:
                job = rng.choice(tokens) if rng.random() < 0.1 else _random_job(rng, CFGJob)
                scan.deregister_job(func_addr, job)
                ref.deregister(func_addr, job)
            else:
                finished = list(ref.without_jobs)
                assert scan.finished_functions() == finished
                scan.cleanup_analysis_jobs(finished[: len(finished) // 2])
                ref.cleanup(finished[: len(finished) // 2])
        assert scan.finished_functions() == list(ref.without_jobs)

    def test_pending_jobs(self):
        rng = random.Random(5)
        returning = {0x1000: True, 0x2000: False, 0x3000: None}
        kb = _KB(returning)
        scan = _bound_scan(kb)
        pending = scan.pending
        ref_acc = _Accounting()
        ref = PyPendingJobs(kb, ref_acc.deregister)

        def popped(j):
            return None if j is None else (j.addr, j.func_addr, j.returning_source, j.job_type)

        for _ in range(4000):
            op = rng.random()
            if op < 0.5:
                job_rust = _random_job(rng, CFGJob)
                job_py = PyCFGJob(
                    job_rust.addr,
                    job_rust.func_addr,
                    job_rust.jumpkind,
                    last_addr=job_rust.last_addr,
                    returning_source=job_rust.returning_source,
                    syscall=job_rust.syscall,
                    job_type=job_rust.job_type,
                    gp=job_rust.gp,
                )
                pending.add_job(job_rust)
                ref.add_job(job_py)
                scan.register_job(job_rust.func_addr, job_rust)
                ref_acc.register(job_py.func_addr, job_py)
            elif op < 0.7:
                returning_flag = rng.random() < 0.7
                assert popped(pending.pop_job(returning=returning_flag)) == popped(
                    ref.pop_job(returning=returning_flag)
                )
            elif op < 0.8:
                f = rng.choice([None, 0x1000, 0x2000, 0x3000, 0x4000])
                pending.add_returning_function(f)
                ref.add_returning_function(f)
            elif op < 0.9:
                f = rng.choice([None, 0x1000, 0x2000, 0x3000, 0x4000, 0x5000])
                pending.add_nonreturning_function(f)
                ref.add_nonreturning_function(f)
            else:
                assert pending.updated_functions() == list(ref._updated_functions)
                pending.cleanup()
                ref.cleanup()
                assert scan.finished_functions() == list(ref_acc.without_jobs)
            assert len(pending) == len(ref)
            assert bool(pending) == bool(ref)
        assert [popped(j) for j in pending.all_jobs()] == [popped(j) for j in ref.all_jobs()]

    def test_queue(self):
        rng = random.Random(6)
        scan = ScanState()
        jobs = [_random_job(rng, CFGJob, small=False) for _ in range(100)]
        for j in jobs:
            scan.push(j)
        assert scan.queue_len() == 100
        assert scan.peek_at(3) == jobs[3]
        assert scan.has_job_addr(jobs[10].addr)
        scan.remove_jobs_by_mask([i % 3 == 0 for i in range(100)])
        kept = [j for i, j in enumerate(jobs) if i % 3 != 0]
        assert scan.queued_jobs() == kept
        assert not scan.has_job_addr(jobs[0].addr)
        front = scan.peek()
        scan.pop_front(front.addr)
        assert front == kept[0]
        assert scan.queue_len() == len(kept) - 1
        with self.assertRaises(IndexError):
            scan.peek_at(1000)

    def test_job_type_enum(self):
        assert CFGJobType.DATAREF_HINTS == CFGJobType.DATAREF_HINTS
        assert CFGJobType.NORMAL != CFGJobType.COMPLETE_SCANNING
        assert CFGJobType.NORMAL in (CFGJobType.FUNCTION_PROLOGUE, CFGJobType.NORMAL)
        assert CFGJobType.EH_FRAME_HINTS.name == "EH_FRAME_HINTS"
        assert CFGJobType.EH_FRAME_HINTS.value == 5
        assert len({CFGJobType.NORMAL, CFGJobType.NORMAL, CFGJobType.IFUNC_HINTS}) == 2


def _scan_time_functions(cfg) -> list:
    """Every scan-time function with its transition graph edges, in graph order."""
    out = []
    for func in cfg.kb.functions.values():
        edges = [
            (type(s).__name__, s.addr, s.size, type(d).__name__, d.addr, d.size, sorted(data.items(), key=str))
            for s, d, data in func.transition_graph.edges(data=True)
        ]
        out.append((func.addr, func.name, func.returning, func.is_plt, sorted(func.block_addrs_set), edges))
    return out


def _digest(cfg) -> tuple:
    nodes = [(n.addr, n.size, n.function_address, tuple(n.instruction_addrs)) for n in cfg.model.graph]
    edges = [
        (s.addr, d.addr, data["jumpkind"], data.get("ins_addr"), str(data.get("stmt_idx")))
        for s, d, data in cfg.model.graph.edges(data=True)
    ]
    funcs = sorted(
        (f.addr, f.name, f.returning, sorted(f.block_addrs_set), sorted(map(str, f.graph.edges())))
        for f in cfg.kb.functions.values()
    )
    xrefs = sorted(
        (x.ins_addr, x.block_addr, str(x.stmt_idx), x.dst) for xs in cfg.kb.xrefs.xrefs_by_ins_addr.values() for x in xs
    )
    return nodes, edges, funcs, xrefs


class TestCFGFastScanState(unittest.TestCase):
    def _run(self, binary: str, rust: bool):
        snapshots = []
        make_functions = CFGFast.make_functions

        def recording_make_functions(cfg):
            assert type(cfg._pending_jobs).__name__ == ("PendingJobs" if rust else "PyPendingJobs")
            snapshots.append(_scan_time_functions(cfg))
            return make_functions(cfg)

        proj = angr.Project(os.path.join(test_location, binary), auto_load_libs=False)
        with (
            mock.patch.object(CFGFast, "_rust_scan_state", rust),
            mock.patch.object(CFGFast, "make_functions", recording_make_functions),
        ):
            cfg = proj.analyses.CFGFast(normalize=True, show_progressbar=False, data_references=True)
        assert cfg._scan is None
        return _digest(cfg), snapshots

    def _check(self, binary: str):
        digest_rust, scan_rust = self._run(binary, True)
        digest_py, scan_py = self._run(binary, False)
        assert scan_rust == scan_py
        assert digest_rust == digest_py

    def test_x86_64(self):
        self._check("x86_64/fauxware")

    def test_armel(self):
        self._check("armel/fauxware")

    def test_mips(self):
        self._check("mips/fauxware")

    def test_job_views(self):
        proj = angr.Project(os.path.join(test_location, "x86_64/fauxware"), auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=False, show_progressbar=False)
        graph = cfg.model.graph
        main = cfg.kb.functions["main"]
        node = cfg.model.get_any_node(main.addr)
        other = cfg.model.get_any_node(main.addr + node.size)
        assert node is not None and other is not None

        edges = [
            FunctionTransitionEdge(node, other.addr, main.addr, to_outside=False, stmt_idx=-2, ins_addr=node.addr),
            FunctionCallEdge(node, 0x1234, other.addr, main.addr, syscall=False, stmt_idx=3, ins_addr=node.addr),
            FunctionFakeRetEdge(node, other.addr, main.addr, confirmed=True),
            FunctionReturnEdge(0x1234, other.addr, main.addr),
        ]
        job = CFGJob(
            other.addr,
            main.addr,
            "Ijk_FakeRet",
            last_addr=node.addr,
            src_node=node,
            src_ins_addr=node.addr,
            src_stmt_idx=-2,
            returning_source=0x1234,
            func_edges=edges,
        )
        assert job.src_node is node
        assert job.jumpkind == "Ijk_FakeRet"
        assert job._func_edges == edges
        assert job == CFGJob(
            other.addr,
            main.addr,
            "Ijk_FakeRet",
            last_addr=node.addr,
            src_node=node,
            src_ins_addr=node.addr,
            src_stmt_idx=-2,
            returning_source=0x1234,
        )
        assert hash(job) == hash(
            CFGJob(
                other.addr,
                main.addr,
                "Ijk_FakeRet",
                last_addr=node.addr,
                src_node=node,
                src_ins_addr=node.addr,
                src_stmt_idx=-2,
                returning_source=0x1234,
            )
        )
        assert job != CFGJob(other.addr, main.addr, "Ijk_FakeRet")

        # a stored job resolves its nodes against the graph when it comes back out
        scan = ScanState(resolver=lambda idx: graph._keys.node_of_id(idx, cfg.model))
        scan.push(job)
        out = scan.peek()
        assert out == job
        assert out.src_node is node
        out_edges = out._func_edges
        assert [type(e) for e in out_edges] == [type(e) for e in edges]
        assert out_edges[0].src_node is node
        assert (out_edges[1].dst_addr, out_edges[1].ret_addr, out_edges[1].stmt_idx) == (0x1234, other.addr, 3)
        assert out_edges[2].confirmed is True
        assert (out_edges[3].ret_from_addr, out_edges[3].ret_to_addr) == (0x1234, other.addr)
        assert CFGFast._capture_resume_job(out) == CFGFast._capture_resume_job(job)

        # removing the source node orphans it: stored jobs keep the detached node object
        assert scan.remove_jobs_by_src_addr(node.addr + 1) == 0
        scan.orphan_node(graph._id_of_node(node), node)
        cfg.model.remove_node(node.addr, node)
        assert node not in graph
        out = scan.peek()
        assert out.src_node is node
        assert out._func_edges[0].src_node is node
        assert scan.remove_jobs_by_src_addr(node.addr) == 1
        assert scan.queue_len() == 0


if __name__ == "__main__":
    unittest.main()

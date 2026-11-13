from __future__ import annotations

import contextlib
import hashlib
import logging
import signal
import threading
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any

import networkx

from angr.analyses.analysis import AnalysesHub, Analysis
from angr.analyses.cfg import CFGFast
from angr.enums import Flavors
from angr.knowledge_plugins.cfg import CFGModel
from angr.knowledge_plugins.functions.function import Function

from .decompiler import Decompiler

if TYPE_CHECKING:
    from .decompilation_cache import DecompilationCache
    from .presets import DecompilationPreset

_l = logging.getLogger(name=__name__)


class SecondPassOrder(Enum):
    """
    The order of the second decompilation pass of :class:`BinaryDecompiler`.

    ROOT_TO_LEAF: walk the call tree from its roots down to its leaves, so that what a caller learned about the
                  arguments it passes and the globals it touches reaches every callee before the callee is decompiled
                  again.
    LEAF_TO_ROOT: repeat the first pass's order (callees before callers).
    NONE:         decompile every function only once.
    """

    ROOT_TO_LEAF = "root_to_leaf"
    LEAF_TO_ROOT = "leaf_to_root"
    NONE = "none"


class DecompilationStatus(Enum):
    """
    The outcome of decompiling one function in one pass.
    """

    OK = "ok"  # the decompiler produced code
    NO_CODE = "no_code"  # the decompiler returned without code (it recorded the reason in its errors)
    FAILED = "failed"  # the decompiler raised
    TIMEOUT = "timeout"  # the decompiler ran past the per-function time budget
    NOT_RUN = "not_run"  # the function was not decompiled in this pass


@dataclass
class FunctionDecompilationRecord:
    """
    What :class:`BinaryDecompiler` did for one function, across both passes.
    """

    addr: int
    name: str
    first_status: DecompilationStatus = DecompilationStatus.NOT_RUN
    second_status: DecompilationStatus = DecompilationStatus.NOT_RUN
    first_time: float = 0.0
    second_time: float = 0.0
    errors: list[str] = field(default_factory=list)
    # the text of the final decompilation (the second pass's if it produced code, the first pass's otherwise)
    text: str | None = None
    # the digest of the first pass's text, kept to tell whether the second pass changed the output
    first_digest: str | None = None
    changed_in_second_pass: bool = False

    @property
    def has_code(self) -> bool:
        """
        Whether any pass produced code for this function.
        """
        return DecompilationStatus.OK in (self.first_status, self.second_status)


class _DecompilationTimeout(BaseException):
    """
    Raised inside a decompilation that ran past its time budget. It derives from BaseException so that the broad
    exception handlers inside the decompiler do not swallow it.
    """


def _digest(text: str | None) -> str | None:
    return None if text is None else hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()


class BinaryDecompiler(Analysis):
    """
    Decompile every function of the binary so that type information flows across the whole call tree.

    The decompiler infers types per function, but what one function knows is often only part of the story: a callee
    sees the fields of a struct that it touches, its caller sees the fields that it touches, and every function that
    accesses a global sees one slice of that global. The decompiler records what each function learned in the
    knowledge base and uses it when it decompiles the next function. This analysis orders the decompilation so that
    this happens everywhere:

    1. Collapse every recursion cycle of the call graph into one node and sort the resulting DAG topologically. The
       functions that nothing calls are the roots of the call tree, and the functions that call nothing are its
       leaves.
    2. First pass, leaves to root: every callee is decompiled before its callers, so when a caller is decompiled the
       layouts each callee recovered for its arguments are available, and the caller unions them into one type for
       the value it passes and pushes that union back into the callees' prototypes.
    3. Second pass, root to leaves: every caller is decompiled again before its callees, so the unions assembled at
       the callers (and the layouts of globals assembled across all functions) reach every callee before it is
       decompiled again and rendered.

    The final decompilation of each function is in ``kb.decompilations`` as usual; :attr:`records` keeps a summary
    per function (status and time of each pass, errors, final text, and whether the second pass changed the output).
    """

    def __init__(
        self,
        cfg: CFGFast | CFGModel | None = None,
        functions: Iterable[int | str | Function] | None = None,
        second_pass: SecondPassOrder | str = SecondPassOrder.ROOT_TO_LEAF,
        flavor: str = Flavors.DEFAULT_FLAVOR,
        preset: str | DecompilationPreset | None = None,
        timeout: float | None = None,
        complete_calling_conventions: bool = True,
        keep_text: bool = True,
        function_callback: Callable[[int, FunctionDecompilationRecord, Decompiler | None], None] | None = None,
        decompiler_kwargs: dict[str, Any] | None = None,
    ):
        """
        :param cfg:             The CFG to decompile with. Defaults to the most accurate CFG in the knowledge base, and
                                CFGFast is run if the knowledge base has none.
        :param functions:       Only decompile these functions (addresses, names, or Function objects). The call tree
                                is then the call graph restricted to them. Defaults to every function of the main
                                object that has code (no PLT stubs, SimProcedures, syscalls, or alignment padding).
        :param second_pass:     The order of the second pass. See :class:`SecondPassOrder`.
        :param flavor:          The decompilation flavor.
        :param preset:          The decompilation preset, passed to every Decompiler run.
        :param timeout:         A time budget in seconds for each Decompiler run, or None for no budget. It is only
                                enforced on the main thread of platforms that have SIGALRM, and a run that is cut off
                                may leave partial state in the knowledge base for that function.
        :param complete_calling_conventions:    Run CompleteCallingConventions first, so that every function has a
                                                prototype before the first pass (it skips functions that already
                                                have one).
        :param keep_text:       Keep each function's final decompiled text in its record.
        :param function_callback:   Called after every Decompiler run with the function's address, its record, and
                                    the Decompiler (None if the run raised).
        :param decompiler_kwargs:   Additional keyword arguments for every Decompiler run.
        """
        self._flavor = flavor
        self._preset = preset
        self._timeout = timeout
        self._keep_text = keep_text
        self._function_callback = function_callback
        self._decompiler_kwargs = dict(decompiler_kwargs) if decompiler_kwargs else {}
        for reserved in ("func", "cfg", "flavor", "preset", "regen_clinic"):
            if reserved in self._decompiler_kwargs:
                raise TypeError(f"BinaryDecompiler sets the Decompiler argument {reserved!r} itself.")
        self.second_pass = SecondPassOrder(second_pass)

        self._cfg: CFGModel = self._get_cfg(cfg)
        if complete_calling_conventions:
            self.project.analyses.CompleteCallingConventions.prep(kb=self.kb, fail_fast=self._fail_fast)(
                cfg=self._cfg, flavor=flavor
            )

        self.records: dict[int, FunctionDecompilationRecord] = {}
        self.call_tree: networkx.DiGraph = networkx.DiGraph()
        self.first_pass_order: list[int] = []
        self.second_pass_order: list[int] = []
        self._warned_timeout = False

        self._analyze(functions)

    #
    # Public methods
    #

    @property
    def roots(self) -> list[int]:
        """
        The functions at the roots of the call tree: those that no other decompiled function calls (a recursion
        cycle nothing else calls counts as one root, represented by every function in it).
        """
        return sorted(n for n in self.call_tree if not any(p not in self._scc_of(n) for p in self.call_tree.pred[n]))

    @property
    def leaves(self) -> list[int]:
        """
        The functions at the leaves of the call tree: those that call no other decompiled function outside their own
        recursion cycle.
        """
        return sorted(n for n in self.call_tree if not any(s not in self._scc_of(n) for s in self.call_tree.succ[n]))

    @property
    def changed_in_second_pass(self) -> list[int]:
        """
        The functions whose output the second pass changed.
        """
        return sorted(addr for addr, rec in self.records.items() if rec.changed_in_second_pass)

    @property
    def failed(self) -> list[int]:
        """
        The functions that have no decompilation at the end (the decompiler raised, timed out, or produced no code
        in every pass it ran).
        """
        return sorted(addr for addr, rec in self.records.items() if not rec.has_code)

    def decompilation(self, func: int | str | Function) -> DecompilationCache | None:
        """
        The final decompilation of a function, as cached in the knowledge base.
        """
        addr = self._resolve_function(func).addr
        return self.kb.decompilations.get((addr, self._flavor), None)

    #
    # Analysis
    #

    def _get_cfg(self, cfg: CFGFast | CFGModel | None) -> CFGModel:
        if isinstance(cfg, CFGFast):
            return cfg.model
        if cfg is not None:
            return cfg
        model = self.kb.cfgs.get_most_accurate()
        if model is not None:
            return model
        _l.info("No CFG in the knowledge base; running CFGFast.")
        return self.project.analyses.CFGFast.prep(kb=self.kb, fail_fast=self._fail_fast)(
            normalize=True, data_references=True
        ).model

    def _resolve_function(self, func: int | str | Function) -> Function:
        if isinstance(func, Function):
            return func
        resolved = (
            self.kb.functions.function(addr=func) if isinstance(func, int) else self.kb.functions.function(name=func)
        )
        if resolved is None:
            raise KeyError(f"No function {func!r} in the knowledge base.")
        return resolved

    def _is_decompilable(self, func: Function) -> bool:
        return (
            not func.is_plt
            and not func.is_simprocedure
            and not func.is_syscall
            and not func.is_alignment
            and self.project.loader.main_object.contains_addr(func.addr)
            and bool(func.block_addrs_set)
        )

    def _select_functions(self, functions: Iterable[int | str | Function] | None) -> list[int]:
        if functions is None:
            return sorted(addr for addr, func in self.kb.functions.items() if self._is_decompilable(func))
        selected = set()
        for f in functions:
            func = self._resolve_function(f)
            if func.is_plt or func.is_simprocedure or func.is_syscall:
                _l.warning("Skipping %r: it has no code to decompile.", func)
                continue
            selected.add(func.addr)
        return sorted(selected)

    def _build_call_tree(self, func_addrs: list[int]) -> None:
        wanted = set(func_addrs)
        tree = networkx.DiGraph()
        tree.add_nodes_from(func_addrs)
        for src, dst in self.kb.functions.callgraph.edges():
            if src in wanted and dst in wanted and src != dst:
                tree.add_edge(src, dst)
        self.call_tree = tree

        # collapse recursion cycles and sort callees before callers, breaking ties by the lowest address in a cycle
        # so that the order does not depend on how the call graph happened to be built
        condensed = networkx.condensation(tree)
        members = {n: self._cycle_order(tree, condensed.nodes[n]["members"]) for n in condensed}
        self._scc = {addr: frozenset(ms) for n, ms in members.items() for addr in ms}
        callees_first = networkx.lexicographical_topological_sort(
            condensed.reverse(copy=False), key=lambda n: min(members[n])
        )

        # inside a cycle, members are listed callers-first from where the rest of the program enters it; pass 1 walks
        # them backwards, so the second (root-to-leaf) pass reaches the entry before the members it calls
        self.first_pass_order = [addr for n in callees_first for addr in reversed(members[n])]
        if self.second_pass is SecondPassOrder.ROOT_TO_LEAF:
            self.second_pass_order = list(reversed(self.first_pass_order))
        elif self.second_pass is SecondPassOrder.LEAF_TO_ROOT:
            self.second_pass_order = list(self.first_pass_order)
        else:
            self.second_pass_order = []

    @staticmethod
    def _cycle_order(tree: networkx.DiGraph, cycle: set[int]) -> list[int]:
        """
        The members of a recursion cycle, callers first: a depth-first walk inside the cycle that starts at the members
        called from outside it (lowest address first), so that each member comes after the member that first calls it.
        """
        if len(cycle) == 1:
            return list(cycle)
        entries = sorted(m for m in cycle if any(p not in cycle for p in tree.pred[m])) or [min(cycle)]
        order: list[int] = []
        seen: set[int] = set()
        for entry in entries:
            stack = [entry]
            while stack:
                node = stack.pop()
                if node in seen:
                    continue
                seen.add(node)
                order.append(node)
                stack.extend(sorted((s for s in tree.succ[node] if s in cycle and s not in seen), reverse=True))
        order.extend(sorted(cycle - seen))
        return order

    def _scc_of(self, addr: int) -> frozenset[int]:
        return self._scc.get(addr, frozenset((addr,)))

    def _analyze(self, functions: Iterable[int | str | Function] | None) -> None:
        func_addrs = self._select_functions(functions)
        self._build_call_tree(func_addrs)
        for addr in func_addrs:
            self.records[addr] = FunctionDecompilationRecord(addr=addr, name=self.kb.functions[addr].name)

        total = len(self.first_pass_order) + len(self.second_pass_order)
        done = 0
        for pass_idx, order in ((1, self.first_pass_order), (2, self.second_pass_order)):
            for addr in order:
                self._update_progress(
                    100.0 * done / total if total else 100.0,
                    text=f"Pass {pass_idx}/{1 if not self.second_pass_order else 2}: {self.records[addr].name}",
                )
                self._decompile(addr, pass_idx)
                done += 1
        self._finish_progress()

    def _decompile(self, addr: int, pass_idx: int) -> None:
        rec = self.records[addr]
        func = self.kb.functions[addr]
        dec: Decompiler | None = None
        t0 = time.perf_counter()
        try:
            with self._time_budget():
                dec = self.project.analyses[Decompiler].prep(kb=self.kb, fail_fast=self._fail_fast)(
                    func,
                    cfg=self._cfg,
                    flavor=self._flavor,
                    preset=self._preset,
                    # the second pass must rebuild everything from what the knowledge base learned since the first
                    regen_clinic=pass_idx > 1,
                    **self._decompiler_kwargs,
                )
            text = dec.codegen.text if dec.codegen is not None else None
            status = DecompilationStatus.OK if text is not None else DecompilationStatus.NO_CODE
            rec.errors.extend(f"pass {pass_idx}: {err.format()}" for err in dec.errors)
        except _DecompilationTimeout:
            text, status = None, DecompilationStatus.TIMEOUT
            rec.errors.append(f"pass {pass_idx}: timed out after {self._timeout} seconds")
            _l.warning("Decompiling %r timed out in pass %d.", func, pass_idx)
        except Exception as ex:  # pylint:disable=broad-exception-caught
            if self._fail_fast:
                raise
            text, status = None, DecompilationStatus.FAILED
            rec.errors.append(f"pass {pass_idx}: {type(ex).__name__}: {ex}")
            _l.warning("Decompiling %r failed in pass %d.", func, pass_idx, exc_info=True)
        elapsed = time.perf_counter() - t0

        if pass_idx == 1:
            rec.first_status, rec.first_time = status, elapsed
            rec.first_digest = _digest(text)
            if text is not None and self._keep_text:
                rec.text = text
        else:
            rec.second_status, rec.second_time = status, elapsed
            if text is not None:
                rec.changed_in_second_pass = rec.first_digest is not None and _digest(text) != rec.first_digest
                if self._keep_text:
                    rec.text = text

        if self._function_callback is not None:
            self._function_callback(addr, rec, dec)

    @contextlib.contextmanager
    def _time_budget(self):
        if not self._timeout:
            yield
            return
        if not hasattr(signal, "SIGALRM") or threading.current_thread() is not threading.main_thread():
            if not self._warned_timeout:
                _l.warning("The per-function timeout needs SIGALRM on the main thread; decompiling without it.")
                self._warned_timeout = True
            yield
            return

        started = time.perf_counter()
        old_delay, old_interval = signal.getitimer(signal.ITIMER_REAL)
        old_deadline = started + old_delay if old_delay else None
        deadline = started + self._timeout

        def arm(now):
            next_deadline = min(deadline, old_deadline) if old_deadline is not None else deadline
            signal.setitimer(signal.ITIMER_REAL, max(next_deadline - now, 1e-6))

        def dispatch(signum, frame):
            nonlocal old_deadline
            now = time.perf_counter()
            if old_deadline is not None and old_deadline <= deadline and now >= old_deadline:
                # Advance before invoking the previous handler: it may raise and unwind this context.
                if old_interval:
                    old_deadline += (int((now - old_deadline) / old_interval) + 1) * old_interval
                else:
                    old_deadline = None
                if callable(old_handler):
                    old_handler(signum, frame)
                elif old_handler == signal.SIG_DFL:
                    signal.signal(signal.SIGALRM, signal.SIG_DFL)
                    signal.raise_signal(signal.SIGALRM)
                now = time.perf_counter()
            if now >= deadline:
                raise _DecompilationTimeout
            arm(now)

        old_handler = signal.signal(signal.SIGALRM, dispatch)
        try:
            arm(started)
            yield
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, old_handler)
            if old_deadline is not None:
                signal.setitimer(signal.ITIMER_REAL, max(old_deadline - time.perf_counter(), 1e-6), old_interval)


AnalysesHub.register_default("BinaryDecompiler", BinaryDecompiler)

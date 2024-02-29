from typing import Tuple, Optional, Callable, Iterable, Dict, Set, TYPE_CHECKING
import queue
import threading
import time
import logging
from collections import defaultdict

import networkx

import claripy

from angr.utils.graph import GraphUtils
from ..utils.mp import mp_context, Initializer
from ..knowledge_plugins.cfg import CFGModel
from . import Analysis, register_analysis, VariableRecoveryFast, CallingConventionAnalysis

if TYPE_CHECKING:
    from angr.calling_conventions import SimCC
    from angr.sim_type import SimTypeFunction
    from angr.knowledge_plugins.variables.variable_manager import VariableManagerInternal
    from angr.knowledge_plugins.functions.function_manager import Function


_l = logging.getLogger(name=__name__)

_mp_context = mp_context()


class CompleteCallingConventionsAnalysis(Analysis):
    """
    Implements full-binary calling convention analysis. During the initial analysis of a binary, you may set
    `recover_variables` to True so that it will perform variable recovery on each function before performing calling
    convention analysis.
    """

    def __init__(
        self,
        recover_variables=False,
        low_priority=False,
        force=False,
        cfg: Optional[CFGModel] = None,
        analyze_callsites: bool = False,
        skip_signature_matched_functions: bool = False,
        max_function_blocks: Optional[int] = None,
        max_function_size: Optional[int] = None,
        workers: int = 0,
        cc_callback: Optional[Callable] = None,
        prioritize_func_addrs: Optional[Iterable[int]] = None,
        skip_other_funcs: bool = False,
        auto_start: bool = True,
        func_graphs: Optional[Dict[int, "networkx.DiGraph"]] = None,
    ):
        """

        :param recover_variables:   Recover variables on each function before performing calling convention analysis.
        :param low_priority:        Run in the background - periodically release GIL.
        :param force:               Perform calling convention analysis on functions even if they have calling
                                    conventions or prototypes already specified (or previously recovered).
        :param cfg:                 The control flow graph model, which will be passed to CallingConventionAnalysis.
        :param analyze_callsites:   Consider artifacts at call sites when performing calling convention analysis.
        :param skip_signature_matched_functions:    Do not perform calling convention analysis on functions that match
                                                    against existing FLIRT signatures.
        :param max_function_blocks: Do not perform calling convention analysis on functions with more than the
                                    specified number of blocks. Setting it to None disables this check.
        :param max_function_size:   Do not perform calling convention analysis on functions whose sizes are more than
                                    `max_function_size`. Setting it to None disables this check.
        :param workers:             Number of multiprocessing workers.
        """

        self._recover_variables = recover_variables
        self._low_priority = low_priority
        self._force = force
        self._cfg = cfg
        self._analyze_callsites = analyze_callsites
        self._skip_signature_matched_functions = skip_signature_matched_functions
        self._max_function_blocks = max_function_blocks
        self._max_function_size = max_function_size
        self._workers = workers
        self._cc_callback = cc_callback
        self._prioritize_func_addrs = prioritize_func_addrs
        self._skip_other_funcs = skip_other_funcs
        self._auto_start = auto_start
        self._total_funcs = None
        self._func_graphs = {} if not func_graphs else func_graphs
        self.prototype_libnames: Set[str] = set()

        self._func_addrs = []  # a list that holds addresses of all functions to be analyzed
        self._results = []
        if workers > 0:
            self._remaining_funcs = _mp_context.Value("i", 0)
            self._func_queue = _mp_context.Queue()
            self._results = _mp_context.Queue()
            self._func_queue_lock = _mp_context.Lock()
        else:
            self._remaining_funcs = None  # not needed
            self._func_queue = None  # not needed
            self._func_queue_lock = threading.Lock()

        self._analyze()
        if self._auto_start:
            self.work()

    def _analyze(self):
        """
        Infer calling conventions for all functions in the current project.
        """

        # get an ordering of functions based on the call graph
        # note that the call graph is a multi-digraph. we convert it to a digraph to speed up topological sort
        directed_callgraph = networkx.DiGraph(self.kb.functions.callgraph)
        sorted_funcs = GraphUtils.quasi_topological_sort_nodes(directed_callgraph)

        total_funcs = 0
        for func_addr in reversed(sorted_funcs):
            func = self.kb.functions.get_by_addr(func_addr)
            if (func.calling_convention is None or func.prototype is None) or self._force:
                if func.is_alignment:
                    # skip all alignments
                    continue

                if self._skip_signature_matched_functions and func.from_signature:
                    # this function matches against a known library function. skip it.
                    continue

                if self._max_function_size is not None:
                    func_size = sum(block.size for block in func.blocks)
                    if func_size > self._max_function_size:
                        _l.info(
                            "Skipping variable recovery for %r since its size (%d) is greater than the cutoff "
                            "size (%d).",
                            func,
                            func_size,
                            self._max_function_size,
                        )
                        continue

                if self._max_function_blocks is not None:
                    if len(func.block_addrs_set) > self._max_function_blocks:
                        _l.info(
                            "Skipping variable recovery for %r since its number of blocks (%d) is greater than the "
                            "cutoff number (%d).",
                            func,
                            len(func.block_addrs_set),
                            self._max_function_blocks,
                        )
                        continue

                # if it's a normal function, we attempt to perform variable recovery
                self._func_addrs.append(func_addr)
                total_funcs += 1

        self._total_funcs = total_funcs

        if self._prioritize_func_addrs:
            self.prioritize_functions(self._prioritize_func_addrs)
        self._prioritize_func_addrs = None  # no longer useful

    def _set_function_prototype(
        self, func: "Function", prototype: Optional["SimTypeFunction"], prototype_libname: Optional[str]
    ) -> None:
        if func.prototype is None or func.is_prototype_guessed or self._force:
            func.is_prototype_guessed = True
            func.prototype = prototype
            func.prototype_libname = prototype_libname

    def work(self):
        total_funcs = self._total_funcs
        if self._workers == 0:
            idx = 0
            self._update_progress(0)
            for func_addr in self._func_addrs:
                cc, proto, proto_libname, _ = self._analyze_core(func_addr)

                func = self.kb.functions.get_by_addr(func_addr)
                if cc is not None or proto is not None:
                    func.calling_convention = cc
                    self._set_function_prototype(func, proto, proto_libname)
                    if proto_libname is not None:
                        self.prototype_libnames.add(proto_libname)

                if self._cc_callback is not None:
                    self._cc_callback(func_addr)

                idx += 1

                percentage = idx / total_funcs * 100.0
                self._update_progress(percentage, text=f"{idx}/{total_funcs} - {func.demangled_name}")
                if self._low_priority:
                    self._release_gil(idx, 10, 0.000001)

        else:
            self._remaining_funcs.value = len(self._func_addrs)

            # generate a call tree (obviously, it's acyclic)
            traversed_func_addrs = set()
            depends_on = {}
            dependents = defaultdict(set)
            func_addrs_set = set(self._func_addrs)
            for func_addr in reversed(self._func_addrs):
                traversed_func_addrs.add(func_addr)
                depends_on[func_addr] = set()
                for callee in self.kb.functions.callgraph.successors(func_addr):
                    if callee not in traversed_func_addrs and callee in func_addrs_set:
                        depends_on[func_addr].add(callee)
                        dependents[callee].add(func_addr)

            # enqueue all leaf functions
            for func_addr in list(
                k for k in depends_on if not depends_on[k]
            ):  # pylint:disable=consider-using-dict-items
                self._func_queue.put((func_addr, None))
                del depends_on[func_addr]

            self._update_progress(0, text="Spawning workers...")
            cc_callback = self._cc_callback
            self._cc_callback = None

            # spawn workers to perform the analysis
            with self._func_queue_lock:
                procs = [
                    _mp_context.Process(target=self._worker_routine, args=(Initializer.get(),), daemon=True)
                    for _ in range(self._workers)
                ]
                for proc_idx, proc in enumerate(procs):
                    self._update_progress(0, text=f"Spawning worker {proc_idx}...")
                    proc.start()

            self._cc_callback = cc_callback

            # update progress
            self._update_progress(0)
            idx = 0
            while idx < total_funcs:
                func_addr, cc, proto, proto_libname, varman = self._results.get(True)
                func = self.kb.functions.get_by_addr(func_addr)
                if cc is not None or proto is not None:
                    func.calling_convention = cc
                    self._set_function_prototype(func, proto, proto_libname)
                    if proto_libname is not None:
                        self.prototype_libnames.add(proto_libname)

                if varman is not None:
                    self.kb.variables.function_managers[func_addr] = varman
                    varman.set_manager(self.kb.variables)
                func.ran_cca = True

                if self._cc_callback is not None:
                    self._cc_callback(func_addr)

                idx += 1

                percentage = idx / total_funcs * 100.0
                self._update_progress(percentage, text=f"{idx}/{total_funcs} - {func.demangled_name}")
                if self._low_priority:
                    self._release_gil(idx, 10, 0.0000001)

                # enqueue functions whose callees have been analyzed
                if func_addr in dependents:
                    for dependent in dependents[func_addr]:
                        depends_on[dependent].discard(func_addr)
                        if not depends_on[dependent]:
                            callee_prototypes = self._get_callees_cc_prototypes(dependent)
                            self._func_queue.put((dependent, callee_prototypes))
                            del depends_on[dependent]

            for proc in procs:
                proc.join()

    def _worker_routine(self, initializer: Initializer):
        initializer.initialize()
        idx = 0
        while self._remaining_funcs.value > 0:
            try:
                with self._func_queue_lock:
                    func_addr, callee_info = self._func_queue.get(True, timeout=0.01)
                    self._remaining_funcs.value -= 1
            except queue.Empty:
                time.sleep(0.3)
                continue

            if callee_info is not None:
                callee_info: Dict[int, Tuple[Optional["SimCC"], Optional["SimTypeFunction"], Optional[str]]]
                for callee, (callee_cc, callee_proto, callee_proto_libname) in callee_info.items():
                    callee_func = self.kb.functions.get_by_addr(callee)
                    callee_func.calling_convention = callee_cc
                    self._set_function_prototype(callee_func, callee_proto, callee_proto_libname)

            idx += 1
            if self._low_priority:
                if idx % 3 == 0:
                    time.sleep(0.1)

            try:
                cc, proto, proto_libname, varman = self._analyze_core(func_addr)
            except Exception:  # pylint:disable=broad-except
                _l.error("Exception occurred during _analyze_core().", exc_info=True)
                cc, proto, proto_libname, varman = None, None, None, None
            self._results.put((func_addr, cc, proto, proto_libname, varman))

    def _analyze_core(
        self, func_addr: int
    ) -> Tuple[Optional["SimCC"], Optional["SimTypeFunction"], Optional["str"], Optional["VariableManagerInternal"]]:
        func = self.kb.functions.get_by_addr(func_addr)
        if func.ran_cca:
            return (
                func.calling_convention,
                func.prototype,
                func.prototype_libname,
                self.kb.variables.get_function_manager(func_addr),
            )

        if self._recover_variables and self.function_needs_variable_recovery(func):
            # special case: we don't have a PCode-engine variable recovery analysis for PCode architectures!
            if ":" in self.project.arch.name:
                # this is a pcode architecture
                if not self._func_graphs or func.addr not in self._func_graphs:
                    return None, None, None, None

            _l.info("Performing variable recovery on %r...", func)
            try:
                _ = self.project.analyses[VariableRecoveryFast].prep(kb=self.kb)(
                    func, low_priority=self._low_priority, func_graph=self._func_graphs.get(func.addr, None)
                )
            except claripy.ClaripyError:
                _l.warning(
                    "An claripy exception occurred during variable recovery analysis on function %#x.",
                    func.addr,
                    exc_info=True,
                )
                return None, None, None, None

        # determine the calling convention of each function
        cc_analysis = self.project.analyses[CallingConventionAnalysis].prep(kb=self.kb)(
            func, cfg=self._cfg, analyze_callsites=self._analyze_callsites
        )

        if cc_analysis.cc is not None:
            _l.info("Determined calling convention and prototype for %r.", func)
            return (
                cc_analysis.cc,
                cc_analysis.prototype,
                func.prototype_libname,
                self.kb.variables.get_function_manager(func_addr),
            )
        else:
            _l.info("Cannot determine calling convention for %r.", func)
            return None, None, None, self.kb.variables.get_function_manager(func_addr)

    def prioritize_functions(self, func_addrs_to_prioritize: Iterable[int]):
        """
        Prioritize the analysis of specified functions.

        :param func_addrs_to_prioritize: A collection of function addresses to analyze first.
        """

        with self._func_queue_lock:
            func_addrs_to_prioritize = set(func_addrs_to_prioritize)
            to_prioritize = []
            remaining = []
            for addr in self._func_addrs:
                if addr in func_addrs_to_prioritize:
                    to_prioritize.append(addr)
                else:
                    if not self._skip_other_funcs:
                        remaining.append(addr)

            self._func_addrs = to_prioritize + remaining

    def _get_callees_cc_prototypes(
        self, caller_func_addr: int
    ) -> Dict[int, Tuple[Optional["SimCC"], Optional["SimTypeFunction"], Optional[str]]]:
        d = {}
        for callee in self.kb.functions.callgraph.successors(caller_func_addr):
            if callee != caller_func_addr and callee not in d:
                func = self.kb.functions.get_by_addr(callee)
                tpl = func.calling_convention, func.prototype, func.prototype_libname
                d[callee] = tpl
        return d

    #
    # Static methods
    #

    @staticmethod
    def function_needs_variable_recovery(func):
        """
        Check if running variable recovery on the function is the only way to determine the calling convention of the
        this function.

        We do not need to run variable recovery to determine the calling convention of a function if:
        - The function is a SimProcedure.
        - The function is a PLT stub.
        - The function is a library function and we already know its prototype.

        :param func:    The function object.
        :return:        True if we must run VariableRecovery before we can determine what the calling convention of this
                        function is. False otherwise.
        :rtype:         bool
        """

        if func.is_simprocedure or func.is_plt:
            return False
        # TODO: Check SimLibraries
        return True


register_analysis(CompleteCallingConventionsAnalysis, "CompleteCallingConventions")

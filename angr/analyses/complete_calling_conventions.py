from typing import Tuple, Optional, Callable, Iterable, TYPE_CHECKING
import itertools
import queue
import threading
import time
import logging

import claripy

from ..utils.mp import mp_context
from ..knowledge_plugins.cfg import CFGModel
from ..analyses.cfg import CFGUtils
from . import Analysis, register_analysis, VariableRecoveryFast, CallingConventionAnalysis

if TYPE_CHECKING:
    from angr.calling_conventions import SimCC
    from angr.sim_type import SimTypeFunction
    from angr.knowledge_plugins.variables.variable_manager import VariableManagerInternal

_l = logging.getLogger(name=__name__)

_mp_context = mp_context()


class CompleteCallingConventionsAnalysis(Analysis):
    """
    Implements full-binary calling convention analysis. During the initial analysis of a binary, you may set
    `recover_variables` to True so that it will perform variable recovery on each function before performing calling
    convention analysis.
    """

    def __init__(self, recover_variables=False, low_priority=False, force=False, cfg: Optional[CFGModel]=None,
                 analyze_callsites: bool=False, skip_signature_matched_functions: bool=False,
                 max_function_blocks: Optional[int]=None, max_function_size: Optional[int]=None, workers: int=0,
                 cc_callback: Optional[Callable]=None, prioritize_func_addrs: Optional[Iterable[int]]=None,
                 skip_other_funcs: bool=False, auto_start: bool=True):
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

        self._results = [ ]
        if workers > 0:
            self._func_queue = _mp_context.Queue()
            self._results = _mp_context.Queue()
            self._func_queue_lock = _mp_context.Lock()
        else:
            self._func_queue = queue.Queue()
            self._func_queue_lock = threading.Lock()

        self._analyze()
        if self._auto_start:
            self.work()

    def _analyze(self):
        """
        Infer calling conventions for all functions in the current project.
        """

        # get an ordering of functions based on the call graph
        sorted_funcs = CFGUtils.quasi_topological_sort_nodes(self.kb.functions.callgraph)

        total_funcs = 0
        for func_addr in reversed(sorted_funcs):
            func = self.kb.functions.get_by_addr(func_addr)
            if (func.calling_convention is None or func.prototype is None) or self._force:
                if func.alignment:
                    # skip all alignments
                    continue

                if self._skip_signature_matched_functions and func.from_signature:
                    # this function matches against a known library function. skip it.
                    continue

                if self._max_function_size is not None:
                    func_size = sum(block.size for block in func.blocks)
                    if func_size > self._max_function_size:
                        _l.info("Skipping variable recovery for %r since its size (%d) is greater than the cutoff "
                                "size (%d).", func, func_size, self._max_function_size)
                        continue

                if self._max_function_blocks is not None:
                    if len(func.block_addrs_set) > self._max_function_blocks:
                        _l.info("Skipping variable recovery for %r since its number of blocks (%d) is greater than the "
                                "cutoff number (%d).", func, len(func.block_addrs_set), self._max_function_blocks)
                        continue

                # if it's a normal function, we attempt to perform variable recovery
                self._func_queue.put(func_addr)
                total_funcs += 1

        self._total_funcs = total_funcs

        if self._prioritize_func_addrs:
            self.prioritize_functions(self._prioritize_func_addrs)
        self._prioritize_func_addrs = None  # no longer useful

    def work(self):
        total_funcs = self._total_funcs
        if self._workers == 0:
            idx = 0
            self._update_progress(0)
            while not self._func_queue.empty():
                func_addr = self._func_queue.get()
                cc, proto, _ = self._analyze_core(func_addr)

                func = self.kb.functions.get_by_addr(func_addr)
                if cc is not None or proto is not None:
                    func.calling_convention = cc
                    func.prototype = proto
                    func.is_prototype_guessed = True

                if self._cc_callback is not None:
                    self._cc_callback(func_addr)

                idx += 1

                percentage = idx / total_funcs * 100.0
                self._update_progress(percentage, text=f"{idx}/{total_funcs} - {func.demangled_name}")
                if self._low_priority:
                    self._release_gil(idx, 10, 0.000001)

        else:
            self._update_progress(0, text="Spawning workers...")
            cc_callback = self._cc_callback
            self._cc_callback = None

            # spawn workers to perform the analysis
            with self._func_queue_lock:
                procs = [_mp_context.Process(target=self._worker_routine, daemon=True) for _ in range(self._workers)]
                for proc_idx, proc in enumerate(procs):
                    self._update_progress(0, text=f"Spawning worker {proc_idx}...")
                    proc.start()

            self._cc_callback = cc_callback

            # update progress
            self._update_progress(0)
            idx = 0
            while idx < total_funcs:
                func_addr, cc, proto, varman = self._results.get(True)
                func = self.kb.functions.get_by_addr(func_addr)
                if cc is not None or proto is not None:
                    func.calling_convention = cc
                    func.prototype = proto
                    func.is_prototype_guessed = True
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

            for proc in procs:
                proc.join()

    def _worker_routine(self):
        idx = 0
        while not self._func_queue.empty():
            try:
                with self._func_queue_lock:
                    func_addr = self._func_queue.get(True, timeout=1)
            except queue.Empty:
                break

            idx += 1
            if self._low_priority:
                if idx % 3 == 0:
                    time.sleep(0.1)

            try:
                cc, proto, varman = self._analyze_core(func_addr)
            except Exception:  # pylint:disable=broad-except
                _l.error("Exception occurred during _analyze_core().", exc_info=True)
                cc, proto, varman = None, None, None
            self._results.put((func_addr, cc, proto, varman))

    def _analyze_core(self, func_addr: int) -> Tuple[Optional['SimCC'],Optional['SimTypeFunction'],
                                                     Optional['VariableManagerInternal']]:
        func = self.kb.functions.get_by_addr(func_addr)
        if func.ran_cca:
            return func.calling_convention, func.prototype, self.kb.variables.get_function_manager(func_addr)

        if self._recover_variables and self.function_needs_variable_recovery(func):
            _l.info("Performing variable recovery on %r...", func)
            try:
                _ = self.project.analyses[VariableRecoveryFast].prep(kb=self.kb)(func, low_priority=self._low_priority)
            except claripy.ClaripyError:
                _l.warning("An claripy exception occurred during variable recovery analysis on function %#x.",
                           func.addr,
                           exc_info=True,
                           )
                return None, None, None

        # determine the calling convention of each function
        cc_analysis = self.project.analyses[CallingConventionAnalysis].prep(kb=self.kb)(
            func, cfg=self._cfg,
            analyze_callsites=self._analyze_callsites)

        if cc_analysis.cc is not None:
            _l.info("Determined calling convention and prototype for %r.", func)
            return cc_analysis.cc, cc_analysis.prototype, self.kb.variables.get_function_manager(func_addr)
        else:
            _l.info("Cannot determine calling convention for %r.", func)
            return None, None, self.kb.variables.get_function_manager(func_addr)

    def prioritize_functions(self, func_addrs: Iterable[int]):
        """
        Prioritize the analysis of specified functions.

        :param func_addrs: A collection of function addresses to analyze first.
        """

        with self._func_queue_lock:
            func_addrs = set(func_addrs)
            to_prioritize = [ ]
            remaining = [ ]
            while not self._func_queue.empty():
                addr = self._func_queue.get()
                if addr in func_addrs:
                    to_prioritize.append(addr)
                else:
                    if not self._skip_other_funcs:
                        remaining.append(addr)

            for addr in itertools.chain(to_prioritize, remaining):
                self._func_queue.put(addr)

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

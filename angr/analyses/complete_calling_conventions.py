from typing import Optional
import logging

import claripy

from ..knowledge_plugins.cfg import CFGModel
from ..analyses.cfg import CFGUtils
from . import Analysis, register_analysis

_l = logging.getLogger(name=__name__)


class CompleteCallingConventionsAnalysis(Analysis):

    def __init__(self, recover_variables=False, low_priority=False, force=False, cfg: Optional[CFGModel]=None,
                 analyze_callsites: bool=False, skip_signature_matched_functions: bool=False):

        self._recover_variables = recover_variables
        self._low_priority = low_priority
        self._force = force
        self._cfg = cfg
        self._analyze_callsites = analyze_callsites
        self._skip_signature_matched_functions = skip_signature_matched_functions

        self._analyze()

    def _analyze(self):
        """
        Infer calling conventions for all functions in the current project.

        :return:
        """

        # get an ordering of functions based on the call graph
        sorted_funcs = CFGUtils.quasi_topological_sort_nodes(self.kb.functions.callgraph)
        total_funcs = len(sorted_funcs)

        self._update_progress(0)

        for idx, func_addr in enumerate(reversed(sorted_funcs)):
            func = self.kb.functions.get_by_addr(func_addr)

            if func.calling_convention is None or self._force:
                if func.alignment:
                    # skip all alignments
                    continue

                if self._skip_signature_matched_functions and func.from_signature:
                    # this function matches against a known library function. skip it.
                    continue

                # if it's a normal function, we attempt to perform variable recovery
                if self._recover_variables and self.function_needs_variable_recovery(func):
                    _l.info("Performing variable recovery on %r...", func)
                    try:
                        _ = self.project.analyses.VariableRecoveryFast(func, kb=self.kb, low_priority=self._low_priority)
                    except claripy.ClaripyError:
                        _l.warning("An claripy exception occurred during variable recovery analysis on function %#x.",
                                   func.addr,
                                   exc_info=True,
                                   )
                        continue

                # determine the calling convention of each function
                cc_analysis = self.project.analyses.CallingConvention(func, cfg=self._cfg,
                                                                      analyze_callsites=self._analyze_callsites)
                if cc_analysis.cc is not None:
                    _l.info("Determined calling convention for %r.", func)
                    func.calling_convention = cc_analysis.cc
                else:
                    _l.info("Cannot determine calling convention for %r.", func)

            percentage = (idx + 1) / total_funcs * 100.0
            self._update_progress(percentage)
            if self._low_priority:
                self._release_gil(idx, 1, 0.000001)

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

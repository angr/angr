# pylint:disable=unused-import
from collections import defaultdict
from typing import List, Tuple, Any

from cle import SymbolType

from ...sim_variable import SimMemoryVariable
from .. import Analysis, AnalysesHub
from .condition_processor import ConditionProcessor
from .decompilation_options import DecompilationOption


class Decompiler(Analysis):
    def __init__(self, func, cfg=None, options=None, optimization_passes=None, sp_tracker_track_memory=True):
        self.func = func
        self._cfg = cfg
        self._options = options
        self._optimization_passes = optimization_passes
        self._sp_tracker_track_memory = sp_tracker_track_memory

        self.clinic = None  # mostly for debugging purposes
        self.codegen = None

        self._decompile()

    def _decompile(self):

        if self.func.is_simprocedure:
            return

        options_by_class = defaultdict(list)

        if self._options:
            for o, v in self._options:
                options_by_class[o.cls].append((o, v))

        # set global variables
        self._set_global_variables()

        # convert function blocks to AIL blocks
        clinic = self.project.analyses.Clinic(self.func,
                                              kb=self.kb,
                                              optimization_passes=self._optimization_passes,
                                              sp_tracker_track_memory=self._sp_tracker_track_memory,
                                              **self.options_to_params(options_by_class['clinic'])
                                              )

        cond_proc = ConditionProcessor()

        # recover regions
        ri = self.project.analyses.RegionIdentifier(self.func, graph=clinic.graph, cond_proc=cond_proc, kb=self.kb)

        # structure it
        rs = self.project.analyses.RecursiveStructurer(ri.region, cond_proc=cond_proc, kb=self.kb)

        # simplify it
        s = self.project.analyses.RegionSimplifier(rs.result, kb=self.kb)

        codegen = self.project.analyses.StructuredCodeGenerator(self.func, s.result, cfg=self._cfg,
                                                                func_args=clinic.arg_list,
                                                                kb=self.kb,
                                                                variable_kb=clinic.variable_kb)

        self.clinic = clinic
        self.codegen = codegen

    def _set_global_variables(self):

        global_variables = self.kb.variables['global']
        for symbol in self.project.loader.main_object.symbols:
            if symbol.type == SymbolType.TYPE_OBJECT:
                global_variables.set_variable('global', symbol.rebased_addr, SimMemoryVariable(symbol.rebased_addr, 1,
                                                                                               name=symbol.name))

    @staticmethod
    def options_to_params(options):
        """
        Convert decompilation options to a dict of params.

        :param List[Tuple[DecompilationOption, Any]] options:   The decompilation options.
        :return:                                                A dict of keyword arguments.
        :rtype:                                                 dict
        """

        d = { }
        for option, value in options:
            d[option.param] = value
        return d


AnalysesHub.register_default('Decompiler', Decompiler)

# pylint:disable=unused-import
from collections import defaultdict
from typing import List, Tuple, Optional, Iterable, Union, Type, Set, TYPE_CHECKING

from cle import SymbolType

from ...sim_variable import SimMemoryVariable
from .. import Analysis, AnalysesHub
from .condition_processor import ConditionProcessor
from .decompilation_options import DecompilationOption

if TYPE_CHECKING:
    from .peephole_optimizations import PeepholeOptimizationStmtBase, PeepholeOptimizationExprBase


class Decompiler(Analysis):
    def __init__(self, func, cfg=None, options=None, optimization_passes=None, sp_tracker_track_memory=True,
                 variable_kb=None,
                 peephole_optimizations: Optional[Iterable[Union[Type['PeepholeOptimizationStmtBase'],Type['PeepholeOptimizationExprBase']]]]=None,
                 vars_must_struct: Optional[Set[str]]=None,
                 flavor='pseudocode',
                 expr_comments=None,
                 stmt_comments=None,
                 ):
        self.func = func
        self._cfg = cfg
        self._options = options
        self._optimization_passes = optimization_passes
        self._sp_tracker_track_memory = sp_tracker_track_memory
        self._peephole_optimizations = peephole_optimizations
        self._vars_must_struct = vars_must_struct
        self._flavor = flavor
        self._variable_kb = variable_kb
        self._expr_comments = expr_comments
        self._stmt_comments = stmt_comments

        self.clinic = None  # mostly for debugging purposes
        self.codegen = None

        self._decompile()

    def _decompile(self):

        if self.func.is_simprocedure:
            return

        try:
            old_codegen = self.kb.structured_code[(self.func.addr, self._flavor)]
        except KeyError:
            old_codegen = None

        options_by_class = defaultdict(list)

        if self._options:
            for o, v in self._options:
                options_by_class[o.cls].append((o, v))

        # set global variables
        self._set_global_variables()
        self._update_progress(5., text='Converting to AIL')

        variable_kb = self._variable_kb
        if variable_kb is None:
            # fall back to old codegen
            if old_codegen is not None:
                variable_kb = old_codegen._variable_kb

        if variable_kb is None:
            reset_variable_names = True
        else:
            reset_variable_names = self.func.addr not in variable_kb.variables.function_managers

        # convert function blocks to AIL blocks
        clinic = self.project.analyses.Clinic(self.func,
                                              kb=self.kb,
                                              variable_kb=variable_kb,
                                              reset_variable_names=reset_variable_names,
                                              optimization_passes=self._optimization_passes,
                                              sp_tracker_track_memory=self._sp_tracker_track_memory,
                                              cfg=self._cfg,
                                              peephole_optimizations=self._peephole_optimizations,
                                              must_struct=self._vars_must_struct,
                                              progress_callback=lambda p, **kwargs: self._update_progress(p*(70-5)/100.+5, **kwargs),
                                              **self.options_to_params(options_by_class['clinic'])
                                              )
        self.clinic = clinic
        self._update_progress(70., text='Identifying regions')

        if clinic.graph is None:
            # the function is empty
            return

        cond_proc = ConditionProcessor()

        # recover regions
        ri = self.project.analyses.RegionIdentifier(self.func, graph=clinic.graph, cond_proc=cond_proc, kb=self.kb)
        self._update_progress(75., text='Structuring code')

        # structure it
        rs = self.project.analyses.RecursiveStructurer(ri.region, cond_proc=cond_proc, kb=self.kb)
        self._update_progress(80., text='Simplifying regions')

        # simplify it
        s = self.project.analyses.RegionSimplifier(rs.result, kb=self.kb)
        self._update_progress(85., text='Generating code')

        codegen = self.project.analyses.StructuredCodeGenerator(self.func, s.result, cfg=self._cfg,
                                                                flavor=self._flavor,
                                                                func_args=clinic.arg_list,
                                                                kb=self.kb,
                                                                variable_kb=clinic.variable_kb,
                                                                expr_comments=old_codegen.expr_comments if old_codegen is not None else None,
                                                                stmt_comments=old_codegen.stmt_comments if old_codegen is not None else None,
                                                                **self.options_to_params(options_by_class['codegen']))
        self._update_progress(90., text='Finishing up')

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

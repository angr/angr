# pylint:disable=unused-import
import logging
from collections import defaultdict
from typing import List, Tuple, Optional, Iterable, Union, Type, Set, Dict, TYPE_CHECKING

from cle import SymbolType
import ailment

from ...knowledge_base import KnowledgeBase
from ...sim_variable import SimMemoryVariable
from ...utils import timethis
from .. import Analysis, AnalysesHub
from .optimization_passes.optimization_pass import OptimizationPass, OptimizationPassStage
from .optimization_passes import get_default_optimization_passes
from .ailgraph_walker import AILGraphWalker
from .condition_processor import ConditionProcessor
from .decompilation_options import DecompilationOption
from .decompilation_cache import DecompilationCache

if TYPE_CHECKING:
    from .peephole_optimizations import PeepholeOptimizationStmtBase, PeepholeOptimizationExprBase

l = logging.getLogger(name=__name__)

_PEEPHOLE_OPTIMIZATIONS_TYPE = \
    Optional[Iterable[Union[Type['PeepholeOptimizationStmtBase'],Type['PeepholeOptimizationExprBase']]]]

class Decompiler(Analysis):
    """
    The decompiler analysis.

    Run this on a Function object for which a normalized CFG has been constructed.
    The fully processed output can be found in result.codegen.text
    """
    def __init__(self, func, cfg=None, options=None, optimization_passes=None, sp_tracker_track_memory=True,
                 variable_kb=None,
                 peephole_optimizations: _PEEPHOLE_OPTIMIZATIONS_TYPE=None,
                 vars_must_struct: Optional[Set[str]]=None,
                 flavor='pseudocode',
                 expr_comments=None,
                 stmt_comments=None,
                 decompile=True,
                 ):
        self.func = func
        self._cfg = cfg
        self._options = options
        if optimization_passes is None:
            self._optimization_passes = get_default_optimization_passes(self.project.arch, self.project.simos.name)
            l.debug("Get %d optimization passes for the current binary.", len(self._optimization_passes))
        else:
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
        self.cache: Optional[DecompilationCache] = None

        if decompile:
            self._decompile()

    def _decompile(self):

        if self.func.is_simprocedure:
            return

        try:
            old_codegen = self.kb.structured_code[(self.func.addr, self._flavor)].codegen
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

        cache = DecompilationCache(self.func.addr)

        # convert function blocks to AIL blocks
        progress_callback = lambda p, **kwargs: self._update_progress(p * (70 - 5) / 100. + 5, **kwargs)
        clinic = self.project.analyses.Clinic(self.func,
                                              kb=self.kb,
                                              variable_kb=variable_kb,
                                              reset_variable_names=reset_variable_names,
                                              optimization_passes=self._optimization_passes,
                                              sp_tracker_track_memory=self._sp_tracker_track_memory,
                                              cfg=self._cfg,
                                              peephole_optimizations=self._peephole_optimizations,
                                              must_struct=self._vars_must_struct,
                                              cache=cache,
                                              progress_callback=progress_callback,
                                              **self.options_to_params(options_by_class['clinic'])
                                              )
        self.clinic = clinic
        self.cache = cache
        self._update_progress(70., text='Identifying regions')

        if clinic.graph is None:
            # the function is empty
            return

        cond_proc = ConditionProcessor(self.project.arch)

        # recover regions
        ri = self.project.analyses.RegionIdentifier(self.func, graph=clinic.graph, cond_proc=cond_proc, kb=self.kb)
        # run optimizations that may require re-RegionIdentification
        self.clinic.graph, ri = self._run_region_simplification_passes(clinic.graph, ri, clinic.reaching_definitions)
        self._update_progress(75., text='Structuring code')

        # structure it
        rs = self.project.analyses.RecursiveStructurer(ri.region, cond_proc=cond_proc, kb=self.kb, func=self.func)
        self._update_progress(80., text='Simplifying regions')

        # simplify it
        s = self.project.analyses.RegionSimplifier(self.func, rs.result, kb=self.kb, variable_kb=clinic.variable_kb)
        self._update_progress(85., text='Generating code')

        codegen = self.project.analyses.StructuredCodeGenerator(
            self.func, s.result, cfg=self._cfg,
            flavor=self._flavor,
            func_args=clinic.arg_list,
            kb=self.kb,
            variable_kb=clinic.variable_kb,
            expr_comments=old_codegen.expr_comments if old_codegen is not None else None,
            stmt_comments=old_codegen.stmt_comments if old_codegen is not None else None,
            const_formats=old_codegen.const_formats if old_codegen is not None else None,
            externs=clinic.externs,
            **self.options_to_params(options_by_class['codegen'])
        )
        self._update_progress(90., text='Finishing up')

        self.codegen = codegen
        self.cache.codegen = codegen
        self.cache.clinic = self.clinic

    @timethis
    def _run_region_simplification_passes(self, ail_graph, ri, reaching_definitions):
        """
        Runs optimizations that should be executed after a single region identification. This function will return
        two items: the new RegionIdentifier object and the new AIL Graph, which should probably be written
        back to the clinic object that the graph is from.

        Note: After each optimization run, if the optimization modifies the graph in any way then RegionIdentification
        will be run again.

        @param ail_graph:   DiGraph with AIL Statements
        @param ri:          RegionIdentifier
        @param reaching_defenitions: ReachingDefenitionAnalysis
        @return:            The possibly new AIL DiGraph and RegionIdentifier
        """
        addr_and_idx_to_blocks: Dict[Tuple[int, Optional[int]], ailment.Block] = {}
        addr_to_blocks: Dict[int, Set[ailment.Block]] = defaultdict(set)

        # update blocks_map to allow node_addr to node lookup
        def _updatedict_handler(node):
            addr_and_idx_to_blocks[(node.addr, node.idx)] = node
            addr_to_blocks[node.addr].add(node)

        AILGraphWalker(ail_graph, _updatedict_handler).walk()

        # run each pass
        for pass_ in self._optimization_passes:

            # only for post region id opts
            if pass_.STAGE != OptimizationPassStage.DURING_REGION_IDENTIFICATION:
                continue

            a = pass_(self.func, blocks_by_addr=addr_to_blocks, blocks_by_addr_and_idx=addr_and_idx_to_blocks,
                         graph=ail_graph, region_identifier=ri, reaching_definitions=reaching_definitions)

            # should be None if no changes
            if a.out_graph:
                # use the new graph
                ail_graph = a.out_graph

                cond_proc = ConditionProcessor(self.project.arch)
                # always update RI on graph change
                ri = self.project.analyses.RegionIdentifier(self.func, graph=ail_graph, cond_proc=cond_proc,
                                                            kb=self.kb)

        return ail_graph, ri

    def _set_global_variables(self):

        global_variables = self.kb.variables['global']
        for symbol in self.project.loader.main_object.symbols:
            if symbol.type == SymbolType.TYPE_OBJECT:
                ident = global_variables.next_variable_ident('global')
                global_variables.set_variable('global', symbol.rebased_addr, SimMemoryVariable(
                    symbol.rebased_addr,
                    1,
                    name=symbol.name,
                    ident=ident
                ))

    def reflow_variable_types(self, type_constraints: Set, var_to_typevar: Dict, codegen):
        """
        Re-run type inference on an existing variable recovery result, then rerun codegen to generate new results.

        :return:
        """

        var_kb = self._variable_kb if self._variable_kb is not None else KnowledgeBase(self.project)

        if self.func.addr not in var_kb.variables:
            # for some reason variables for the current function don't really exist...
            groundtruth = {}
        else:
            var_manager = var_kb.variables[self.func.addr]
            # ground-truth types
            groundtruth = {}
            for variable in var_manager.variables_with_manual_types:
                vartype = var_manager.variable_to_types.get(variable, None)
                if vartype is not None:
                    for typevar in var_to_typevar[variable]:
                        groundtruth[typevar] = vartype

        # variables that must be interpreted as structs
        if self._vars_must_struct:
            must_struct = set()
            for var, typevars in var_to_typevar.items():
                for typevar in typevars:
                    if var.ident in self._vars_must_struct:
                        must_struct.add(typevar)
        else:
            must_struct = None

        # type inference
        try:
            tp = self.project.analyses.Typehoon(type_constraints, kb=var_kb, var_mapping=var_to_typevar,
                                                must_struct=must_struct, ground_truth=groundtruth)
            tp.update_variable_types(self.func.addr, var_to_typevar)
            tp.update_variable_types('global', var_to_typevar)
        except Exception:  # pylint:disable=broad-except
            l.warning("Typehoon analysis failed. Variables will not have types. Please report to GitHub.",
                      exc_info=True)

        codegen.reload_variable_types()

        return codegen

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

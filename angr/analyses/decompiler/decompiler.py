# pylint:disable=unused-import
import logging
from collections import defaultdict
from typing import Optional, Union, Any, TYPE_CHECKING
from collections.abc import Iterable

import networkx
from cle import SymbolType
import ailment

from angr.analyses.cfg import CFGFast
from ...knowledge_plugins.functions.function import Function
from ...knowledge_base import KnowledgeBase
from ...sim_variable import SimMemoryVariable, SimRegisterVariable, SimStackVariable
from ...utils import timethis
from .. import Analysis, AnalysesHub
from .structuring import RecursiveStructurer, PhoenixStructurer
from .region_identifier import RegionIdentifier
from .optimization_passes.optimization_pass import OptimizationPassStage
from .optimization_passes import get_default_optimization_passes
from .ailgraph_walker import AILGraphWalker
from .condition_processor import ConditionProcessor
from .decompilation_options import DecompilationOption
from .decompilation_cache import DecompilationCache
from .utils import remove_labels
from .sequence_walker import SequenceWalker

if TYPE_CHECKING:
    from angr.knowledge_plugins.cfg.cfg_model import CFGModel
    from .peephole_optimizations import PeepholeOptimizationExprBase, PeepholeOptimizationStmtBase
    from .structuring.structurer_nodes import SequenceNode
    from .structured_codegen.c import CStructuredCodeGenerator

l = logging.getLogger(name=__name__)

_PEEPHOLE_OPTIMIZATIONS_TYPE = Optional[
    Iterable[Union[type["PeepholeOptimizationStmtBase"], type["PeepholeOptimizationExprBase"]]]
]


class Decompiler(Analysis):
    """
    The decompiler analysis.

    Run this on a Function object for which a normalized CFG has been constructed.
    The fully processed output can be found in result.codegen.text
    """

    def __init__(
        self,
        func: Function | str | int,
        cfg: Union["CFGFast", "CFGModel"] | None = None,
        options=None,
        optimization_passes=None,
        sp_tracker_track_memory=True,
        variable_kb=None,
        peephole_optimizations: _PEEPHOLE_OPTIMIZATIONS_TYPE = None,
        vars_must_struct: set[str] | None = None,
        flavor="pseudocode",
        expr_comments=None,
        stmt_comments=None,
        ite_exprs=None,
        binop_operators=None,
        decompile=True,
        regen_clinic=True,
        inline_functions=frozenset(),
        update_memory_data: bool = True,
        generate_code: bool = True,
    ):
        if not isinstance(func, Function):
            func = self.kb.functions[func]
        self.func: Function = func
        self._cfg = cfg.model if isinstance(cfg, CFGFast) else cfg
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
        self._ite_exprs = ite_exprs
        self._binop_operators = binop_operators
        self._regen_clinic = regen_clinic
        self._update_memory_data = update_memory_data
        self._generate_code = generate_code
        self._inline_functions = inline_functions

        self.clinic = None  # mostly for debugging purposes
        self.codegen: Optional["CStructuredCodeGenerator"] = None
        self.cache: DecompilationCache | None = None
        self.options_by_class = None
        self.seq_node: Optional["SequenceNode"] = None
        self.unoptimized_ail_graph: networkx.DiGraph | None = None
        self.ail_graph: networkx.DiGraph | None = None

        if decompile:
            self._decompile()

    def _decompile(self):
        if self.func.is_simprocedure:
            return

        # Load from cache
        try:
            cache = self.kb.structured_code[(self.func.addr, self._flavor)]
            old_codegen = cache.codegen
            old_clinic = cache.clinic
            ite_exprs = cache.ite_exprs if self._ite_exprs is None else self._ite_exprs
            binop_operators = cache.binop_operators if self._binop_operators is None else self._binop_operators
        except KeyError:
            ite_exprs = self._ite_exprs
            binop_operators = self._binop_operators
            old_codegen = None
            old_clinic = None

        self.options_by_class = defaultdict(list)

        if self._options:
            for o, v in self._options:
                self.options_by_class[o.cls].append((o, v))

        # set global variables
        self._set_global_variables()
        self._update_progress(5.0, text="Converting to AIL")

        variable_kb = self._variable_kb
        if variable_kb is None:
            # fall back to old codegen
            if old_codegen is not None:
                variable_kb = old_codegen._variable_kb

        if variable_kb is None:
            reset_variable_names = True
        else:
            reset_variable_names = self.func.addr not in variable_kb.variables.function_managers

        # determine a few arguments according to the structuring algorithm
        fold_callexprs_into_conditions = False
        self._force_loop_single_exit = True
        self._complete_successors = False
        self._recursive_structurer_params = self.options_to_params(self.options_by_class["recursive_structurer"])
        if "structurer_cls" not in self._recursive_structurer_params:
            self._recursive_structurer_params["structurer_cls"] = PhoenixStructurer
        if self._recursive_structurer_params["structurer_cls"] == PhoenixStructurer:
            self._force_loop_single_exit = False
            self._complete_successors = True
            fold_callexprs_into_conditions = True

        cache = DecompilationCache(self.func.addr)
        cache.ite_exprs = ite_exprs
        cache.binop_operators = binop_operators

        # convert function blocks to AIL blocks
        def progress_callback(p, **kwargs):
            return self._update_progress(p * (70 - 5) / 100.0 + 5, **kwargs)

        if self._regen_clinic or old_clinic is None or self.func.prototype is None:
            clinic = self.project.analyses.Clinic(
                self.func,
                kb=self.kb,
                variable_kb=variable_kb,
                reset_variable_names=reset_variable_names,
                optimization_passes=self._optimization_passes,
                sp_tracker_track_memory=self._sp_tracker_track_memory,
                fold_callexprs_into_conditions=fold_callexprs_into_conditions,
                cfg=self._cfg,
                peephole_optimizations=self._peephole_optimizations,
                must_struct=self._vars_must_struct,
                cache=cache,
                progress_callback=progress_callback,
                inline_functions=self._inline_functions,
                **self.options_to_params(self.options_by_class["clinic"]),
            )
        else:
            clinic = old_clinic
            # reuse the old, unaltered graph
            clinic.graph = clinic.cc_graph
            clinic.cc_graph = clinic.copy_graph()

        self.clinic = clinic
        self.cache = cache
        self._variable_kb = clinic.variable_kb
        self._update_progress(70.0, text="Identifying regions")

        if clinic.graph is None:
            # the function is empty
            return

        # expose a copy of the graph before any optimizations that may change the graph occur;
        # use this graph if you need a reference of exact mapping of instructions to AIL statements
        self.unoptimized_ail_graph = (
            clinic.unoptimized_graph if clinic.unoptimized_graph is not None else clinic.copy_graph()
        )
        cond_proc = ConditionProcessor(self.project.arch)

        clinic.graph = self._run_graph_simplification_passes(
            clinic.graph,
            clinic.reaching_definitions,
            ite_exprs=ite_exprs,
        )

        # recover regions, delay updating when we have optimizations that may update regions themselves
        delay_graph_updates = any(
            pass_.STAGE == OptimizationPassStage.DURING_REGION_IDENTIFICATION for pass_ in self._optimization_passes
        )
        ri = self._recover_regions(clinic.graph, cond_proc, update_graph=not delay_graph_updates)

        # run optimizations that may require re-RegionIdentification
        clinic.graph, ri = self._run_region_simplification_passes(
            clinic.graph,
            ri,
            clinic.reaching_definitions,
            ite_exprs=ite_exprs,
        )

        # save the graph before structuring happens (for AIL view)
        clinic.cc_graph = remove_labels(clinic.copy_graph())

        codegen = None
        seq_node = None
        # in the event that the decompiler is used without code generation as the target, we should avoid all
        # heavy analysis that is used only for the purpose of code generation
        if self._generate_code:
            self._update_progress(75.0, text="Structuring code")

            # structure it
            rs = self.project.analyses[RecursiveStructurer].prep(kb=self.kb)(
                ri.region,
                cond_proc=cond_proc,
                func=self.func,
                **self._recursive_structurer_params,
            )
            self._update_progress(80.0, text="Simplifying regions")

            # simplify it
            s = self.project.analyses.RegionSimplifier(
                self.func,
                rs.result,
                kb=self.kb,
                variable_kb=clinic.variable_kb,
                **self.options_to_params(self.options_by_class["region_simplifier"]),
            )
            seq_node = s.result
            seq_node = self._run_post_structuring_simplification_passes(
                seq_node, binop_operators=cache.binop_operators, goto_manager=s.goto_manager, graph=clinic.graph
            )
            # update memory data
            if self._cfg is not None and self._update_memory_data:
                self.find_data_references_and_update_memory_data(seq_node)

            self._update_progress(85.0, text="Generating code")
            codegen = self.project.analyses.StructuredCodeGenerator(
                self.func,
                seq_node,
                cfg=self._cfg,
                ail_graph=clinic.graph,
                flavor=self._flavor,
                func_args=clinic.arg_list,
                kb=self.kb,
                variable_kb=clinic.variable_kb,
                expr_comments=old_codegen.expr_comments if old_codegen is not None else None,
                stmt_comments=old_codegen.stmt_comments if old_codegen is not None else None,
                const_formats=old_codegen.const_formats if old_codegen is not None else None,
                externs=clinic.externs,
                **self.options_to_params(self.options_by_class["codegen"]),
            )

        self._update_progress(90.0, text="Finishing up")
        self.seq_node = seq_node
        self.codegen = codegen
        # save a copy of the AIL graph that is optimized but not modified by region identification
        self.ail_graph = clinic.cc_graph
        self.cache.codegen = codegen
        self.cache.clinic = self.clinic

    def _recover_regions(self, graph: networkx.DiGraph, condition_processor, update_graph: bool = True):
        return self.project.analyses[RegionIdentifier].prep(kb=self.kb)(
            self.func,
            graph=graph,
            cond_proc=condition_processor,
            update_graph=update_graph,
            force_loop_single_exit=self._force_loop_single_exit,
            complete_successors=self._complete_successors,
            **self.options_to_params(self.options_by_class["region_identifier"]),
        )

    @timethis
    def _run_graph_simplification_passes(self, ail_graph, reaching_definitions, **kwargs):
        """
        Runs optimizations that should be executed before region identification.

        :param ail_graph:   DiGraph with AIL Statements
        :param reaching_defenitions: ReachingDefenitionAnalysis
        :return:            The possibly new AIL DiGraph and RegionIdentifier
        """
        addr_and_idx_to_blocks: dict[tuple[int, int | None], ailment.Block] = {}
        addr_to_blocks: dict[int, set[ailment.Block]] = defaultdict(set)

        # update blocks_map to allow node_addr to node lookup
        def _updatedict_handler(node):
            addr_and_idx_to_blocks[(node.addr, node.idx)] = node
            addr_to_blocks[node.addr].add(node)

        AILGraphWalker(ail_graph, _updatedict_handler).walk()

        # run each pass
        for pass_ in self._optimization_passes:
            # only for post region id opts
            if pass_.STAGE != OptimizationPassStage.BEFORE_REGION_IDENTIFICATION:
                continue
            if pass_.STRUCTURING:
                if self._recursive_structurer_params["structurer_cls"].NAME not in pass_.STRUCTURING:
                    continue

            a = pass_(
                self.func,
                blocks_by_addr=addr_to_blocks,
                blocks_by_addr_and_idx=addr_and_idx_to_blocks,
                graph=ail_graph,
                variable_kb=self._variable_kb,
                reaching_definitions=reaching_definitions,
                **kwargs,
            )

            # should be None if no changes
            if a.out_graph:
                # use the new graph
                ail_graph = a.out_graph

        return ail_graph

    @timethis
    def _run_region_simplification_passes(self, ail_graph, ri, reaching_definitions, **kwargs):
        """
        Runs optimizations that should be executed after a single region identification. This function will return
        two items: the new RegionIdentifier object and the new AIL Graph, which should probably be written
        back to the clinic object that the graph is from.

        Note: After each optimization run, if the optimization modifies the graph in any way then RegionIdentification
        will be run again.

        :param ail_graph:   DiGraph with AIL Statements
        :param ri:          RegionIdentifier
        :param reaching_defenitions: ReachingDefenitionAnalysis
        :return:            The possibly new AIL DiGraph and RegionIdentifier
        """
        addr_and_idx_to_blocks: dict[tuple[int, int | None], ailment.Block] = {}
        addr_to_blocks: dict[int, set[ailment.Block]] = defaultdict(set)

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
            if pass_.STRUCTURING:
                if self._recursive_structurer_params["structurer_cls"].NAME not in pass_.STRUCTURING:
                    continue

            a = pass_(
                self.func,
                blocks_by_addr=addr_to_blocks,
                blocks_by_addr_and_idx=addr_and_idx_to_blocks,
                graph=ail_graph,
                variable_kb=self._variable_kb,
                region_identifier=ri,
                reaching_definitions=reaching_definitions,
                **kwargs,
            )

            # should be None if no changes
            if a.out_graph:
                # use the new graph
                ail_graph = a.out_graph

                # the graph might change! update them.
                addr_and_idx_to_blocks = {}
                addr_to_blocks = defaultdict(set)
                AILGraphWalker(ail_graph, _updatedict_handler).walk()

                cond_proc = ConditionProcessor(self.project.arch)
                # always update RI on graph change
                ri = self._recover_regions(ail_graph, cond_proc, update_graph=False)

        return ail_graph, self._recover_regions(ail_graph, ConditionProcessor(self.project.arch), update_graph=True)

    @timethis
    def _run_post_structuring_simplification_passes(self, seq_node, **kwargs):
        for pass_ in self._optimization_passes:
            if pass_.STAGE != OptimizationPassStage.AFTER_STRUCTURING:
                continue

            a = pass_(self.func, seq=seq_node, **kwargs)
            if a.out_seq:
                seq_node = a.out_seq

        return seq_node

    def _set_global_variables(self):
        global_variables = self.kb.variables["global"]
        for symbol in self.project.loader.main_object.symbols:
            if symbol.type == SymbolType.TYPE_OBJECT:
                ident = global_variables.next_variable_ident("global")
                global_variables.set_variable(
                    "global",
                    symbol.rebased_addr,
                    SimMemoryVariable(symbol.rebased_addr, 1, name=symbol.name, ident=ident),
                )

    def reflow_variable_types(self, type_constraints: set, func_typevar, var_to_typevar: dict, codegen):
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

        # Type inference
        try:
            tp = self.project.analyses.Typehoon(
                type_constraints,
                func_typevar,
                kb=var_kb,
                var_mapping=var_to_typevar,
                must_struct=must_struct,
                ground_truth=groundtruth,
            )
            tp.update_variable_types(
                self.func.addr,
                {v: t for v, t in var_to_typevar.items() if isinstance(v, (SimRegisterVariable, SimStackVariable))},
            )
            tp.update_variable_types(
                "global",
                {v: t for v, t in var_to_typevar.items() if isinstance(v, (SimRegisterVariable, SimStackVariable))},
            )
            # update the function prototype if needed
            if self.func.prototype is not None and self.func.prototype.args:
                var_manager = var_kb.variables[self.func.addr]
                for i, arg in enumerate(codegen.cfunc.arg_list):
                    if i >= len(self.func.prototype.args):
                        break
                    var = arg.variable
                    new_type = var_manager.get_variable_type(var)
                    if new_type is not None:
                        self.func.prototype.args[i] = new_type
        except Exception:  # pylint:disable=broad-except
            l.warning(
                "Typehoon analysis failed. Variables will not have types. Please report to GitHub.", exc_info=True
            )

        codegen.reload_variable_types()

        return codegen

    def find_data_references_and_update_memory_data(self, seq_node: "SequenceNode"):
        const_values: set[int] = set()

        def _handle_Const(expr_idx: int, expr: ailment.Expr.Const, *args, **kwargs):  # pylint:disable=unused-argument
            const_values.add(expr.value)

        def _handle_block(block: ailment.Block, **kwargs):  # pylint:disable=unused-argument
            block_walker = ailment.AILBlockWalkerBase(
                expr_handlers={
                    ailment.Expr.Const: _handle_Const,
                }
            )
            block_walker.walk(block)

        seq_walker = SequenceWalker(
            handlers={
                ailment.Block: _handle_block,
            },
            update_seqnode_in_place=False,
        )
        seq_walker.walk(seq_node)

        added_memory_data_addrs = []
        for data_addr in const_values:
            if data_addr in self._cfg.memory_data:
                continue
            if not self.project.loader.find_loadable_containing(data_addr):
                continue
            if self._cfg.add_memory_data(data_addr, None):
                added_memory_data_addrs.append(data_addr)

        self._cfg.tidy_data_references(
            memory_data_addrs=added_memory_data_addrs,
        )

    @staticmethod
    def options_to_params(options: list[tuple[DecompilationOption, Any]]) -> dict[str, Any]:
        """
        Convert decompilation options to a dict of params.

        :param options:   The decompilation options.
        :return:          A dict of keyword arguments.
        """

        d = {}
        for option, value in options:
            if option.convert is not None:
                d[option.param] = option.convert(value)
            else:
                d[option.param] = value
        return d


AnalysesHub.register_default("Decompiler", Decompiler)

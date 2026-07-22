# pylint:disable=unused-import,protected-access
from __future__ import annotations

import logging
from collections import defaultdict
from collections.abc import Iterable
from typing import TYPE_CHECKING, Any

import networkx
from cle import SymbolType

from angr import ailment
from angr.analyses.analysis import AnalysesHub, Analysis
from angr.analyses.cfg import CFGFast
from angr.analyses.s_propagator import sprop_cache_scope
from angr.analyses.typehoon.typehoon import Typehoon
from angr.analyses.typehoon.typevars import TypeVariableManager
from angr.errors import AngrAIError
from angr.knowledge_plugins.functions.function import Function
from angr.rust.optimization_passes import get_rust_optimization_passes
from angr.rust.typehoon.typehoon import RustTypehoon
from angr.sim_type import parse_type
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable, SimStackVariable
from angr.utils import timethis

from .ailgraph_walker import AILGraphWalker
from .clinic import ClinicStage
from .condition_processor import ConditionProcessor
from .decompilation_cache import DecompilationCache
from .decompilation_options import PARAM_TO_OPTION, DecompilationOption
from .notes import DecompilationNote
from .optimization_passes.optimization_pass import OptimizationPassStage
from .presets import DECOMPILATION_PRESETS, DecompilationPreset
from .region_identifier import RegionIdentifier
from .sequence_walker import SequenceWalker
from .structured_codegen import DummyStructuredCodeGenerator
from .structured_codegen.c import CStructuredCodeGenerator
from .structured_codegen.rust import RustStructuredCodeGenerator
from .structurer_nodes import SequenceNode
from .structuring import DEFAULT_STRUCTURER, PhoenixStructurer, RecursiveStructurer
from .structuring.phoenix import MultiStmtExprMode
from .utils import remove_edges_in_ailgraph
from .variable_map import VariableMap

if TYPE_CHECKING:
    from angr.analyses.typehoon.typevars import TypeConstraint, TypeVariable
    from angr.knowledge_plugins.cfg.cfg_model import CFGModel

    from .peephole_optimizations import PeepholeOptimizationExprBase, PeepholeOptimizationStmtBase
    from .structured_codegen.base import BaseStructuredCodeGenerator

l = logging.getLogger(name=__name__)

_PEEPHOLE_OPTIMIZATIONS_TYPE = (
    Iterable[type["PeepholeOptimizationStmtBase"] | type["PeepholeOptimizationExprBase"]] | None
)


class Decompiler(Analysis):
    """
    The decompiler analysis.

    Run this on a Function object for which a normalized CFG has been constructed.
    The fully processed output can be found in result.codegen.text

    AIL graphs exposed on the result (both on a fresh run and on a cache hit, including caches reloaded from
    angrdb or the runtime-db spill):

    - ``ail_graph`` (= ``clinic.cc_graph``): the simplified graph before region identification.
    - ``clinic.graph``: the final graph after region identification and region simplification.
    - ``unoptimized_ail_graph`` (= ``clinic.unoptimized_graph``): a snapshot before the first structure-altering
      optimization pass; use it for an exact instruction-to-AIL mapping. Only built when
      ``save_unoptimized_graph=True`` is passed; otherwise this attribute is None on both fresh runs and cache hits.
    """

    def __init__(
        self,
        func: Function | str | int,
        cfg: CFGFast | CFGModel | None = None,
        options=None,
        preset: str | DecompilationPreset | None = None,
        optimization_passes=None,
        sp_tracker_track_memory=True,
        peephole_optimizations: _PEEPHOLE_OPTIMIZATIONS_TYPE = None,
        vars_must_struct: set[str] | None = None,
        flavor="pseudocode",
        expr_comments=None,
        stmt_comments=None,
        ite_exprs=None,
        binop_operators=None,
        decompile=True,
        regen_clinic=False,
        inline_functions=None,
        desired_variables=None,
        update_memory_data: bool = True,
        want_full_graph: bool = False,
        generate_code: bool = True,
        use_cache: bool = True,
        update_cache: bool = True,
        expr_collapse_depth: int = 16,
        clinic_graph=None,
        clinic_arg_vvars=None,
        clinic_start_stage=None,
        clinic_end_stage=None,
        clinic_skip_stages=(),
        static_vvars: dict | None = None,
        static_buffers: dict | None = None,
        codegen_cls=CStructuredCodeGenerator,
        save_unoptimized_graph: bool = False,
    ):
        if not isinstance(func, Function):
            func = self.kb.functions[func]
        self.func: Function = func
        if self.func.evicted:
            l.warning(
                "The Function instance %r has been evicted. Pass in a non-evicted Function instance or the "
                "function address instead to avoid unexpected decompilation output caused by using out-dated "
                "data.",
                func,
            )

        self._flavor = flavor

        if cfg is None:
            cfg = self.func._function_manager._kb.cfgs.get_most_accurate()
        self._cfg = cfg.model if isinstance(cfg, CFGFast) else cfg
        self._options = self._parse_options(options) if options else []

        if preset is None and optimization_passes:
            self._optimization_passes = optimization_passes
        else:
            # we use the preset
            if isinstance(preset, str):
                if preset not in DECOMPILATION_PRESETS:
                    raise KeyError(f"Decompilation preset {preset} is not found")
                preset = DECOMPILATION_PRESETS[preset]
            elif preset is None:
                preset = DECOMPILATION_PRESETS["default"]
            if not isinstance(preset, DecompilationPreset):
                raise TypeError('"preset" must be a DecompilationPreset instance')
            self._optimization_passes = preset.get_optimization_passes(self.project.arch, self.project.simos.name)

        if self._flavor == "rust":
            self._optimization_passes.extend(get_rust_optimization_passes())

        l.debug("Get %d optimization passes for the current binary.", len(self._optimization_passes))
        self._sp_tracker_track_memory = sp_tracker_track_memory
        self._peephole_optimizations = peephole_optimizations
        self._vars_must_struct = vars_must_struct
        self._expr_comments = expr_comments
        self._stmt_comments = stmt_comments
        self._ite_exprs = ite_exprs
        self._binop_operators = binop_operators
        self._regen_clinic = regen_clinic
        self._update_memory_data = update_memory_data
        self._want_full_graph = want_full_graph
        self._generate_code = generate_code
        self._inline_functions = frozenset(inline_functions) if inline_functions else set()
        self._desired_variables = frozenset(desired_variables) if desired_variables else set()
        self._static_vvars = static_vvars if static_vvars is not None else {}
        self._static_buffers = static_buffers if static_buffers is not None else {}
        self._save_unoptimized_graph = save_unoptimized_graph
        # ``cfg`` is not in this dict: it is an input, not part of the decompilation result. Its identity is
        # checked separately in :meth:`_can_use_decompilation_cache`.
        # Collection-typed values are normalized to empty collections (never None) so the serialized cache does not
        # need to distinguish None from empty. The exception is peephole_optimizations, where None means "use the
        # default peephole set" and is distinct from an explicitly empty list.
        self._cache_parameters = (
            {
                "options": {(o, v) for o, v in self._options if o.category != "Display" and v != o.default_value},
                "optimization_passes": self._optimization_passes,
                "sp_tracker_track_memory": self._sp_tracker_track_memory,
                "peephole_optimizations": self._peephole_optimizations,
                "vars_must_struct": self._vars_must_struct or set(),
                "flavor": self._flavor,
                "expr_comments": self._expr_comments or {},
                "stmt_comments": self._stmt_comments or {},
                "ite_exprs": self._ite_exprs or set(),
                "binop_operators": self._binop_operators or {},
                "inline_functions": self._inline_functions,
                "desired_variables": self._desired_variables,
                "static_vvars": self._static_vvars,
                "static_buffers": self._static_buffers,
                "save_unoptimized_graph": self._save_unoptimized_graph,
            }
            if use_cache
            else None
        )

        self.clinic = None  # mostly for debugging purposes
        self._clinic_graph = clinic_graph
        self._clinic_arg_vvars = clinic_arg_vvars
        self._clinic_start_stage = clinic_start_stage
        self._clinic_end_stage = clinic_end_stage
        self._clinic_skip_stages = clinic_skip_stages
        self.codegen: BaseStructuredCodeGenerator | None = None
        self.codegen_cls = codegen_cls
        self.cache: DecompilationCache | None = None
        self.cache: DecompilationCache | None = None
        self.options_by_class = None
        self.seq_node: SequenceNode | None = None
        self.unoptimized_ail_graph: networkx.DiGraph | None = None
        self.ail_graph: networkx.DiGraph | None = None
        self.vvar_id_start = None
        self._copied_var_ids: set[int] = set()
        self._optimization_scratch: dict[str, Any] = {}
        self.expr_collapse_depth = expr_collapse_depth
        self.notes: dict[str, DecompilationNote] = {}
        self.region_identifier = None
        self.use_cache = use_cache
        self.update_cache = update_cache

        self._variable_map = None
        # structuring-specific parameters - will be reset in _decompile()
        self._force_loop_single_exit = True
        self._refine_loops_with_single_successor = False
        self._expose_loop_head_backedges = False
        self._recursive_structurer_params = {}

        # cache of reusable AILBlockWalker instances that are shared by all SPropagator instances created during
        # decompilation. Owned here so all walkers are released when this Decompiler instance is garbage-collected.
        # SPropagator picks up this cache (see walker_cache_scope).
        self._sprop_walker_cache: dict = {}

        self._codegen_cls = CStructuredCodeGenerator
        self._typehoon_cls = Typehoon
        if self._flavor == "rust":
            self._codegen_cls = RustStructuredCodeGenerator
            self._typehoon_cls = RustTypehoon

        if decompile:
            with self._resilience():
                self._decompile_with_cache()
            if self.errors:
                if self.update_cache:
                    if (self.func.addr, self._flavor) not in self.kb.decompilations:
                        self.kb.decompilations[(self.func.addr, self._flavor)] = DecompilationCache(self.func.addr)
                    for error in self.errors:
                        self.kb.decompilations[(self.func.addr, self._flavor)].errors.append(error.format())
                with self._resilience():
                    l.info("Decompilation failed for %s. Switching to basic preset and trying again.", self.func)
                    if preset != DECOMPILATION_PRESETS["basic"]:
                        self._optimization_passes = DECOMPILATION_PRESETS["basic"].get_optimization_passes(
                            self.project.arch, self.project.simos.name
                        )
                        self._decompile_with_cache()
                        if self.update_cache:
                            for error in self.errors:
                                self.kb.decompilations[(self.func.addr, self._flavor)].errors.append(error.format())

    def _can_use_decompilation_cache(self, cache: DecompilationCache) -> bool:
        if self._cache_parameters is None or cache.parameters is None:
            return False
        # deserialized caches come back with cfg unset until the caller re-attaches it; unset is not a mismatch
        if cache.cfg is not None and cache.cfg is not self._cfg:
            return False
        a, b = self._cache_parameters, cache.parameters
        if not b:
            # AngrDB-loaded caches carry no recorded parameters; there is nothing to validate against
            return True
        return all(k in b and a[k] == b[k] for k in a)

    @staticmethod
    def _parse_options(options: list[tuple[DecompilationOption | str, Any]]) -> list[tuple[DecompilationOption, Any]]:
        """
        Parse the options and return a list of option tuples.
        """

        converted_options = []
        for o, v in options:
            if isinstance(o, str):
                # convert to DecompilationOption
                o = PARAM_TO_OPTION[o]
            converted_options.append((o, v))
        return converted_options

    def _decompile_with_cache(self):
        with sprop_cache_scope(self._sprop_walker_cache):
            self._decompile()

    def _reuse_cached_decompilation(self, cache, clinic, codegen) -> None:
        """Full-reuse fast path: expose the cached clinic and codegen as this run's results without re-running the
        pipeline. A live codegen's text is re-rendered to pick up in-place display edits; a freshly-deserialized
        codegen (``_handlers is None``) keeps its stored text. The codegen inherits the cache's version and
        timestamp."""
        codegen.version = cache.version
        codegen.timestamp = cache.timestamp
        if codegen._handlers is not None:
            codegen.regenerate_text()

        self.cache = cache
        self.clinic = clinic
        self.codegen = codegen
        self.seq_node = None
        self.ail_graph = clinic.cc_graph
        self.unoptimized_ail_graph = clinic.unoptimized_graph
        self._variable_map = clinic.variable_map
        self.vvar_id_start = clinic.vvar_id_start
        self._copied_var_ids = clinic.copied_var_ids

        if self.update_cache:
            self.kb.decompilations[(self.func.addr, self._flavor)] = cache
        self._finish_progress()

    @timethis
    def _decompile(self):
        if self.func.is_simprocedure:
            return

        cache = None

        if self._cache_parameters is not None:
            try:
                cache = self.kb.decompilations[(self.func.addr, self._flavor)]
                if not self._can_use_decompilation_cache(cache):
                    cache = None
            except KeyError:
                pass

        if cache:
            old_codegen = cache.codegen
            old_clinic = cache.clinic
            ite_exprs = cache.ite_exprs if self._ite_exprs is None else self._ite_exprs
            binop_operators = cache.binop_operators if self._binop_operators is None else self._binop_operators
            l.debug("Decompilation cache hit")
        else:
            old_codegen = None
            old_clinic = None
            # normalize to empty collections so the cache never stores None (passes treat None and empty the same)
            ite_exprs = self._ite_exprs or set()
            binop_operators = self._binop_operators or {}
            l.debug("Decompilation cache miss")

        # Full-reuse fast path: with use_cache and without regen_clinic (the default), a valid cache short-circuits
        # the entire pipeline and hands back the cached clinic and codegen. Requires an AST-carrying codegen (not
        # DummyStructuredCodeGenerator) and this function's variables in kb.dec_variables; anything else falls
        # through to a fresh decompilation.
        if (
            self.use_cache
            and not self._regen_clinic
            and cache is not None
            and old_clinic is not None
            and old_codegen is not None
            and not isinstance(old_codegen, DummyStructuredCodeGenerator)
            and self.func.addr in self.kb.dec_variables
            and self.func.prototype is not None
        ):
            self._reuse_cached_decompilation(cache, old_clinic, old_codegen)
            return

        self.options_by_class = defaultdict(list)

        if self._options:
            for o, v in self._options:
                self.options_by_class[o.cls].append((o, v))

        # set global variables
        self._set_global_variables()
        self._update_progress(5.0, text="Converting to AIL")

        reset_variable_names = self.func.addr not in self.kb.dec_variables.function_managers

        # determine a few arguments according to the structuring algorithm
        fold_callexprs_into_conditions = False
        self._force_loop_single_exit = True
        self._refine_loops_with_single_successor = False
        self._expose_loop_head_backedges = False
        self._recursive_structurer_params = self.options_to_params(self.options_by_class["recursive_structurer"])
        if "structurer_cls" not in self._recursive_structurer_params:
            self._recursive_structurer_params["structurer_cls"] = DEFAULT_STRUCTURER
        # The Rust flavor disables multi-statement-expression generation regardless of user options.
        if self._flavor == "rust":
            self._recursive_structurer_params["use_multistmtexprs"] = MultiStmtExprMode.NEVER
        # is the algorithm based on Phoenix (a schema-based algorithm)?
        if issubclass(self._recursive_structurer_params["structurer_cls"], PhoenixStructurer):
            self._force_loop_single_exit = False
            # self._refine_loops_with_single_successor = True
            self._expose_loop_head_backedges = True
            fold_callexprs_into_conditions = True

        cache = DecompilationCache(self.func.addr)
        cache.cfg = self._cfg
        if self._cache_parameters is not None:
            cache.parameters = self._cache_parameters
        cache.ite_exprs = ite_exprs
        cache.binop_operators = binop_operators

        # The Decompiler owns the VariableMap. A fresh map is created before launching a new Clinic (re-linking
        # populates it from scratch over freshly-allocated atom idx values). When a cached Clinic is reused without
        # re-linking, its existing map is carried over below.
        variable_map = VariableMap()

        # convert function blocks to AIL blocks
        def progress_callback(p, **kwargs):
            return self._update_progress(p * (70 - 5) / 100.0 + 5, **kwargs)

        # a deserialized clinic whose function has no dec_variables cannot drive codegen; re-run Clinic instead
        if (
            self._regen_clinic
            or old_clinic is None
            or self.func.prototype is None
            or self.func.addr not in self.kb.dec_variables
        ):
            clinic = self.project.analyses.Clinic(
                self.func,
                kb=self.kb,
                fail_fast=self._fail_fast,
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
                desired_variables=self._desired_variables,
                optimization_scratch=self._optimization_scratch,
                force_loop_single_exit=self._force_loop_single_exit,
                refine_loops_with_single_successor=self._refine_loops_with_single_successor,
                expose_loop_head_backedges=self._expose_loop_head_backedges,
                typehoon_cls=self._typehoon_cls,
                ail_graph=self._clinic_graph,
                arg_vvars=self._clinic_arg_vvars,
                start_stage=self._clinic_start_stage,
                end_stage=self._clinic_end_stage,
                skip_stages=self._clinic_skip_stages,
                notes=self.notes,
                static_vvars=self._static_vvars,
                static_buffers=self._static_buffers,
                save_unoptimized_graph=self._save_unoptimized_graph,
                flavor=self._flavor,
                variable_map=variable_map,
                **self.options_to_params(self.options_by_class["clinic"]),
            )
        else:
            clinic = old_clinic
            # reuse the old, unaltered graph
            clinic.graph = clinic.cc_graph
            clinic.cc_graph = clinic.copy_graph()
            # the SRDA model is tied to the previous run's graph; drop it so the simplification passes below
            # regenerate it fresh for the reused graph
            clinic.reaching_definitions = None

        self.clinic = clinic
        self.cache = cache
        # Make the VariableMap available on the cache regardless of whether Clinic re-linked variables (a partial
        # Clinic run, or the reuse-cached-Clinic path, may not repopulate cache.variable_map during linking).
        cache.variable_map = clinic.variable_map
        self._variable_map = clinic.variable_map
        self._update_progress(70.0, text="Identifying regions")
        self.vvar_id_start = clinic.vvar_id_start
        self._copied_var_ids = clinic.copied_var_ids

        if clinic.graph is None:
            # the function is empty
            return

        # expose a copy of the graph before any optimizations that may change the graph occur; use this graph if you
        # need an exact instruction-to-AIL mapping. Only built when save_unoptimized_graph is set. clinic captured
        # the snapshot iff a structure-altering pass ran; if none did, the current graph is itself unoptimized.
        if self._save_unoptimized_graph:
            self.unoptimized_ail_graph = (
                clinic.unoptimized_graph if clinic.unoptimized_graph is not None else clinic.copy_graph()
            )
        cond_proc = ConditionProcessor(self.project.arch, clinic._ail_manager)

        clinic.graph = self._run_graph_simplification_passes(
            clinic.graph,
            clinic.reaching_definitions,
            ite_exprs=ite_exprs,
        )

        # recover regions, delay updating when we have optimizations that may update regions themselves
        delay_graph_updates = any(
            pass_.STAGE == OptimizationPassStage.DURING_REGION_IDENTIFICATION for pass_ in self._optimization_passes
        )
        self.region_identifier = self._recover_regions(clinic.graph, cond_proc, update_graph=not delay_graph_updates)

        self._update_progress(73.0, text="Running region-simplification passes")

        # run optimizations that may require re-RegionIdentification
        clinic.graph, self.region_identifier = self._run_region_simplification_passes(
            clinic.graph,
            self.region_identifier,
            clinic.reaching_definitions,
            ite_exprs=ite_exprs,
            arg_vvars=set(clinic.arg_vvars) if clinic.arg_vvars is not None else set(),
            edges_to_remove=clinic.edges_to_remove,
        )

        if not self._want_full_graph:
            # finally (no more graph-based simplifications will run in the future),
            # we can remove the edges that should be removed!
            remove_edges_in_ailgraph(clinic.graph, clinic.edges_to_remove)

        # save the graph before structuring happens (for AIL view)
        clinic.cc_graph = clinic.copy_graph()

        codegen = None
        seq_node = None
        # in the event that the decompiler is used without code generation as the target, we should avoid all
        # heavy analysis that is used only for the purpose of code generation
        # we also do not want to run structurer if clinic stopped before variable recovery
        if self._generate_code and (
            self._clinic_end_stage is None or self._clinic_end_stage >= ClinicStage.RECOVER_VARIABLES
        ):
            self._update_progress(75.0, text="Structuring code")

            # structure it
            rs = self.project.analyses[RecursiveStructurer].prep(kb=self.kb, fail_fast=self._fail_fast)(
                self.region_identifier.region,
                cond_proc=cond_proc,
                func=self.func,
                ail_manager=clinic._ail_manager,
                **self._recursive_structurer_params,
            )
            self._update_progress(80.0, text="Simplifying regions")

            # simplify it
            # Get variable manager for loop counter naming in RegionSimplifier
            variable_manager = None
            if self.func.addr in self.kb.dec_variables:
                variable_manager = self.kb.dec_variables[self.func.addr]
            region_simplifier_params = self.options_to_params(self.options_by_class["region_simplifier"])
            # The Rust flavor forces if-else simplification off regardless of user options.
            region_simplifier_params.pop("simplify_ifelse", None)
            s = self.project.analyses.RegionSimplifier(
                self.func,
                rs.result,
                self.clinic._ail_manager,
                arg_vvars=set(self.clinic.arg_vvars)
                if self.clinic is not None and self.clinic.arg_vvars is not None
                else set(),
                kb=self.kb,
                fail_fast=self._fail_fast,
                variable_manager=variable_manager,
                simplify_ifelse=self._flavor != "rust",
                **region_simplifier_params,
            )
            seq_node = s.result
            seq_node = self._run_post_structuring_simplification_passes(
                seq_node,
                binop_operators=cache.binop_operators,
                goto_manager=s.goto_manager,
                graph=clinic.graph,
                kb=self.kb,
            )

            # rewrite the sequence node to remove phi expressions
            seq_node = self.transform_seqnode_from_ssa(seq_node)

            # update memory data
            if self._cfg is not None and self._update_memory_data:
                self.find_data_references_and_update_memory_data(seq_node)

            if self._clinic_end_stage is None or self._clinic_end_stage >= ClinicStage.RECOVER_VARIABLES:
                self._update_progress(85.0, text="Generating code")
                codegen = self.project.analyses[self._codegen_cls].prep(kb=self.kb, fail_fast=self._fail_fast)(
                    self.func,
                    seq_node,
                    cfg=self._cfg,
                    ail_graph=clinic.graph,
                    flavor=self._flavor,
                    func_args=clinic.arg_list,
                    variable_map=clinic.variable_map,
                    expr_comments=old_codegen.expr_comments if old_codegen is not None else None,
                    stmt_comments=old_codegen.stmt_comments if old_codegen is not None else None,
                    const_formats=old_codegen.const_formats if old_codegen is not None else None,
                    externs=clinic.externs,
                    binop_depth_cutoff=self.expr_collapse_depth,
                    notes=self.notes,
                    **self.options_to_params(self.options_by_class["codegen"]),
                )

        self.seq_node = seq_node
        self.codegen = codegen
        # save a copy of the AIL graph that is optimized but not modified by region identification
        self.ail_graph = clinic.cc_graph
        self.cache.codegen = codegen
        if codegen is not None:
            # copy the cache's version and timestamp onto the codegen
            codegen.version = self.cache.version
            codegen.timestamp = self.cache.timestamp
        self.cache.clinic = self.clinic

        # LLM refinement pass
        if self.codegen is not None and self.options_by_class is not None:
            llm_opts = self.options_to_params(self.options_by_class.get("decompiler", []))
            if llm_opts.get("llm_refine", False):
                self._update_progress(90.0, text="LLM refinement")
                try:
                    self.llm_refine()
                except Exception:  # pylint:disable=broad-exception-caught
                    l.error("LLM refinement failed", exc_info=True)

        self._update_progress(95.0, text="Finishing up")
        if self.update_cache:
            self.kb.decompilations[(self.func.addr, self._flavor)] = self.cache
        self._finish_progress()

    def _recover_regions(self, graph: networkx.DiGraph, condition_processor, update_graph: bool = True):
        assert self.clinic is not None
        assert self.options_by_class is not None

        return self.project.analyses[RegionIdentifier].prep(kb=self.kb, fail_fast=self._fail_fast)(
            self.func,
            graph=graph,
            cond_proc=condition_processor,
            ail_manager=self.clinic._ail_manager,
            update_graph=update_graph,
            force_loop_single_exit=self._force_loop_single_exit,
            refine_loops_with_single_successor=self._refine_loops_with_single_successor,
            expose_loop_head_backedges=self._expose_loop_head_backedges,
            entry_node_addr=self.clinic.entry_node_addr,
            **self.options_to_params(self.options_by_class["region_identifier"]),
        )

    @timethis
    def _run_graph_simplification_passes(self, ail_graph, reaching_definitions, **kwargs):
        """
        Runs optimizations that should be executed before region identification.

        :param ail_graph:   DiGraph with AIL Statements
        :param reaching_definitions: ReachingDefinitionAnalysis
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
            if pass_.STRUCTURING and self._recursive_structurer_params["structurer_cls"].NAME not in pass_.STRUCTURING:
                l.warning(
                    "Skipping %s because it does not support structuring algorithm: %s",
                    pass_,
                    self._recursive_structurer_params["structurer_cls"].NAME,
                )
                continue

            pass_ = timethis(pass_)
            assert self.clinic is not None
            a = pass_(
                self.func,
                self.clinic._ail_manager,
                blocks_by_addr=addr_to_blocks,
                blocks_by_addr_and_idx=addr_and_idx_to_blocks,
                graph=ail_graph,
                kb=self.kb,
                reaching_definitions=reaching_definitions,
                entry_node_addr=self.clinic.entry_node_addr,
                scratch=self._optimization_scratch,
                force_loop_single_exit=self._force_loop_single_exit,
                refine_loops_with_single_successor=self._refine_loops_with_single_successor,
                expose_loop_head_backedges=self._expose_loop_head_backedges,
                **kwargs,
            )

            # should be None if no changes
            if a.out_graph:
                # use the new graph
                ail_graph = a.out_graph

        return ail_graph

    @timethis
    def _run_region_simplification_passes(self, ail_graph, ri, reaching_definitions, arg_vvars: set[int], **kwargs):
        """
        Runs optimizations that should be executed after a single region identification. This function will return
        two items: the new RegionIdentifier object and the new AIL Graph, which should probably be written
        back to the clinic object that the graph is from.

        Note: After each optimization run, if the optimization modifies the graph in any way then RegionIdentification
        will be run again.

        :param ail_graph:   DiGraph with AIL Statements
        :param ri:          RegionIdentifier
        :param reaching_definitions: ReachingDefinitionAnalysis
        :return:            The possibly new AIL DiGraph and RegionIdentifier
        """
        assert self.clinic is not None

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
            if pass_.STRUCTURING and self._recursive_structurer_params["structurer_cls"].NAME not in pass_.STRUCTURING:
                l.warning(
                    "Skipping %s because it does not support structuring algorithm: %s",
                    pass_,
                    self._recursive_structurer_params["structurer_cls"].NAME,
                )
                continue

            pass_ = timethis(pass_)
            assert self.clinic is not None
            a = pass_(
                self.func,
                self.clinic._ail_manager,
                blocks_by_addr=addr_to_blocks,
                blocks_by_addr_and_idx=addr_and_idx_to_blocks,
                graph=ail_graph,
                kb=self.kb,
                arg_vvars=arg_vvars,
                region_identifier=ri,
                reaching_definitions=reaching_definitions,
                vvar_id_start=self.vvar_id_start,
                entry_node_addr=self.clinic.entry_node_addr,
                scratch=self._optimization_scratch,
                force_loop_single_exit=self._force_loop_single_exit,
                refine_loops_with_single_successor=self._refine_loops_with_single_successor,
                expose_loop_head_backedges=self._expose_loop_head_backedges,
                peephole_optimizations=self._peephole_optimizations,
                avoid_vvar_ids=self._copied_var_ids,
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

                cond_proc = ConditionProcessor(self.project.arch, self.clinic._ail_manager)
                # always update RI on graph change
                ri = self._recover_regions(ail_graph, cond_proc, update_graph=False)

                self.vvar_id_start = a.vvar_id_start

        return ail_graph, self._recover_regions(
            ail_graph, ConditionProcessor(self.project.arch, self.clinic._ail_manager), update_graph=True
        )

    @timethis
    def _run_post_structuring_simplification_passes(self, seq_node, **kwargs):
        for pass_ in self._optimization_passes:
            if pass_.STAGE != OptimizationPassStage.AFTER_STRUCTURING:
                continue

            pass_ = timethis(pass_)
            assert self.clinic is not None
            a = pass_(
                self.func,
                self.clinic._ail_manager,
                seq=seq_node,
                scratch=self._optimization_scratch,
                peephole_optimizations=self._peephole_optimizations,
                **kwargs,
            )
            if a.out_seq:
                seq_node = a.out_seq

        return seq_node

    def _set_global_variables(self):
        global_variables = self.kb.variables["global"]
        for symbol in self.project.loader.main_object.symbols:
            if symbol.type == SymbolType.TYPE_OBJECT:
                ident = global_variables.next_variable_ident("global")
                variable = SimMemoryVariable(symbol.rebased_addr, symbol.size or 1, name=symbol.name, ident=ident)
                variable.renamed = True
                global_variables.set_variable(
                    "global",
                    symbol.rebased_addr,
                    variable,
                )

    def reflow_variable_types(self, cache: DecompilationCache):
        """
        Re-run type inference on an existing variable recovery result, then rerun codegen to generate new results.

        :return:
        """

        # extract everything from the cache
        type_constraints: dict[TypeVariable, set[TypeConstraint]] = cache.type_constraints or {}
        func_typevar = cache.func_typevar
        var_to_typevar = cache.var_to_typevar
        arg_vvars = cache.arg_vvars
        stack_offset_typevars = cache.stack_offset_typevars
        stackvar_max_sizes = cache.stackvar_max_sizes
        codegen = cache.codegen
        max_tv_id = cache.max_tv_id
        tv_manager = TypeVariableManager(self.func.addr, idx=max_tv_id + 1)

        if codegen is None:
            # nothing to reflow; but this should not happen
            return None

        var_kb = self.kb

        if self.func.addr not in var_kb.dec_variables:
            # for some reason variables for the current function don't really exist...
            groundtruth = {}
        else:
            var_manager = var_kb.dec_variables[self.func.addr]
            # ground-truth types
            groundtruth = {}
            for variable in var_manager.variables_with_manual_types:
                vartype = var_manager.variable_to_types.get(variable, None)
                if vartype is not None:
                    for typevar in var_to_typevar[variable]:
                        groundtruth[typevar] = vartype

        if self.func.prototype is not None and not self.func.is_prototype_guessed:
            for arg_i, (_, variable) in arg_vvars.items():
                if arg_i < len(self.func.prototype.args):
                    for tv in var_to_typevar[variable]:
                        groundtruth[tv] = self.func.prototype.args[arg_i]

        # variables that must be interpreted as structs
        if self._vars_must_struct:
            must_struct = set()
            for var, typevars in var_to_typevar.items():
                for typevar in typevars:
                    if var.ident in self._vars_must_struct:
                        must_struct.add(typevar)
        else:
            must_struct = None

        tv_max_sizes = {}
        for v, s in stackvar_max_sizes.items():
            assert isinstance(v, SimStackVariable)
            if v in var_to_typevar:
                for tv in var_to_typevar[v]:
                    tv_max_sizes[tv] = s
            if v.offset in stack_offset_typevars:
                tv = stack_offset_typevars[v.offset]
                tv_max_sizes[tv] = s

        # Type inference
        try:
            tp = self.project.analyses[self._typehoon_cls].prep(kb=var_kb, fail_fast=self._fail_fast)(
                type_constraints,
                func_typevar,
                var_mapping=var_to_typevar,
                must_struct=must_struct,
                ground_truth=groundtruth,
                stack_offset_tvs=stack_offset_typevars,
                stackvar_max_sizes=tv_max_sizes,
                tv_manager=tv_manager,
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
            if (
                self.func.is_prototype_guessed
                and self.func.prototype is not None
                and self.func.prototype.args
                and isinstance(codegen, CStructuredCodeGenerator)
                and codegen.cfunc is not None
            ):
                var_manager = var_kb.dec_variables[self.func.addr]
                for i, arg in enumerate(codegen.cfunc.arg_list):
                    if i >= len(self.func.prototype.args):
                        break
                    var = arg.variable
                    new_type = var_manager.get_variable_type(var)
                    if new_type is not None:
                        self.func.prototype.args = (
                            *self.func.prototype.args[:i],
                            new_type,
                            *self.func.prototype.args[i + 1 :],
                        )
        except Exception:  # pylint:disable=broad-except
            if self._fail_fast:
                raise
            l.warning(
                "Typehoon analysis failed. Variables will not have types. Please report to GitHub.", exc_info=True
            )

        codegen.reload_variable_types()

        return codegen

    def find_data_references_and_update_memory_data(self, seq_node: SequenceNode):
        assert self._cfg is not None

        const_values: set[int] = set()

        def _handle_Const(expr_idx: int, expr: ailment.Expr.Const, *args, **kwargs):  # pylint:disable=unused-argument
            if isinstance(expr.value, int):
                const_values.add(expr.value)

        def _handle_block(block: ailment.Block, **kwargs):  # pylint:disable=unused-argument
            block_walker = ailment.AILBlockViewer(
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

    def transform_graph_from_ssa(self, ail_graph: networkx.DiGraph) -> networkx.DiGraph:
        """
        Translate an SSA AIL graph out of SSA form. This is useful for producing a non-SSA AIL graph for displaying in
        angr management.

        :param ail_graph:   The AIL graph to transform out of SSA form.
        :return:            The translated AIL graph.
        """
        dephication = self.project.analyses.GraphDephication(
            self.func,
            ail_graph,
            rewrite=True,
            variable_map=self._variable_map,
            kb=self.kb,
            fail_fast=self._fail_fast,
        )
        return dephication.output

    def transform_seqnode_from_ssa(self, seq_node: SequenceNode) -> SequenceNode:
        dephication = self.project.analyses.SeqNodeDephication(
            self.func,
            seq_node,
            rewrite=True,
            variable_map=self._variable_map,
            kb=self.kb,
            fail_fast=self._fail_fast,
        )
        return dephication.output

    def llm_refine(self) -> bool:
        """
        Use the configured LLM to suggest improved variable names, function names, and variable types.
        Returns True if any changes were made.
        """
        if self.codegen is None:
            l.warning("llm_refine: no codegen available")
            return False

        llm_client = self.project.llm_client
        if llm_client is None:
            l.error("llm_refine: no LLM client configured. Set ANGR_LLM_MODEL env var or assign project.llm_client.")
            return False

        code_text = self.codegen.text
        if not code_text:
            l.warning("llm_refine: no decompiled text available")
            return False

        changed = False
        changed |= self.llm_suggest_variable_names(llm_client=llm_client, code_text=code_text)
        changed |= self.llm_suggest_function_name(llm_client=llm_client, code_text=code_text)
        changed |= self.llm_suggest_variable_types(llm_client=llm_client, code_text=code_text)

        if changed:
            self.codegen.regenerate_text()

        self.llm_summarize_function(llm_client=llm_client, code_text=self.codegen.text)

        return changed

    def llm_suggest_variable_names(
        self, llm_client=None, code_text: str | None = None, raise_exc: bool = False
    ) -> bool:
        """
        Ask the LLM to suggest better variable names for the decompiled code.
        Returns True if any variables were renamed.

        :param raise_exc:   If True, exceptions from the LLM call are propagated to the caller.
                            If False (default), exceptions are caught and the method returns False.
        """

        from angr.llm_models import VariableNameSuggestions  # pylint:disable=import-outside-toplevel

        if llm_client is None:
            llm_client = self.project.llm_client
        if llm_client is None:
            return False
        if code_text is None:
            code_text = self.codegen.text if self.codegen else None
        if not code_text:
            return False

        # collect unified variables
        varman = self.kb.dec_variables[self.func.addr]
        unified_vars = varman.get_unified_variables(sort=None)

        # also collect argument variables
        arg_vars = []
        if (
            self.codegen
            and isinstance(self.codegen, CStructuredCodeGenerator)
            and self.codegen.cfunc
            and self.codegen.cfunc.arg_list
        ):
            for cvar in self.codegen.cfunc.arg_list:
                v = cvar.unified_variable if cvar.unified_variable is not None else cvar.variable
                if v not in unified_vars:
                    arg_vars.append(v)

        all_vars = unified_vars + arg_vars
        if not all_vars:
            return False

        var_names = [v.name or str(v) for v in all_vars]

        prompt = (
            "You are a reverse engineering assistant. Given the following decompiled C code, suggest better, "
            "more descriptive variable names. Only include variables that you want to rename. "
            "Use snake_case naming convention.\n\n"
            f"Current variable names: {var_names}\n\n"
            f"Decompiled code:\n```c\n{code_text}\n```"
        )

        result = llm_client.completion_structured(
            [{"role": "user", "content": prompt}], output_type=VariableNameSuggestions, raise_exc=raise_exc
        )
        if not result:
            return False

        # build name-to-variable lookup
        name_to_var = {}
        for v in all_vars:
            key = v.name or str(v)
            name_to_var[key] = v

        changed = False
        for rename in result.renames:
            old_name = rename.old_name
            new_name = rename.new_name
            if not new_name:
                continue
            var = name_to_var.get(old_name)
            if var is None:
                continue
            if old_name == new_name:
                continue
            var.name = new_name
            var.renamed = True
            changed = True
            l.info("LLM renamed variable %s -> %s", old_name, new_name)

        return changed

    def llm_suggest_function_name(self, llm_client=None, code_text: str | None = None, raise_exc: bool = False) -> bool:
        """
        Ask the LLM to suggest a better function name.
        Only suggests rename for auto-generated names (starting with ``sub_`` or ``fcn.``).
        Returns True if the function was renamed.

        :param raise_exc:   If True, exceptions from the LLM call are propagated to the caller.
        """

        from angr.llm_models import FunctionNameSuggestion  # pylint:disable=import-outside-toplevel

        if llm_client is None:
            llm_client = self.project.llm_client
        if llm_client is None:
            return False
        if code_text is None:
            code_text = self.codegen.text if self.codegen else None
        if not code_text:
            return False

        if not self.func.is_default_name:
            return False
        current_name = self.func.name

        prompt = (
            "You are a reverse engineering assistant. Given the following decompiled C code, suggest a descriptive "
            "function name that reflects what the function does. Use snake_case naming convention.\n\n"
            f"Decompiled code:\n```c\n{code_text}\n```"
        )

        result = llm_client.completion_structured(
            [{"role": "user", "content": prompt}], output_type=FunctionNameSuggestion, raise_exc=raise_exc
        )
        if not result:
            return False

        new_name = result.function_name
        if not new_name or new_name == current_name:
            return False

        l.info("LLM renamed function %s -> %s", current_name, new_name)
        self.func.name = new_name
        self.func.is_default_name = False
        if self.codegen and isinstance(self.codegen, CStructuredCodeGenerator) and self.codegen.cfunc:
            self.codegen.cfunc.name = new_name

        return True

    def llm_suggest_variable_types(
        self, llm_client=None, code_text: str | None = None, raise_exc: bool = False
    ) -> bool:
        """
        Ask the LLM to suggest better C types for variables.
        Returns True if any variable types were changed.

        :param raise_exc:   If True, exceptions from the LLM call are propagated to the caller.
        """

        from angr.llm_models import VariableTypeSuggestions  # pylint:disable=import-outside-toplevel

        if llm_client is None:
            llm_client = self.project.llm_client
        if llm_client is None:
            return False
        if code_text is None:
            code_text = self.codegen.text if self.codegen else None
        if not code_text:
            return False

        varman = self.kb.dec_variables[self.func.addr]
        unified_vars = varman.get_unified_variables(sort=None)

        if not unified_vars:
            return False

        # build current type info
        var_type_info = {}
        for v in unified_vars:
            name = v.name or str(v)
            current_type = varman.get_variable_type(v)
            var_type_info[name] = str(current_type) if current_type else "unknown"

        prompt = (
            "You are a reverse engineering assistant. Given the following decompiled C code and the current "
            "variable types, suggest better C types for the variables. Only include variables whose types "
            "you want to change.\n\n"
            f"Current variable types: {var_type_info}\n\n"
            f"Decompiled code:\n```c\n{code_text}\n```"
        )

        result = llm_client.completion_structured(
            [{"role": "user", "content": prompt}], output_type=VariableTypeSuggestions, raise_exc=raise_exc
        )
        if not result:
            return False

        # build name-to-variable lookup
        name_to_var = {}
        for v in unified_vars:
            key = v.name or str(v)
            name_to_var[key] = v

        changed = False
        for type_change in result.type_changes:
            var_name = type_change.variable_name
            type_str = type_change.new_type
            if not type_str:
                continue
            var = name_to_var.get(var_name)
            if var is None:
                continue
            try:
                new_type = parse_type(type_str, arch=self.project.arch)
            except Exception:  # pylint:disable=broad-exception-caught
                l.debug("LLM suggested unparseable type '%s' for %s", type_str, var_name)
                continue

            varman.set_variable_type(var, new_type, mark_manual=True, all_unified=True)
            changed = True
            l.info("LLM changed type of %s to %s", var_name, type_str)

        if changed and self.codegen:
            self.codegen.reload_variable_types()

        return changed

    def llm_summarize_function(
        self, llm_client=None, code_text: str | None = None, raise_exc: bool = False
    ) -> str | None:
        """
        Ask the LLM to produce a natural-language summary of what the decompiled function does.
        The summary is stored in the DecompilationCache and returned.

        Returns the summary string, or None if summarization failed.

        :param raise_exc:   If True, exceptions from the LLM call are propagated to the caller.
        """
        if llm_client is None:
            llm_client = self.project.llm_client
        if llm_client is None:
            l.warning("llm_summarize_function: no LLM client configured.")
            return None
        if code_text is None:
            code_text = self.codegen.text if self.codegen else None
        if not code_text:
            l.warning("llm_summarize_function: no decompiled text available.")
            return None

        prompt = (
            "You are a reverse engineering assistant. Given the following decompiled C code, write a concise "
            "natural-language summary of what the function does. Focus on the function's purpose, its inputs "
            "and outputs, and any important side effects. Keep the summary to a short paragraph.\n\n"
            f"Decompiled code:\n```c\n{code_text}\n```\n\n"
            "Respond with ONLY the summary text, no extra formatting."
        )

        try:
            summary = llm_client.completion([{"role": "user", "content": prompt}])
        except Exception as ex:  # pylint:disable=broad-exception-caught
            if raise_exc:
                raise AngrAIError("LLM call failed") from ex
            l.warning("llm_summarize_function: LLM call failed", exc_info=True)
            return None

        if not summary or not isinstance(summary, str):
            return None

        summary = summary.strip()
        if not summary:
            return None

        l.info("LLM generated function summary for %s", self.func.name)

        if self.cache is not None:
            self.cache.function_summary = summary

        return summary

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

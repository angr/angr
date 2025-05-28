# pylint:disable=too-many-boolean-expressions
from __future__ import annotations
from typing import Any, NamedTuple, TYPE_CHECKING
import copy
import logging
import enum
from collections import defaultdict, namedtuple
from collections.abc import Iterable
from dataclasses import dataclass

import networkx
import capstone

import angr.ailment as ailment

from angr.errors import AngrDecompilationError
from angr.knowledge_base import KnowledgeBase
from angr.knowledge_plugins.functions import Function
from angr.knowledge_plugins.cfg.memory_data import MemoryDataSort
from angr.knowledge_plugins.key_definitions import atoms
from angr.codenode import BlockNode
from angr.utils import timethis
from angr.utils.graph import GraphUtils
from angr.utils.types import dereference_simtype_by_lib
from angr.calling_conventions import SimRegArg, SimStackArg, SimFunctionArgument
from angr.sim_type import (
    SimTypeChar,
    SimTypeInt,
    SimTypeLongLong,
    SimTypeShort,
    SimTypeFunction,
    SimTypeBottom,
    SimTypeFloat,
    SimTypePointer,
)
from angr.analyses.stack_pointer_tracker import Register, OffsetVal
from angr.sim_variable import SimVariable, SimStackVariable, SimRegisterVariable, SimMemoryVariable
from angr.procedures.stubs.UnresolvableCallTarget import UnresolvableCallTarget
from angr.procedures.stubs.UnresolvableJumpTarget import UnresolvableJumpTarget
from angr.analyses import Analysis, register_analysis
from angr.analyses.cfg.cfg_base import CFGBase
from angr.analyses.reaching_definitions import ReachingDefinitionsAnalysis
from .ssailification.ssailification import Ssailification
from .stack_item import StackItem, StackItemType
from .return_maker import ReturnMaker
from .ailgraph_walker import AILGraphWalker, RemoveNodeNotice
from .optimization_passes import (
    OptimizationPassStage,
    RegisterSaveAreaSimplifier,
    StackCanarySimplifier,
    TagSlicer,
    DUPLICATING_OPTS,
    CONDENSING_OPTS,
)

if TYPE_CHECKING:
    from angr.knowledge_plugins.cfg import CFGModel
    from .decompilation_cache import DecompilationCache
    from .peephole_optimizations import PeepholeOptimizationStmtBase, PeepholeOptimizationExprBase

l = logging.getLogger(name=__name__)


BlockCache = namedtuple("BlockCache", ("rd", "prop"))


class ClinicMode(enum.Enum):
    """
    Analysis mode for Clinic.
    """

    DECOMPILE = 1
    COLLECT_DATA_REFS = 2


@dataclass
class DataRefDesc:
    """
    The fields of this class is compatible with items inside IRSB.data_refs.
    """

    data_addr: int
    data_size: int
    block_addr: int
    stmt_idx: int
    ins_addr: int
    data_type_str: str


class ClinicStage(enum.IntEnum):
    """
    Different stages of treating an ailment.
    """

    INITIALIZATION = 0
    AIL_GRAPH_CONVERSION = 1
    MAKE_RETURN_SITES = 2
    MAKE_ARGUMENT_LIST = 3
    PRE_SSA_LEVEL0_FIXUPS = 4
    SSA_LEVEL0_TRANSFORMATION = 5
    CONSTANT_PROPAGATION = 6
    TRACK_STACK_POINTERS = 7
    PRE_SSA_LEVEL1_SIMPLIFICATIONS = 8
    SSA_LEVEL1_TRANSFORMATION = 9
    POST_SSA_LEVEL1_SIMPLIFICATIONS = 10
    MAKE_CALLSITES = 11
    POST_CALLSITES = 12
    RECOVER_VARIABLES = 13


class Clinic(Analysis):
    """
    A Clinic deals with AILments.
    """

    _ail_manager: ailment.Manager

    def __init__(
        self,
        func,
        remove_dead_memdefs=False,
        exception_edges=False,
        sp_tracker_track_memory=True,
        fold_callexprs_into_conditions=False,
        insert_labels=True,
        optimization_passes=None,
        cfg=None,
        peephole_optimizations: None | (
            Iterable[type[PeepholeOptimizationStmtBase] | type[PeepholeOptimizationExprBase]]
        ) = None,  # pylint:disable=line-too-long
        must_struct: set[str] | None = None,
        variable_kb=None,
        reset_variable_names=False,
        rewrite_ites_to_diamonds=True,
        cache: DecompilationCache | None = None,
        mode: ClinicMode = ClinicMode.DECOMPILE,
        sp_shift: int = 0,
        inline_functions: set[Function] | None = None,
        inlined_counts: dict[int, int] | None = None,
        inlining_parents: set[int] | None = None,
        vvar_id_start: int = 0,
        optimization_scratch: dict[str, Any] | None = None,
        desired_variables: set[str] | None = None,
        force_loop_single_exit: bool = True,
        complete_successors: bool = False,
        max_type_constraints: int = 4000,
        ail_graph: networkx.DiGraph | None = None,
        arg_vvars: dict[int, tuple[ailment.Expr.VirtualVariable, SimVariable]] | None = None,
        start_stage: ClinicStage | None = ClinicStage.INITIALIZATION,
    ):
        if not func.normalized and mode == ClinicMode.DECOMPILE:
            raise ValueError("Decompilation must work on normalized function graphs.")

        self.function = func

        self.graph = None
        self.cc_graph: networkx.DiGraph | None = None
        self.unoptimized_graph: networkx.DiGraph | None = None
        self.arg_list = None
        self.arg_vvars: dict[int, tuple[ailment.Expr.VirtualVariable, SimVariable]] | None = None
        self.func_args = None
        self.variable_kb = variable_kb
        self.externs: set[SimMemoryVariable] = set()
        self.data_refs: dict[int, list[DataRefDesc]] = {}  # data address to data reference description
        self.optimization_scratch = optimization_scratch if optimization_scratch is not None else {}

        self._func_graph: networkx.DiGraph | None = None
        self._init_ail_graph = ail_graph
        self._init_arg_vvars = arg_vvars
        self._start_stage = start_stage if start_stage is not None else ClinicStage.INITIALIZATION
        self._blocks_by_addr_and_size = {}
        self.entry_node_addr: tuple[int, int | None] = self.function.addr, None

        self._fold_callexprs_into_conditions = fold_callexprs_into_conditions
        self._insert_labels = insert_labels
        self._remove_dead_memdefs = remove_dead_memdefs
        self._exception_edges = exception_edges
        self._sp_tracker_track_memory = sp_tracker_track_memory
        self._cfg: CFGModel | None = cfg
        self.peephole_optimizations = peephole_optimizations
        self._must_struct = must_struct
        self._reset_variable_names = reset_variable_names
        self._rewrite_ites_to_diamonds = rewrite_ites_to_diamonds
        self.reaching_definitions: ReachingDefinitionsAnalysis | None = None
        self._cache = cache
        self._mode = mode
        self._max_type_constraints = max_type_constraints
        self.vvar_id_start = vvar_id_start
        self.vvar_to_vvar: dict[int, int] | None = None
        # during SSA conversion, we create secondary stack variables because they overlap and are larger than the
        # actual stack variables. these secondary stack variables can be safely eliminated if not used by anything.
        self.secondary_stackvars: set[int] = set()

        #
        # intermediate variables used during decompilation
        #

        self._ail_graph: networkx.DiGraph = None  # type:ignore
        self._spt = None
        # cached block-level reaching definition analysis results and propagator results
        self._block_simplification_cache: dict[ailment.Block, NamedTuple] | None = {}
        self._preserve_vvar_ids: set[int] = set()
        self._type_hints: list[tuple[atoms.VirtualVariable | atoms.MemoryLocation, str]] = []

        # inlining help
        self._sp_shift = sp_shift
        self._max_stack_depth = 0
        self._inline_functions = inline_functions if inline_functions else set()
        self._inlined_counts = {} if inlined_counts is None else inlined_counts
        self._inlining_parents = inlining_parents or ()
        self._desired_variables = desired_variables
        self._force_loop_single_exit = force_loop_single_exit
        self._complete_successors = complete_successors

        self._register_save_areas_removed: bool = False
        self.edges_to_remove: list[tuple[tuple[int, int | None], tuple[int, int | None]]] = []
        self.copied_var_ids: set[int] = set()

        self._new_block_addrs = set()

        # a reference to the Typehoon type inference engine; useful for debugging and loading stats post decompilation
        self.typehoon = None

        # sanity checks
        if not self.kb.functions:
            l.warning("No function is available in kb.functions. It will lead to a suboptimal conversion result.")

        if optimization_passes is not None:
            self._optimization_passes = optimization_passes
        else:
            self._optimization_passes = []

        self.stack_items: dict[int, StackItem] = {}
        if self.project.arch.call_pushes_ret:
            self.stack_items[0] = StackItem(0, self.project.arch.bytes, "ret_addr", StackItemType.RET_ADDR)

        if self._mode == ClinicMode.DECOMPILE:
            self._analyze_for_decompiling()
        elif self._mode == ClinicMode.COLLECT_DATA_REFS:
            self._analyze_for_data_refs()
        else:
            raise TypeError(f"Unsupported analysis mode {self._mode}")

    #
    # Public methods
    #

    def block(self, addr, size):
        """
        Get the converted block at the given specific address with the given size.

        :param int addr:
        :param int size:
        :return:
        """

        try:
            return self._blocks_by_addr_and_size[(addr, size)] if self._blocks_by_addr_and_size is not None else None
        except KeyError:
            return None

    def dbg_repr(self):
        """

        :return:
        """
        assert self.graph is not None

        s = ""

        for block in sorted(self.graph.nodes(), key=lambda x: x.addr):
            s += str(block) + "\n\n"

        return s

    #
    # Private methods
    #

    def _analyze_for_decompiling(self):
        # initialize the AIL conversion manager
        self._ail_manager = ailment.Manager(arch=self.project.arch)

        ail_graph = self._init_ail_graph if self._init_ail_graph is not None else self._decompilation_graph_recovery()
        if not ail_graph:
            return
        if self._start_stage <= ClinicStage.INITIALIZATION:
            ail_graph = self._decompilation_fixups(ail_graph)

        if self._inline_functions:
            self._max_stack_depth += self.calculate_stack_depth()
            ail_graph = self._inline_child_functions(ail_graph)

        ail_graph = self._decompilation_simplifications(ail_graph)

        if self._desired_variables:
            ail_graph = self._slice_variables(ail_graph)
        self.graph = ail_graph

    def _decompilation_graph_recovery(self):
        is_pcode_arch = ":" in self.project.arch.name

        # Set up the function graph according to configurations
        self._update_progress(0.0, text="Setting up function graph")
        self._set_function_graph()

        # Remove alignment blocks
        self._update_progress(5.0, text="Removing alignment blocks")
        self._remove_alignment_blocks()

        # if the graph is empty, don't continue
        if not self._func_graph:
            return None

        # Make sure calling conventions of all functions that the current function calls have been recovered
        if not is_pcode_arch:
            self._update_progress(10.0, text="Recovering calling conventions")
            self._recover_calling_conventions()

        # Convert VEX blocks to AIL blocks and then simplify them

        self._update_progress(20.0, text="Converting VEX to AIL")
        self._convert_all()

        return self._make_ailgraph()

    def _decompilation_fixups(self, ail_graph):
        is_pcode_arch = ":" in self.project.arch.name

        self._remove_redundant_jump_blocks(ail_graph)
        # _fix_abnormal_switch_case_heads may re-lift from VEX blocks, so it should be placed as high up as possible
        self._fix_abnormal_switch_case_heads(ail_graph)
        if self._rewrite_ites_to_diamonds:
            self._rewrite_ite_expressions(ail_graph)
        self._remove_redundant_jump_blocks(ail_graph)
        if self._insert_labels:
            self._insert_block_labels(ail_graph)

        # Run simplification passes
        self._update_progress(22.0, text="Optimizing fresh ailment graph")
        ail_graph = self._run_simplification_passes(ail_graph, OptimizationPassStage.AFTER_AIL_GRAPH_CREATION)

        # Fix "fake" indirect jumps and calls
        self._update_progress(25.0, text="Analyzing simple indirect jumps")
        ail_graph = self._replace_single_target_indirect_transitions(ail_graph)

        # Fix tail calls
        self._update_progress(28.0, text="Analyzing tail calls")
        ail_graph = self._replace_tail_jumps_with_calls(ail_graph)

        if is_pcode_arch:
            self._update_progress(29.0, text="Recovering calling conventions (AIL mode)")
            self._recover_calling_conventions(func_graph=ail_graph)

        return self._apply_callsite_prototype_and_calling_convention(ail_graph)

    def _slice_variables(self, ail_graph):
        assert self.variable_kb is not None and self._desired_variables is not None

        nodes_index = {(n.addr, n.idx): n for n in ail_graph.nodes()}

        vfm = self.variable_kb.variables.function_managers[self.function.addr]
        for v_name in self._desired_variables:
            v = next(iter(vv for vv in vfm._unified_variables if vv.name == v_name))
            for va in vfm.get_variable_accesses(v):
                nodes_index[(va.location.block_addr, va.location.block_idx)].statements[va.location.stmt_idx].tags[
                    "keep_in_slice"
                ] = True

        a = TagSlicer(
            self.function,
            graph=ail_graph,
            variable_kb=self.variable_kb,
        )
        if a.out_graph:
            # use the new graph
            ail_graph = a.out_graph
        return ail_graph

    def _inline_child_functions(self, ail_graph):
        for blk in ail_graph.nodes():
            for idx, stmt in enumerate(blk.statements):
                if isinstance(stmt, ailment.Stmt.Call) and isinstance(stmt.target, ailment.Expr.Const):
                    callee = self.function._function_manager.function(stmt.target.value)
                    if (
                        callee.addr == self.function.addr
                        or callee.addr in self._inlining_parents
                        or callee not in self._inline_functions
                        or callee.is_plt
                        or callee.is_simprocedure
                    ):
                        continue

                    ail_graph = self._inline_call(ail_graph, blk, idx, callee)
        return ail_graph

    def _inline_call(self, ail_graph, caller_block, call_idx, callee):
        callee_clinic = self.project.analyses.Clinic(
            callee,
            mode=ClinicMode.DECOMPILE,
            inline_functions=self._inline_functions,
            inlining_parents=(*self._inlining_parents, self.function.addr),
            inlined_counts=self._inlined_counts,
            optimization_passes=[StackCanarySimplifier],
            sp_shift=self._max_stack_depth,
            vvar_id_start=self.vvar_id_start,
            fail_fast=self._fail_fast,  # type: ignore
        )
        self.vvar_id_start = callee_clinic.vvar_id_start + 1
        self._max_stack_depth = callee_clinic._max_stack_depth
        callee_graph = callee_clinic.copy_graph()

        # uniquely mark all the blocks in case of duplicates (e.g., foo(); foo();)
        self._inlined_counts.setdefault(callee.addr, 0)
        for blk in callee_graph.nodes():
            blk.idx = self._inlined_counts[callee.addr]
        self._inlined_counts[callee.addr] += 1

        # figure out where the callee should start at and return to
        callee_start = next(n for n in callee_graph if n.addr == callee.addr)
        caller_successors = list(ail_graph.out_edges(caller_block, data=True))
        assert len(caller_successors) == 1
        caller_successor = caller_successors[0][1]
        ail_graph.remove_edge(caller_block, caller_successor)

        # update all callee return nodes with caller successor
        ail_graph = networkx.union(ail_graph, callee_graph)
        for blk in callee_graph.nodes():
            for idx, stmt in enumerate(list(blk.statements)):
                if isinstance(stmt, ailment.Stmt.Return):
                    # replace the return statement with an assignment to the return register
                    blk.statements.pop(idx)

                    if stmt.ret_exprs and self.project.arch.ret_offset is not None:
                        assign_to_retreg = ailment.Stmt.Assignment(
                            self._ail_manager.next_atom(),
                            ailment.Expr.Register(
                                self._ail_manager.next_atom(),
                                None,
                                self.project.arch.ret_offset,
                                self.project.arch.bits,
                            ),
                            stmt.ret_exprs[0],
                            **stmt.tags,
                        )
                        blk.statements.insert(idx, assign_to_retreg)
                        idx += 1
                    ail_graph.add_edge(blk, caller_successor)
                    break

        # update the call edge
        caller_block.statements[call_idx] = ailment.Stmt.Jump(
            None,
            ailment.Expr.Const(None, None, callee.addr, self.project.arch.bits),
            callee_start.idx,
            **caller_block.statements[call_idx].tags,
        )
        if (
            isinstance(caller_block.statements[call_idx - 2], ailment.Stmt.Store)
            and caller_block.statements[call_idx - 2].data.value == caller_successor.addr
        ):
            # don't push the return address
            caller_block.statements.pop(call_idx - 5)  # t6 = rsp<8>
            caller_block.statements.pop(call_idx - 5)  # t5 = (t6 - 0x8<64>)
            caller_block.statements.pop(call_idx - 5)  # rsp<8> = t5
            caller_block.statements.pop(
                call_idx - 5
            )  # STORE(addr=t5, data=0x40121b<64>, size=8, endness=Iend_LE, guard=None)
            caller_block.statements.pop(call_idx - 5)  # t7 = (t5 - 0x80<64>) <- wtf is this??
        elif (
            isinstance(caller_block.statements[call_idx - 1], ailment.Stmt.Store)
            and caller_block.statements[call_idx - 1].addr.base == "stack_base"
            and caller_block.statements[call_idx - 1].data.value == caller_successor.addr
        ):
            caller_block.statements.pop(call_idx - 1)  # s_10 =L 0x401225<64><8>

        # update caller_block to setup parameters
        if callee_clinic.arg_vvars:
            for arg_idx in sorted(callee_clinic.arg_vvars.keys()):
                param_vvar, reg_arg = callee_clinic.arg_vvars[arg_idx]
                if isinstance(reg_arg, SimRegisterVariable):
                    reg_offset = reg_arg.reg
                    stmt = ailment.Stmt.Assignment(
                        self._ail_manager.next_atom(),
                        param_vvar,
                        ailment.Expr.Register(self._ail_manager.next_atom(), None, reg_offset, reg_arg.bits),
                        ins_addr=caller_block.addr + caller_block.original_size,
                    )
                    caller_block.statements.append(stmt)
                else:
                    raise NotImplementedError("Unsupported parameter type")

        ail_graph.add_edge(caller_block, callee_start)

        return ail_graph

    def calculate_stack_depth(self):
        # we need to reserve space for our own stack
        spt = self._track_stack_pointers()
        stack_offsets = spt.offsets_for(self.project.arch.sp_offset)
        if max(stack_offsets) > 2 ** (self.project.arch.bits - 1):
            # why is this unsigned...
            depth = min(s for s in stack_offsets if s > 2 ** (self.project.arch.bits - 1)) - 2**self.project.arch.bits
        else:
            depth = min(stack_offsets)

        if spt.inconsistent_for(self.project.arch.sp_offset):
            l.warning("Inconsistency found during stack pointer tracking. Stack depth may be incorrect.")
            depth -= 0x1000

        return depth

    def _decompilation_simplifications(self, ail_graph):
        self.arg_vvars = self._init_arg_vvars if self._init_arg_vvars is not None else {}
        self.func_args = {arg_vvar for arg_vvar, _ in self.arg_vvars.values()}
        self._ail_graph = ail_graph

        stages = {
            ClinicStage.MAKE_RETURN_SITES: self._stage_make_return_sites,
            ClinicStage.MAKE_ARGUMENT_LIST: self._stage_make_function_argument_list,
            ClinicStage.PRE_SSA_LEVEL0_FIXUPS: self._stage_pre_ssa_level0_fixups,
            ClinicStage.SSA_LEVEL0_TRANSFORMATION: self._stage_transform_to_ssa_level0,
            ClinicStage.CONSTANT_PROPAGATION: self._stage_constant_propagation,
            ClinicStage.TRACK_STACK_POINTERS: self._stage_track_stack_pointers,
            ClinicStage.PRE_SSA_LEVEL1_SIMPLIFICATIONS: self._stage_pre_ssa_level1_simplifications,
            ClinicStage.SSA_LEVEL1_TRANSFORMATION: self._stage_transform_to_ssa_level1,
            ClinicStage.POST_SSA_LEVEL1_SIMPLIFICATIONS: self._stage_post_ssa_level1_simplifications,
            ClinicStage.MAKE_CALLSITES: self._stage_make_function_callsites,
            ClinicStage.POST_CALLSITES: self._stage_post_callsite_simplifications,
            ClinicStage.RECOVER_VARIABLES: self._stage_recover_variables,
        }

        for stage in sorted(stages):
            if stage < self._start_stage:
                continue
            stages[stage]()

        # remove empty nodes from the graph
        self._ail_graph = self.remove_empty_nodes(self._ail_graph)
        # note that there are still edges to remove before we can structure this graph!

        self.cc_graph = self.copy_graph(self._ail_graph)
        self.externs = self._collect_externs(self._ail_graph, self.variable_kb)
        return self._ail_graph

    def _stage_make_return_sites(self) -> None:
        self._update_progress(30.0, text="Making return sites")
        if self.function.prototype is None or not isinstance(self.function.prototype.returnty, SimTypeBottom):
            self._ail_graph = self._make_returns(self._ail_graph)
        self._ail_graph = self._run_simplification_passes(
            self._ail_graph, stage=OptimizationPassStage.BEFORE_SSA_LEVEL0_TRANSFORMATION
        )

    def _stage_make_function_argument_list(self) -> None:
        self._update_progress(33.0, text="Making argument list")
        self.arg_list = self._make_argument_list()
        self.arg_vvars = self._create_function_argument_vvars(self.arg_list)
        self.func_args = {arg_vvar for arg_vvar, _ in self.arg_vvars.values()}

    def _stage_pre_ssa_level0_fixups(self) -> None:
        # duplicate orphaned conditional jump blocks
        self._ail_graph = self._duplicate_orphaned_cond_jumps(self._ail_graph)
        # rewrite jmp_rax function calls
        self._ail_graph = self._rewrite_jump_rax_calls(self._ail_graph)

    def _stage_transform_to_ssa_level0(self) -> None:
        self._update_progress(35.0, text="Transforming to partial-SSA form (registers)")
        assert self.func_args is not None
        self._ail_graph = self._transform_to_ssa_level0(self._ail_graph, self.func_args)

    def _stage_constant_propagation(self) -> None:
        # full-function constant-only propagation
        self._update_progress(36.0, text="Constant propagation")
        self._simplify_function(
            self._ail_graph,
            remove_dead_memdefs=False,
            unify_variables=False,
            narrow_expressions=False,
            only_consts=True,
            fold_callexprs_into_conditions=self._fold_callexprs_into_conditions,
            max_iterations=1,
        )

    def _stage_track_stack_pointers(self) -> None:
        self._spt = self._track_stack_pointers()

    def _stage_transform_to_ssa_level1(self) -> None:
        self._update_progress(37.0, text="Transforming to partial-SSA form (stack variables)")
        # rewrite (qualified) stack variables into SSA form
        assert self.func_args is not None
        self._ail_graph = self._transform_to_ssa_level1(self._ail_graph, self.func_args)

    def _stage_pre_ssa_level1_simplifications(self) -> None:
        # Simplify blocks
        # we never remove dead memory definitions before making callsites. otherwise stack arguments may go missing
        # before they are recognized as stack arguments.
        self._update_progress(38.0, text="Simplifying blocks 1")
        self._ail_graph = self._simplify_blocks(
            self._ail_graph,
            stack_pointer_tracker=self._spt,
            cache=self._block_simplification_cache,
            preserve_vvar_ids=self._preserve_vvar_ids,
            type_hints=self._type_hints,
        )
        self._rewrite_alloca(self._ail_graph)

        # Run simplification passes
        self._update_progress(40.0, text="Running simplifications 1")
        self._ail_graph = self._run_simplification_passes(
            self._ail_graph,
            stack_pointer_tracker=self._spt,
            stack_items=self.stack_items,
            stage=OptimizationPassStage.AFTER_SINGLE_BLOCK_SIMPLIFICATION,
        )

        # Simplify the entire function for the first time
        self._update_progress(45.0, text="Simplifying function 1")
        self._simplify_function(
            self._ail_graph,
            remove_dead_memdefs=False,
            unify_variables=False,
            narrow_expressions=True,
            fold_callexprs_into_conditions=self._fold_callexprs_into_conditions,
            arg_vvars=self.arg_vvars,
        )

        # Run simplification passes again. there might be more chances for peephole optimizations after function-level
        # simplification
        self._update_progress(48.0, text="Simplifying blocks 2")
        self._ail_graph = self._simplify_blocks(
            self._ail_graph,
            stack_pointer_tracker=self._spt,
            cache=self._block_simplification_cache,
            preserve_vvar_ids=self._preserve_vvar_ids,
            type_hints=self._type_hints,
        )

        # Run simplification passes
        self._update_progress(49.0, text="Running simplifications 2")
        self._ail_graph = self._run_simplification_passes(
            self._ail_graph, stage=OptimizationPassStage.BEFORE_SSA_LEVEL1_TRANSFORMATION
        )

    def _stage_post_ssa_level1_simplifications(self) -> None:
        # Rust-specific; only call this on Rust binaries when we can identify language and compiler
        self._ail_graph = self._rewrite_rust_probestack_call(self._ail_graph)
        # Windows-specific
        self._ail_graph = self._rewrite_windows_chkstk_call(self._ail_graph)

    def _stage_make_function_callsites(self) -> None:
        assert self.func_args is not None

        # Make call-sites
        self._update_progress(50.0, text="Making callsites")
        _, stackarg_offsets, removed_vvar_ids = self._make_callsites(
            self._ail_graph, self.func_args, stack_pointer_tracker=self._spt, preserve_vvar_ids=self._preserve_vvar_ids
        )

        # Run simplification passes
        self._update_progress(53.0, text="Running simplifications 2")
        self._ail_graph = self._run_simplification_passes(
            self._ail_graph, stage=OptimizationPassStage.AFTER_MAKING_CALLSITES
        )

        # Simplify the entire function for the second time
        self._update_progress(55.0, text="Simplifying function 2")
        self._simplify_function(
            self._ail_graph,
            remove_dead_memdefs=self._remove_dead_memdefs,
            stack_arg_offsets=stackarg_offsets,
            unify_variables=True,
            narrow_expressions=True,
            fold_callexprs_into_conditions=self._fold_callexprs_into_conditions,
            removed_vvar_ids=removed_vvar_ids,
            arg_vvars=self.arg_vvars,
            preserve_vvar_ids=self._preserve_vvar_ids,
        )

        # After global optimization, there might be more chances for peephole optimizations.
        # Simplify blocks for the second time
        self._update_progress(60.0, text="Simplifying blocks 3")
        self._ail_graph = self._simplify_blocks(
            self._ail_graph,
            stack_pointer_tracker=self._spt,
            cache=self._block_simplification_cache,
            preserve_vvar_ids=self._preserve_vvar_ids,
            type_hints=self._type_hints,
        )

        # Run simplification passes
        self._update_progress(65.0, text="Running simplifications 3")
        self._ail_graph = self._run_simplification_passes(
            self._ail_graph, stack_items=self.stack_items, stage=OptimizationPassStage.AFTER_GLOBAL_SIMPLIFICATION
        )

        # Simplify the entire function for the third time
        self._update_progress(70.0, text="Simplifying function 3")
        self._simplify_function(
            self._ail_graph,
            remove_dead_memdefs=self._remove_dead_memdefs,
            stack_arg_offsets=stackarg_offsets,
            unify_variables=True,
            narrow_expressions=True,
            fold_callexprs_into_conditions=self._fold_callexprs_into_conditions,
            arg_vvars=self.arg_vvars,
            preserve_vvar_ids=self._preserve_vvar_ids,
        )

        self._update_progress(75.0, text="Simplifying blocks 4")
        self._ail_graph = self._simplify_blocks(
            self._ail_graph,
            stack_pointer_tracker=self._spt,
            cache=self._block_simplification_cache,
            preserve_vvar_ids=self._preserve_vvar_ids,
            type_hints=self._type_hints,
        )

        # Simplify the entire function for the fourth time
        self._update_progress(78.0, text="Simplifying function 4")
        self._simplify_function(
            self._ail_graph,
            remove_dead_memdefs=self._remove_dead_memdefs,
            stack_arg_offsets=stackarg_offsets,
            unify_variables=True,
            narrow_expressions=True,
            fold_callexprs_into_conditions=self._fold_callexprs_into_conditions,
            arg_vvars=self.arg_vvars,
            preserve_vvar_ids=self._preserve_vvar_ids,
        )

        self._update_progress(79.0, text="Running simplifications 4")
        self._ail_graph = self._run_simplification_passes(
            self._ail_graph, stack_items=self.stack_items, stage=OptimizationPassStage.BEFORE_VARIABLE_RECOVERY
        )

    def _stage_post_callsite_simplifications(self) -> None:
        self.arg_list = []
        self.vvar_to_vvar = {}
        self.copied_var_ids = set()

        assert self.arg_vvars is not None

        # update arg_list
        for idx in sorted(self.arg_vvars):
            self.arg_list.append(self.arg_vvars[idx][1])

        # Get virtual variable mapping that can de-phi the SSA representation
        self.vvar_to_vvar, self.copied_var_ids = self._collect_dephi_vvar_mapping_and_rewrite_blocks(
            self._ail_graph, self.arg_vvars
        )

    def _stage_recover_variables(self) -> None:
        assert self.arg_list is not None and self.arg_vvars is not None and self.vvar_to_vvar is not None

        # Recover variables on AIL blocks
        self._update_progress(80.0, text="Recovering variables")
        variable_kb = self._recover_and_link_variables(
            self._ail_graph, self.arg_list, self.arg_vvars, self.vvar_to_vvar, self._type_hints
        )

        # Run simplification passes
        self._update_progress(85.0, text="Running simplifications 4")
        self._ail_graph = self._run_simplification_passes(
            self._ail_graph,
            stage=OptimizationPassStage.AFTER_VARIABLE_RECOVERY,
            avoid_vvar_ids=self.copied_var_ids,
        )

        # Make function prototype
        self._update_progress(90.0, text="Making function prototype")
        self._make_function_prototype(self.arg_list, variable_kb)

        self.variable_kb = variable_kb

    def _analyze_for_data_refs(self):
        # Set up the function graph according to configurations
        self._update_progress(0.0, text="Setting up function graph")
        self._set_function_graph()

        # Remove alignment blocks
        self._update_progress(5.0, text="Removing alignment blocks")
        self._remove_alignment_blocks()

        # if the graph is empty, don't continue
        if not self._func_graph:
            return

        # initialize the AIL conversion manager
        self._ail_manager = ailment.Manager(arch=self.project.arch)

        # Track stack pointers
        self._update_progress(15.0, text="Tracking stack pointers")
        spt = self._track_stack_pointers()

        # Convert VEX blocks to AIL blocks and then simplify them

        self._update_progress(20.0, text="Converting VEX to AIL")
        self._convert_all()

        # there must be at least one Load or one Store
        assert self._blocks_by_addr_and_size is not None
        found_load_or_store = False
        for ail_block in self._blocks_by_addr_and_size.values():
            for stmt in ail_block.statements:
                if isinstance(stmt, ailment.Stmt.Store):
                    found_load_or_store = True
                    break
                if isinstance(stmt, ailment.Stmt.Assignment) and isinstance(stmt.src, ailment.Expr.Load):
                    found_load_or_store = True
                    break
        if not found_load_or_store:
            self.data_refs = {}
            return

        ail_graph = self._make_ailgraph()
        self._remove_redundant_jump_blocks(ail_graph)

        # full-function constant-only propagation
        self._update_progress(33.0, text="Constant propagation")
        self._simplify_function(
            ail_graph,
            remove_dead_memdefs=False,
            unify_variables=False,
            narrow_expressions=False,
            only_consts=True,
            fold_callexprs_into_conditions=self._fold_callexprs_into_conditions,
            max_iterations=1,
        )

        # cached block-level reaching definition analysis results and propagator results
        block_simplification_cache: dict[ailment.Block, NamedTuple] | None = {}

        # Simplify blocks
        # we never remove dead memory definitions before making callsites. otherwise stack arguments may go missing
        # before they are recognized as stack arguments.
        self._update_progress(35.0, text="Simplifying blocks 1")
        ail_graph = self._simplify_blocks(ail_graph, stack_pointer_tracker=spt, cache=block_simplification_cache)

        # Simplify the entire function for the first time
        self._update_progress(45.0, text="Simplifying function 1")
        self._simplify_function(
            ail_graph,
            remove_dead_memdefs=False,
            unify_variables=False,
            narrow_expressions=False,
            fold_callexprs_into_conditions=False,
            rewrite_ccalls=False,
            max_iterations=1,
        )

        # clear _blocks_by_addr_and_size so no one can use it again
        # TODO: Totally remove this dict
        self._blocks_by_addr_and_size = None

        self.graph = ail_graph
        self.arg_list = None
        self.variable_kb = None
        self.cc_graph = None
        self.externs = set()
        self.data_refs: dict[int, list[DataRefDesc]] = self._collect_data_refs(ail_graph)

    @staticmethod
    def _copy_graph(graph: networkx.DiGraph) -> networkx.DiGraph:
        """
        Copy AIL Graph.

        :return: A copy of the AIl graph.
        """
        graph_copy = networkx.DiGraph()
        block_mapping = {}
        # copy all blocks
        for block in graph.nodes():
            new_block = copy.copy(block)
            new_stmts = copy.copy(block.statements)
            new_block.statements = new_stmts
            block_mapping[block] = new_block
            graph_copy.add_node(new_block)

        # copy all edges
        for src, dst, data in graph.edges(data=True):
            new_src = block_mapping[src]
            new_dst = block_mapping[dst]
            graph_copy.add_edge(new_src, new_dst, **data)
        return graph_copy

    def copy_graph(self, graph=None) -> networkx.DiGraph:
        return self._copy_graph(graph or self.graph)  # type:ignore

    @timethis
    def _set_function_graph(self):
        self._func_graph = self.function.graph_ex(exception_edges=self._exception_edges)

    @timethis
    def _remove_alignment_blocks(self):
        """
        Alignment blocks are basic blocks that only consist of nops. They should not be included in the graph.
        """
        assert self._func_graph is not None
        for node in list(self._func_graph.nodes()):
            if self._func_graph.in_degree(node) == 0 and CFGBase._is_noop_block(
                self.project.arch, self.project.factory.block(node.addr, node.size)
            ):
                if (node.addr, None) == self.entry_node_addr:
                    # this is the entry node. after removing this node, the new entry node will be its successor
                    if self._func_graph.out_degree[node] == 1:
                        succ = next(iter(self._func_graph.successors(node)))
                        self.entry_node_addr = succ.addr, None
                    else:
                        # we just don't remove this node...
                        continue
                self._func_graph.remove_node(node)

    @timethis
    def _recover_calling_conventions(self, func_graph=None) -> None:
        """
        Examine the calling convention and function prototype for each function called. For functions with missing
        calling conventions or function prototypes, analyze each *call site* and recover the calling convention and
        function prototype of the callee function.

        :return: None
        """

        attempted_funcs: set[int] = set()

        for node in self.function.transition_graph:
            if (
                isinstance(node, BlockNode)
                and node.addr != self.function.addr
                and self.kb.functions.contains_addr(node.addr)
            ):
                # tail jumps
                target_func = self.kb.functions.get_by_addr(node.addr)
            elif isinstance(node, Function):
                target_func = node
            else:
                # TODO: Enable call-site analysis for indirect calls
                continue

            if target_func.addr in attempted_funcs:
                continue
            attempted_funcs.add(target_func.addr)

            # case 0: the calling convention and prototype are available
            if target_func.calling_convention is not None and target_func.prototype is not None:
                continue

            call_sites = []
            for pred, _, data in self.function.transition_graph.in_edges(node, data=True):
                if data.get("type", None) != "return":
                    call_sites.append(pred)
            # case 1: calling conventions and prototypes are available at every single call site
            if call_sites and all(self.kb.callsite_prototypes.has_prototype(callsite.addr) for callsite in call_sites):
                continue

            # case 2: the callee is a SimProcedure
            if target_func.is_simprocedure:
                cc = self.project.analyses.CallingConvention(target_func, fail_fast=self._fail_fast)  # type: ignore
                if cc.cc is not None and cc.prototype is not None:
                    target_func.calling_convention = cc.cc
                    target_func.prototype = cc.prototype
                    target_func.prototype_libname = cc.prototype_libname
                    continue

            # case 3: the callee is a PLT function
            if target_func.is_plt:
                cc = self.project.analyses.CallingConvention(target_func, fail_fast=self._fail_fast)  # type: ignore
                if cc.cc is not None and cc.prototype is not None:
                    target_func.calling_convention = cc.cc
                    target_func.prototype = cc.prototype
                    target_func.prototype_libname = cc.prototype_libname
                    continue

            # case 4: fall back to call site analysis
            for callsite in call_sites:
                if self.kb.callsite_prototypes.has_prototype(callsite.addr):
                    continue

                # parse the call instruction address from the edge
                callsite_ins_addr = None
                edge_data = [
                    data
                    for src, dst, data in self.function.transition_graph.in_edges(node, data=True)
                    if src is callsite
                ]
                if len(edge_data) == 1:
                    callsite_ins_addr = edge_data[0].get("ins_addr", None)
                if callsite_ins_addr is None:
                    # parse the block...
                    callsite_block = self.project.factory.block(callsite.addr, size=callsite.size)
                    if self.project.arch.branch_delay_slot:
                        if callsite_block.instructions < 2:
                            continue
                        callsite_ins_addr = callsite_block.instruction_addrs[-2]
                    else:
                        if callsite_block.instructions == 0:
                            continue
                        callsite_ins_addr = callsite_block.instruction_addrs[-1]

                cc = self.project.analyses.CallingConvention(
                    None,
                    analyze_callsites=True,
                    caller_func_addr=self.function.addr,
                    callsite_block_addr=callsite.addr,
                    callsite_insn_addr=callsite_ins_addr,
                    func_graph=func_graph,
                    fail_fast=self._fail_fast,  # type:ignore
                )

                if cc.cc is not None and cc.prototype is not None:
                    self.kb.callsite_prototypes.set_prototype(callsite.addr, cc.cc, cc.prototype, manual=False)
                    if func_graph is not None and cc.prototype.returnty is not None:
                        # patch the AIL call statement if we can find one
                        callsite_ail_block: ailment.Block | None = next(
                            iter(bb for bb in func_graph if bb.addr == callsite.addr), None
                        )
                        if callsite_ail_block is not None and callsite_ail_block.statements:
                            last_stmt = callsite_ail_block.statements[-1]
                            if (
                                isinstance(last_stmt, ailment.Stmt.Call)
                                and last_stmt.ret_expr is None
                                and isinstance(cc.cc.RETURN_VAL, SimRegArg)
                            ):
                                reg_offset, reg_size = self.project.arch.registers[cc.cc.RETURN_VAL.reg_name]
                                last_stmt.ret_expr = ailment.Expr.Register(
                                    None,
                                    None,
                                    reg_offset,
                                    reg_size * 8,
                                    ins_addr=callsite_ins_addr,
                                    reg_name=cc.cc.RETURN_VAL.reg_name,
                                )
                                last_stmt.bits = reg_size * 8

        # finally, recover the calling convention of the current function
        if self.function.prototype is None or self.function.calling_convention is None:
            self.project.analyses.CompleteCallingConventions(
                fail_fast=self._fail_fast,  # type: ignore
                recover_variables=True,
                prioritize_func_addrs=[self.function.addr],
                skip_other_funcs=True,
                skip_signature_matched_functions=False,
                func_graphs={self.function.addr: func_graph} if func_graph is not None else None,
            )

    @timethis
    def _track_stack_pointers(self):
        """
        For each instruction, track its stack pointer offset and stack base pointer offset.

        :return: None
        """

        regs = {self.project.arch.sp_offset}
        initial_reg_values = {
            self.project.arch.sp_offset: OffsetVal(
                Register(self.project.arch.sp_offset, self.project.arch.bits), self._sp_shift
            )
        }
        if hasattr(self.project.arch, "bp_offset") and self.project.arch.bp_offset is not None:
            regs.add(self.project.arch.bp_offset)
            initial_reg_values[self.project.arch.bp_offset] = OffsetVal(
                Register(self.project.arch.bp_offset, self.project.arch.bits), self._sp_shift
            )

        regs |= self._find_regs_compared_against_sp(self._func_graph)

        spt = self.project.analyses.StackPointerTracker(
            self.function,
            regs,
            fail_fast=self._fail_fast,
            track_memory=self._sp_tracker_track_memory,
            cross_insn_opt=False,
            initial_reg_values=initial_reg_values,
        )

        if spt.inconsistent_for(self.project.arch.sp_offset):
            l.warning("Inconsistency found during stack pointer tracking. Decompilation results might be incorrect.")
        return spt

    @timethis
    def _convert_all(self):
        """
        Convert all VEX blocks in the function graph to AIL blocks, and fill self._blocks.

        :return:    None
        """
        assert self._func_graph is not None
        assert self._blocks_by_addr_and_size is not None

        for block_node in self._func_graph.nodes():
            ail_block = self._convert(block_node)

            if type(ail_block) is ailment.Block:
                # remove constant pc assignments
                ail_block.statements = [
                    stmt
                    for stmt in ail_block.statements
                    if not (
                        isinstance(stmt, ailment.Stmt.Assignment)
                        and isinstance(stmt.dst, ailment.Expr.Register)
                        and stmt.dst.reg_offset == self.project.arch.ip_offset
                        and isinstance(stmt.src, ailment.Expr.Const)
                    )
                ]

                self._blocks_by_addr_and_size[(block_node.addr, block_node.size)] = ail_block

    def _convert(self, block_node):
        """
        Convert a BlockNode to an AIL block.

        :param block_node:  A BlockNode instance.
        :return:            A converted AIL block.
        :rtype:             ailment.Block
        """

        if type(block_node) is not BlockNode:
            return block_node

        if block_node.size == 0:
            return ailment.Block(block_node.addr, 0, statements=[])

        block = self.project.factory.block(block_node.addr, block_node.size, cross_insn_opt=False)
        converted = self._convert_vex(block)

        # architecture-specific setup
        if block.addr == self.function.addr and self.project.arch.name in {"X86", "AMD64"}:
            # setup dflag; this is a hack for most sane ABIs. we may move this logic elsewhere if there are adversarial
            # binaries that mess with dflags and pass them across functions
            dflag_offset, dflag_size = self.project.arch.registers["d"]
            dflag = ailment.Expr.Register(
                self._ail_manager.next_atom(),
                None,
                dflag_offset,
                dflag_size * self.project.arch.byte_width,
                ins_addr=block.addr,
            )
            forward = ailment.Expr.Const(
                self._ail_manager.next_atom(), None, 1, dflag_size * self.project.arch.byte_width, ins_addr=block.addr
            )
            dflag_assignment = ailment.Stmt.Assignment(
                self._ail_manager.next_atom(), dflag, forward, ins_addr=block.addr
            )
            converted.statements.insert(0, dflag_assignment)

        return converted

    def _convert_vex(self, block):
        if block.vex.jumpkind not in {"Ijk_Call", "Ijk_Boring", "Ijk_Ret"} and not block.vex.jumpkind.startswith(
            "Ijk_Sys"
        ):
            # we don't support lifting this block. use a dummy block instead
            dirty_expr = ailment.Expr.DirtyExpression(
                self._ail_manager.next_atom,
                f"Unsupported jumpkind {block.vex.jumpkind} at address {block.addr}",
                [],
                bits=0,
            )
            statements = [
                ailment.Stmt.DirtyStatement(
                    self._ail_manager.next_atom(),
                    dirty_expr,
                    ins_addr=block.addr,
                )
            ]
            return ailment.Block(block.addr, block.size, statements=statements)

        return ailment.IRSBConverter.convert(block.vex, self._ail_manager)

    @timethis
    def _replace_single_target_indirect_transitions(self, ail_graph: networkx.DiGraph) -> networkx.DiGraph:
        """
        Remove single-target indirect jumps and calls and replace them with direct jumps or calls.
        """
        if self._cfg is None:
            return ail_graph

        for block in ail_graph.nodes():
            if not block.statements:
                continue
            last_stmt = block.statements[-1]
            if isinstance(last_stmt, ailment.Stmt.Call) and not isinstance(last_stmt.target, ailment.Expr.Const):
                # indirect call
                # consult CFG to see if this is a call with a single successor
                node = self._cfg.get_any_node(block.addr)
                if node is None:
                    continue
                successors = [
                    node
                    for node, jk in self._cfg.get_successors_and_jumpkinds(node)
                    if jk == "Ijk_Call" or jk.startswith("Ijk_Sys")
                ]
                if len(successors) == 1:
                    succ_addr = successors[0].addr
                    if not self.project.is_hooked(succ_addr) or not isinstance(
                        self.project.hooked_by(successors[0].addr), UnresolvableCallTarget
                    ):
                        # found a single successor - replace the last statement
                        assert isinstance(last_stmt.target, ailment.Expr.Expression)  # not a string
                        new_last_stmt = last_stmt.copy()
                        assert isinstance(successors[0].addr, int)
                        new_last_stmt.target = ailment.Expr.Const(None, None, successors[0].addr, last_stmt.target.bits)
                        block.statements[-1] = new_last_stmt

            elif isinstance(last_stmt, ailment.Stmt.Jump) and not isinstance(last_stmt.target, ailment.Expr.Const):
                # indirect jump
                # consult CFG to see if there is a jump with a single successor
                node = self._cfg.get_any_node(block.addr)
                if node is None:
                    continue
                successors = self._cfg.get_successors(node, excluding_fakeret=True, jumpkind="Ijk_Boring")
                if len(successors) == 1 and not isinstance(
                    self.project.hooked_by(successors[0].addr), UnresolvableJumpTarget
                ):
                    # found a single successor - replace the last statement
                    new_last_stmt = last_stmt.copy()
                    new_last_stmt.target = ailment.Expr.Const(None, None, successors[0].addr, last_stmt.target.bits)
                    block.statements[-1] = new_last_stmt

        return ail_graph

    @timethis
    def _replace_tail_jumps_with_calls(self, ail_graph: networkx.DiGraph) -> networkx.DiGraph:
        """
        Replace tail jumps them with a return statement and a call expression.
        """
        for block in list(ail_graph.nodes()):
            out_degree = ail_graph.out_degree[block]

            if out_degree != 0:
                continue

            last_stmt = block.statements[-1]
            if isinstance(last_stmt, ailment.Stmt.Jump):
                # jumping to somewhere outside the current function
                # rewrite it as a call *if and only if* the target is identified as a function
                target = last_stmt.target
                if isinstance(target, ailment.Const):
                    target_addr = target.value
                    if self.kb.functions.contains_addr(target_addr):
                        # replace the statement
                        target_func = self.kb.functions.get_by_addr(target_addr)
                        if target_func.returning and self.project.arch.ret_offset is not None:
                            ret_reg_offset = self.project.arch.ret_offset
                            ret_expr = ailment.Expr.Register(
                                None,
                                None,
                                ret_reg_offset,
                                self.project.arch.bits,
                                reg_name=self.project.arch.translate_register_name(
                                    ret_reg_offset, size=self.project.arch.bits
                                ),
                                **target.tags,
                            )
                            call_stmt = ailment.Stmt.Call(
                                None,
                                target,
                                calling_convention=None,  # target_func.calling_convention,
                                prototype=None,  # target_func.prototype,
                                ret_expr=ret_expr,
                                **last_stmt.tags,
                            )
                            block.statements[-1] = call_stmt

                            ret_stmt = ailment.Stmt.Return(None, [], **last_stmt.tags)
                            ret_block = ailment.Block(self.new_block_addr(), 1, statements=[ret_stmt])
                            ail_graph.add_edge(block, ret_block, type="fake_return")
                        else:
                            stmt = ailment.Stmt.Call(None, target, **last_stmt.tags)
                            block.statements[-1] = stmt

        return ail_graph

    def _apply_callsite_prototype_and_calling_convention(self, ail_graph: networkx.DiGraph) -> networkx.DiGraph:
        for block in ail_graph.nodes():
            if not block.statements:
                continue

            last_stmt = block.statements[-1]
            if not isinstance(last_stmt, ailment.Stmt.Call):
                continue

            cc = last_stmt.calling_convention
            prototype = last_stmt.prototype
            if cc and prototype:
                continue

            # manually-specified call-site prototype
            has_callsite_prototype = self.kb.callsite_prototypes.has_prototype(block.addr)
            if has_callsite_prototype:
                manually_specified = self.kb.callsite_prototypes.get_prototype_type(block.addr)
                if manually_specified:
                    cc = self.kb.callsite_prototypes.get_cc(block.addr)
                    prototype = self.kb.callsite_prototypes.get_prototype(block.addr)

            # function-specific prototype
            func = None
            if cc is None or prototype is None:
                target = None
                if isinstance(last_stmt.target, ailment.Expr.Const):
                    target = last_stmt.target.value

                if target is not None and target in self.kb.functions:
                    # function-specific logic when the calling target is known
                    func = self.kb.functions[target]
                    if func.prototype is None:
                        func.find_declaration()
                    cc = func.calling_convention
                    prototype = func.prototype

            # automatically recovered call-site prototype
            if (cc is None or prototype is None) and has_callsite_prototype:
                cc = self.kb.callsite_prototypes.get_cc(block.addr)
                prototype = self.kb.callsite_prototypes.get_prototype(block.addr)

            # ensure the prototype has been resolved
            if prototype is not None and func is not None:
                # make sure the function prototype is resolved.
                # TODO: Cache resolved function prototypes globally
                prototype_libname = func.prototype_libname
                if prototype_libname is not None:
                    prototype = dereference_simtype_by_lib(prototype, prototype_libname)

            if cc is None:
                l.warning("Call site %#x (callee %s) has an unknown calling convention.", block.addr, repr(func))

            new_last_stmt = last_stmt.copy()
            new_last_stmt.calling_convention = cc
            new_last_stmt.prototype = prototype
            block.statements[-1] = new_last_stmt

        return ail_graph

    @timethis
    def _make_ailgraph(self) -> networkx.DiGraph:
        return self._function_graph_to_ail_graph(self._func_graph)

    @timethis
    def _simplify_blocks(
        self,
        ail_graph: networkx.DiGraph,
        stack_pointer_tracker=None,
        cache: dict[ailment.Block, NamedTuple] | None = None,
        preserve_vvar_ids: set[int] | None = None,
        type_hints: list[tuple[atoms.VirtualVariable | atoms.MemoryLocation, str]] | None = None,
    ):
        """
        Simplify all blocks in self._blocks.

        :param ail_graph:               The AIL function graph.
        :param stack_pointer_tracker:   The RegisterDeltaTracker analysis instance.
        :param cache:                   A block-level cache that stores reaching definition analysis results and
                                        propagation results.
        :return:                        None
        """

        blocks_by_addr_and_idx: dict[tuple[int, int | None], ailment.Block] = {}

        for ail_block in ail_graph.nodes():
            simplified = self._simplify_block(
                ail_block,
                stack_pointer_tracker=stack_pointer_tracker,
                cache=cache,
                preserve_vvar_ids=preserve_vvar_ids,
                type_hints=type_hints,
            )
            key = ail_block.addr, ail_block.idx
            blocks_by_addr_and_idx[key] = simplified

        # update blocks_map to allow node_addr to node lookup
        def _replace_node_handler(node):
            key = node.addr, node.idx
            if key in blocks_by_addr_and_idx:
                return blocks_by_addr_and_idx[key]
            return None

        AILGraphWalker(ail_graph, _replace_node_handler, replace_nodes=True).walk()

        return ail_graph

    def _simplify_block(
        self,
        ail_block,
        stack_pointer_tracker=None,
        cache=None,
        preserve_vvar_ids: set[int] | None = None,
        type_hints: list[tuple[atoms.VirtualVariable | atoms.MemoryLocation, str]] | None = None,
    ):
        """
        Simplify a single AIL block.

        :param ailment.Block ail_block: The AIL block to simplify.
        :param stack_pointer_tracker:   The RegisterDeltaTracker analysis instance.
        :return:                        A simplified AIL block.
        """

        cached_rd, cached_prop = None, None
        cache_item = None
        cache_key = ail_block.addr, ail_block.idx
        if cache:
            cache_item = cache.get(cache_key, None)
            if cache_item:
                # cache hit
                cached_rd = cache_item.rd
                cached_prop = cache_item.prop

        simp = self.project.analyses.AILBlockSimplifier(
            ail_block,
            self.function.addr,
            fail_fast=self._fail_fast,
            stack_pointer_tracker=stack_pointer_tracker,
            peephole_optimizations=self.peephole_optimizations,
            cached_reaching_definitions=cached_rd,
            cached_propagator=cached_prop,
            preserve_vvar_ids=preserve_vvar_ids,
            type_hints=type_hints,
        )
        # update the cache
        if cache is not None:
            if cache_item:
                del cache[cache_key]
            cache[cache_key] = BlockCache(simp._reaching_definitions, simp._propagator)
        return simp.result_block

    @timethis
    def _simplify_function(
        self,
        ail_graph,
        remove_dead_memdefs=False,
        stack_arg_offsets=None,
        unify_variables=False,
        max_iterations: int = 8,
        narrow_expressions=False,
        only_consts=False,
        fold_callexprs_into_conditions=False,
        rewrite_ccalls=True,
        removed_vvar_ids: set[int] | None = None,
        arg_vvars: dict[int, tuple[ailment.Expr.VirtualVariable, SimVariable]] | None = None,
        preserve_vvar_ids: set[int] | None = None,
    ) -> None:
        """
        Simplify the entire function until it reaches a fixed point.
        """

        for idx in range(max_iterations):
            simplified = self._simplify_function_once(
                ail_graph,
                remove_dead_memdefs=remove_dead_memdefs,
                unify_variables=unify_variables,
                stack_arg_offsets=stack_arg_offsets,
                # only narrow once
                narrow_expressions=narrow_expressions and idx == 0,
                only_consts=only_consts,
                fold_callexprs_into_conditions=fold_callexprs_into_conditions,
                rewrite_ccalls=rewrite_ccalls,
                removed_vvar_ids=removed_vvar_ids,
                arg_vvars=arg_vvars,
                preserve_vvar_ids=preserve_vvar_ids,
            )
            if not simplified:
                break

    @timethis
    def _simplify_function_once(
        self,
        ail_graph,
        remove_dead_memdefs=False,
        stack_arg_offsets=None,
        unify_variables=False,
        narrow_expressions=False,
        only_consts=False,
        fold_callexprs_into_conditions=False,
        rewrite_ccalls=True,
        removed_vvar_ids: set[int] | None = None,
        arg_vvars: dict[int, tuple[ailment.Expr.VirtualVariable, SimVariable]] | None = None,
        preserve_vvar_ids: set[int] | None = None,
    ):
        """
        Simplify the entire function once.

        :return:    None
        """

        simp = self.project.analyses.AILSimplifier(
            self.function,
            fail_fast=self._fail_fast,
            func_graph=ail_graph,
            remove_dead_memdefs=remove_dead_memdefs,
            unify_variables=unify_variables,
            stack_arg_offsets=stack_arg_offsets,
            ail_manager=self._ail_manager,
            gp=self.function.info.get("gp", None) if self.project.arch.name in {"MIPS32", "MIPS64"} else None,
            narrow_expressions=narrow_expressions,
            only_consts=only_consts,
            fold_callexprs_into_conditions=fold_callexprs_into_conditions,
            use_callee_saved_regs_at_return=not self._register_save_areas_removed,
            rewrite_ccalls=rewrite_ccalls,
            removed_vvar_ids=removed_vvar_ids,
            arg_vvars=arg_vvars,
            secondary_stackvars=self.secondary_stackvars,
            avoid_vvar_ids=preserve_vvar_ids,
        )
        # cache the simplifier's RDA analysis
        self.reaching_definitions = simp._reaching_definitions

        # the function graph has been updated at this point
        return simp.simplified

    @timethis
    def _run_simplification_passes(
        self,
        ail_graph,
        stage: OptimizationPassStage = OptimizationPassStage.AFTER_GLOBAL_SIMPLIFICATION,
        variable_kb=None,
        stack_items: dict[int, StackItem] | None = None,
        stack_pointer_tracker=None,
        **kwargs,
    ):
        addr_and_idx_to_blocks: dict[tuple[int, int | None], ailment.Block] = {}
        addr_to_blocks: dict[int, set[ailment.Block]] = defaultdict(set)

        # update blocks_map to allow node_addr to node lookup
        def _updatedict_handler(node):
            addr_and_idx_to_blocks[(node.addr, node.idx)] = node
            addr_to_blocks[node.addr].add(node)

        AILGraphWalker(ail_graph, _updatedict_handler).walk()

        # Run each pass
        for pass_ in self._optimization_passes:
            if stage != pass_.STAGE:
                continue

            if pass_ in DUPLICATING_OPTS + CONDENSING_OPTS and self.unoptimized_graph is None:
                # we should save a copy at the first time any optimization that could alter the structure
                # of the graph is applied
                self.unoptimized_graph = self._copy_graph(ail_graph)

            pass_ = timethis(pass_)
            a = pass_(
                self.function,
                blocks_by_addr=addr_to_blocks,
                blocks_by_addr_and_idx=addr_and_idx_to_blocks,
                graph=ail_graph,
                variable_kb=variable_kb,
                vvar_id_start=self.vvar_id_start,
                entry_node_addr=self.entry_node_addr,
                scratch=self.optimization_scratch,
                force_loop_single_exit=self._force_loop_single_exit,
                complete_successors=self._complete_successors,
                stack_pointer_tracker=stack_pointer_tracker,
                **kwargs,
            )
            if a.out_graph:
                # use the new graph
                ail_graph = a.out_graph
                if isinstance(a, RegisterSaveAreaSimplifier):
                    # register save area has been removed - we should no longer use callee-saved registers in RDA
                    self._register_save_areas_removed = True
                    # clear the cached RDA result
                    self.reaching_definitions = None
                self.vvar_id_start = a.vvar_id_start
            if stack_items is not None and a.stack_items:
                stack_items.update(a.stack_items)

        return ail_graph

    @timethis
    def _create_function_argument_vvars(self, arg_list) -> dict[int, tuple[ailment.Expr.VirtualVariable, SimVariable]]:
        arg_vvars = {}
        for arg in arg_list:
            if isinstance(arg, SimRegisterVariable):
                # get the full register if needed
                arg_vvar = ailment.Expr.VirtualVariable(
                    self._ail_manager.next_atom(),
                    self.vvar_id_start,
                    arg.bits,
                    ailment.Expr.VirtualVariableCategory.PARAMETER,
                    oident=(ailment.Expr.VirtualVariableCategory.REGISTER, arg.reg),
                    ins_addr=self.function.addr,
                    vex_block_addr=self.function.addr,
                )
                self.vvar_id_start += 1
                arg_vvars[arg_vvar.varid] = arg_vvar, arg
            elif isinstance(arg, SimStackVariable):
                arg_vvar = ailment.Expr.VirtualVariable(
                    self._ail_manager.next_atom(),
                    self.vvar_id_start,
                    arg.bits,
                    ailment.Expr.VirtualVariableCategory.PARAMETER,
                    oident=(ailment.Expr.VirtualVariableCategory.STACK, arg.offset),
                    ins_addr=self.function.addr,
                    vex_block_addr=self.function.addr,
                )
                self.vvar_id_start += 1
                arg_vvars[arg_vvar.varid] = arg_vvar, arg

        return arg_vvars

    @timethis
    def _transform_to_ssa_level0(
        self, ail_graph: networkx.DiGraph, func_args: set[ailment.Expr.VirtualVariable]
    ) -> networkx.DiGraph:
        ssailification = self.project.analyses[Ssailification].prep(fail_fast=self._fail_fast)(
            self.function,
            ail_graph,
            entry=next(iter(bb for bb in ail_graph if (bb.addr, bb.idx) == self.entry_node_addr)),
            ail_manager=self._ail_manager,
            ssa_stackvars=False,
            func_args=func_args,
            vvar_id_start=self.vvar_id_start,
        )
        self.vvar_id_start = ssailification.max_vvar_id + 1
        assert ssailification.out_graph is not None
        return ssailification.out_graph

    @timethis
    def _transform_to_ssa_level1(
        self, ail_graph: networkx.DiGraph, func_args: set[ailment.Expr.VirtualVariable]
    ) -> networkx.DiGraph:
        ssailification = self.project.analyses.Ssailification(
            self.function,
            ail_graph,
            fail_fast=self._fail_fast,
            entry=next(iter(bb for bb in ail_graph if (bb.addr, bb.idx) == self.entry_node_addr)),
            ail_manager=self._ail_manager,
            ssa_tmps=True,
            ssa_stackvars=True,
            func_args=func_args,
            vvar_id_start=self.vvar_id_start,
        )
        self.vvar_id_start = ssailification.max_vvar_id + 1
        self.secondary_stackvars = ssailification.secondary_stackvars
        return ssailification.out_graph

    @timethis
    def _collect_dephi_vvar_mapping_and_rewrite_blocks(
        self, ail_graph: networkx.DiGraph, arg_vvars: dict[int, tuple[ailment.Expr.VirtualVariable, SimVariable]]
    ) -> tuple[dict[int, int], set[int]]:
        dephication = self.project.analyses.GraphDephicationVVarMapping(
            self.function,
            ail_graph,
            fail_fast=self._fail_fast,
            entry=next(iter(bb for bb in ail_graph if (bb.addr, bb.idx) == self.entry_node_addr)),
            vvar_id_start=self.vvar_id_start,
            arg_vvars=[arg_vvar for arg_vvar, _ in arg_vvars.values()],
        )
        self.vvar_id_start = dephication.vvar_id_start + 1
        return dephication.vvar_to_vvar_mapping, dephication.copied_vvar_ids

    @timethis
    def _make_argument_list(self) -> list[SimVariable]:
        if self.function.calling_convention is not None and self.function.prototype is not None:
            args: list[SimFunctionArgument] = self.function.calling_convention.arg_locs(self.function.prototype)
            arg_vars: list[SimVariable] = []
            if args:
                arg_names = self.function.prototype.arg_names or [f"a{i}" for i in range(len(args))]
                for idx, arg in enumerate(args):
                    if isinstance(arg, SimRegArg):
                        argvar = SimRegisterVariable(
                            self.project.arch.registers[arg.reg_name][0],
                            arg.size,
                            ident=f"arg_{idx}",
                            name=arg_names[idx],
                            region=self.function.addr,
                        )
                    elif isinstance(arg, SimStackArg):
                        argvar = SimStackVariable(
                            arg.stack_offset,
                            arg.size,
                            base="bp",
                            ident=f"arg_{idx}",
                            name=arg_names[idx],
                            region=self.function.addr,
                        )
                    else:
                        argvar = SimVariable(
                            ident=f"arg_{idx}",
                            name=arg_names[idx],
                            region=self.function.addr,
                            size=arg.size,
                        )
                    arg_vars.append(argvar)
            return arg_vars
        return []

    @timethis
    def _make_callsites(
        self,
        ail_graph,
        func_args: set[ailment.Expr.VirtualVariable],
        stack_pointer_tracker=None,
        preserve_vvar_ids: set[int] | None = None,
    ):
        """
        Simplify all function call statements.
        """

        # Computing reaching definitions
        rd = self.project.analyses.SReachingDefinitions(
            subject=self.function,
            func_graph=ail_graph,
            func_args=func_args,
            fail_fast=self._fail_fast,
            # use_callee_saved_regs_at_return=not self._register_save_areas_removed,  FIXME
        )

        class TempClass:  # pylint:disable=missing-class-docstring
            stack_arg_offsets = set()
            removed_vvar_ids = set()

        def _handler(block):
            csm = self.project.analyses.AILCallSiteMaker(
                block,
                fail_fast=self._fail_fast,
                reaching_definitions=rd,
                stack_pointer_tracker=stack_pointer_tracker,
                ail_manager=self._ail_manager,
            )
            if csm.stack_arg_offsets is not None:
                TempClass.stack_arg_offsets |= csm.stack_arg_offsets
            if csm.removed_vvar_ids:
                TempClass.removed_vvar_ids |= csm.removed_vvar_ids
            if csm.result_block and csm.result_block != block:
                ail_block = csm.result_block
                simp = self.project.analyses.AILBlockSimplifier(
                    ail_block,
                    self.function.addr,
                    fail_fast=self._fail_fast,
                    stack_pointer_tracker=stack_pointer_tracker,
                    peephole_optimizations=self.peephole_optimizations,
                    preserve_vvar_ids=preserve_vvar_ids,
                )
                return simp.result_block
            return None

        # rewriting call-sites at this point, pre-inlining, causes issues with incorrect call signatures
        if not self._inlining_parents:
            AILGraphWalker(ail_graph, _handler, replace_nodes=True).walk()

        return ail_graph, TempClass.stack_arg_offsets, TempClass.removed_vvar_ids

    @timethis
    def _make_returns(self, ail_graph: networkx.DiGraph) -> networkx.DiGraph:
        """
        Work on each return statement and fill in its return expressions.
        """
        if self.function.calling_convention is None:
            # unknown calling convention. cannot do much about return expressions.
            return ail_graph

        ReturnMaker(self._ail_manager, self.project.arch, self.function, ail_graph)

        return ail_graph

    @timethis
    def _make_function_prototype(self, arg_list: list[SimVariable], variable_kb):
        if self.function.prototype is not None:
            if not self.function.is_prototype_guessed:
                # do not overwrite an existing function prototype
                # if you want to re-generate the prototype, clear the existing one first
                return
            if isinstance(self.function.prototype.returnty, SimTypeFloat) or any(
                isinstance(arg, SimTypeFloat) for arg in self.function.prototype.args
            ):
                # Type inference does not yet support floating point variables, but calling convention analysis does
                # FIXME: remove this branch once type inference supports floating point variables
                return

        variables = variable_kb.variables[self.function.addr]
        func_args = []
        for arg in arg_list:
            func_arg = None
            arg_ty = variables.get_variable_type(arg)
            if arg_ty is None:
                # determine type based on size
                if isinstance(arg, (SimRegisterVariable, SimStackVariable)):
                    if arg.size == 1:
                        func_arg = SimTypeChar()
                    elif arg.size == 2:
                        func_arg = SimTypeShort()
                    elif arg.size == 4:
                        func_arg = SimTypeInt()
                    elif arg.size == 8:
                        func_arg = SimTypeLongLong()
                    else:
                        l.warning("Unsupported argument size %d.", arg.size)
            else:
                func_arg = arg_ty

            func_args.append(func_arg)

        if self.function.prototype is not None and self.function.prototype.returnty is not None:
            returnty = self.function.prototype.returnty
        else:
            returnty = SimTypeInt()

        self.function.prototype = SimTypeFunction(func_args, returnty).with_arch(self.project.arch)
        self.function.is_prototype_guessed = False

    @timethis
    def _recover_and_link_variables(
        self,
        ail_graph,
        arg_list: list,
        arg_vvars: dict[int, tuple[ailment.Expr.VirtualVariable, SimVariable]],
        vvar2vvar: dict[int, int],
        type_hints: list[tuple[atoms.VirtualVariable | atoms.MemoryLocation, str]],
    ):
        # variable recovery
        tmp_kb = KnowledgeBase(self.project) if self.variable_kb is None else self.variable_kb
        tmp_kb.functions = self.kb.functions
        vr = self.project.analyses.VariableRecoveryFast(
            self.function,  # pylint:disable=unused-variable
            fail_fast=self._fail_fast,  # type:ignore
            func_graph=ail_graph,
            kb=tmp_kb,  # type:ignore
            track_sp=False,
            func_args=arg_list,
            unify_variables=False,
            func_arg_vvars=arg_vvars,
            vvar_to_vvar=vvar2vvar,
            type_hints=type_hints,
        )
        # get ground-truth types
        var_manager = tmp_kb.variables[self.function.addr]
        groundtruth = {}
        for variable in var_manager.variables_with_manual_types:
            vartype = var_manager.variable_to_types.get(variable, None)
            if vartype is not None:
                for tv in vr.var_to_typevars[variable]:
                    groundtruth[tv] = vartype
        # get maximum sizes of each stack variable, regardless of its original type
        stackvar_max_sizes = var_manager.get_stackvar_max_sizes(self.stack_items)
        tv_max_sizes = {}
        for v, s in stackvar_max_sizes.items():
            assert isinstance(v, SimStackVariable)
            if v in vr.var_to_typevars:
                for tv in vr.var_to_typevars[v]:
                    tv_max_sizes[tv] = s
            if v.offset in vr.stack_offset_typevars:
                tv = vr.stack_offset_typevars[v.offset]
                tv_max_sizes[tv] = s
        # clean up existing types for this function
        var_manager.remove_types()
        # TODO: Type inference for global variables
        # run type inference
        if self._must_struct:
            must_struct = set()
            for var, typevars in vr.var_to_typevars.items():
                if var.ident in self._must_struct:
                    must_struct |= typevars
        else:
            must_struct = None
        total_type_constraints = sum(len(tc) for tc in vr.type_constraints.values()) if vr.type_constraints else 0
        if total_type_constraints > self._max_type_constraints:
            l.warning(
                "The number of type constraints (%d) is greater than the threshold (%d). Skipping type inference.",
                total_type_constraints,
                self._max_type_constraints,
            )
        else:
            try:
                tp = self.project.analyses.Typehoon(
                    vr.type_constraints,
                    vr.func_typevar,
                    kb=tmp_kb,
                    fail_fast=self._fail_fast,
                    var_mapping=vr.var_to_typevars,
                    stack_offset_tvs=vr.stack_offset_typevars,
                    must_struct=must_struct,
                    ground_truth=groundtruth,
                    stackvar_max_sizes=tv_max_sizes,
                )
                # tp.pp_constraints()
                # tp.pp_solution()
                tp.update_variable_types(
                    self.function.addr,
                    {
                        v: t
                        for v, t in vr.var_to_typevars.items()
                        if isinstance(v, (SimRegisterVariable, SimStackVariable))
                    },
                    vr.stack_offset_typevars,
                )
                tp.update_variable_types(
                    "global",
                    {
                        v: t
                        for v, t in vr.var_to_typevars.items()
                        if isinstance(v, SimMemoryVariable) and not isinstance(v, SimStackVariable)
                    },
                )
                self.typehoon = tp
            except Exception:  # pylint:disable=broad-except
                if self._fail_fast:
                    raise
                l.warning(
                    "Typehoon analysis failed. Variables will not have types. Please report to GitHub.", exc_info=True
                )

        # for any left-over variables, assign Bottom type (which will get "corrected" into a default type in
        # VariableManager)
        bottype = SimTypeBottom().with_arch(self.project.arch)
        for var in var_manager._variables:
            if var not in var_manager.variable_to_types:
                var_manager.set_variable_type(var, bottype)

        # Unify SSA variables
        tmp_kb.variables.global_manager.assign_variable_names(labels=self.kb.labels, types={SimMemoryVariable})
        liveness = self.project.analyses.SLiveness(
            self.function,
            func_graph=ail_graph,
            entry=next(iter(bb for bb in ail_graph if (bb.addr, bb.idx) == self.entry_node_addr)),
            arg_vvars=[vvar for vvar, _ in arg_vvars.values()],
        )
        var_manager.unify_variables(interference=liveness.interference_graph())
        var_manager.assign_unified_variable_names(
            labels=self.kb.labels,
            arg_names=self.function.prototype.arg_names if self.function.prototype else None,
            reset=self._reset_variable_names,
            func_blocks=list(ail_graph),
        )

        # Link variables and struct member information to every statement and expression
        for block in ail_graph.nodes():
            self._link_variables_on_block(block, tmp_kb)

        if self._cache is not None:
            self._cache.type_constraints = vr.type_constraints
            self._cache.func_typevar = vr.func_typevar
            self._cache.var_to_typevar = vr.var_to_typevars

        return tmp_kb

    def _link_variables_on_block(self, block, kb):
        """
        Link atoms (AIL expressions) in the given block to corresponding variables identified previously.

        :param ailment.Block block: The AIL block to work on.
        :return:                    None
        """

        variable_manager = kb.variables[self.function.addr]
        global_variables = kb.variables["global"]

        for stmt_idx, stmt in enumerate(block.statements):
            stmt_type = type(stmt)
            if stmt_type is ailment.Stmt.Store:
                # find a memory variable
                mem_vars = variable_manager.find_variables_by_atom(block.addr, stmt_idx, stmt, block_idx=block.idx)
                if len(mem_vars) == 1:
                    stmt.variable, stmt.offset = next(iter(mem_vars))
                else:
                    # check if the dest address is a variable
                    stmt: ailment.Stmt.Store
                    # special handling for constant addresses
                    if isinstance(stmt.addr, ailment.Expr.Const):
                        # global variable?
                        variables = global_variables.get_global_variables(stmt.addr.value)
                        if variables:
                            var = next(iter(variables))
                            stmt.variable = var
                            stmt.offset = 0
                    else:
                        self._link_variables_on_expr(
                            variable_manager, global_variables, block, stmt_idx, stmt, stmt.addr
                        )
                self._link_variables_on_expr(variable_manager, global_variables, block, stmt_idx, stmt, stmt.data)

                # link struct member info
                if isinstance(stmt.variable, SimStackVariable):
                    off = stmt.variable.offset
                    if off in variable_manager.stack_offset_to_struct_member_info:
                        stmt.tags["struct_member_info"] = variable_manager.stack_offset_to_struct_member_info[off]

            elif stmt_type is ailment.Stmt.Assignment or stmt_type is ailment.Stmt.WeakAssignment:
                self._link_variables_on_expr(variable_manager, global_variables, block, stmt_idx, stmt, stmt.dst)
                self._link_variables_on_expr(variable_manager, global_variables, block, stmt_idx, stmt, stmt.src)

            elif stmt_type is ailment.Stmt.CAS:
                for expr in [
                    stmt.addr,
                    stmt.data_lo,
                    stmt.data_hi,
                    stmt.expd_lo,
                    stmt.expd_hi,
                    stmt.old_lo,
                    stmt.old_hi,
                ]:
                    if expr is not None:
                        self._link_variables_on_expr(variable_manager, global_variables, block, stmt_idx, stmt, expr)

            elif stmt_type is ailment.Stmt.ConditionalJump:
                self._link_variables_on_expr(variable_manager, global_variables, block, stmt_idx, stmt, stmt.condition)

            elif stmt_type is ailment.Stmt.Jump and not isinstance(stmt.target, ailment.Expr.Const):
                self._link_variables_on_expr(variable_manager, global_variables, block, stmt_idx, stmt, stmt.target)

            elif stmt_type is ailment.Stmt.Call:
                self._link_variables_on_call(variable_manager, global_variables, block, stmt_idx, stmt, is_expr=False)

            elif stmt_type is ailment.Stmt.Return:
                assert isinstance(stmt, ailment.Stmt.Return)
                self._link_variables_on_return(variable_manager, global_variables, block, stmt_idx, stmt)

    def _link_variables_on_return(
        self, variable_manager, global_variables, block: ailment.Block, stmt_idx: int, stmt: ailment.Stmt.Return
    ):
        if stmt.ret_exprs:
            for ret_expr in stmt.ret_exprs:
                self._link_variables_on_expr(variable_manager, global_variables, block, stmt_idx, stmt, ret_expr)

    def _link_variables_on_call(self, variable_manager, global_variables, block, stmt_idx, stmt, is_expr=False):
        if not isinstance(stmt.target, ailment.Expr.Const):
            self._link_variables_on_expr(variable_manager, global_variables, block, stmt_idx, stmt, stmt.target)
        if stmt.args:
            for arg in stmt.args:
                self._link_variables_on_expr(variable_manager, global_variables, block, stmt_idx, stmt, arg)
        if not is_expr and stmt.ret_expr:
            self._link_variables_on_expr(variable_manager, global_variables, block, stmt_idx, stmt, stmt.ret_expr)

    def _link_variables_on_expr(self, variable_manager, global_variables, block, stmt_idx, stmt, expr):
        """
        Link atoms (AIL expressions) in the given expression to corresponding variables identified previously.

        :param variable_manager:    Variable manager of the function.
        :param ailment.Block block: AIL block.
        :param int stmt_idx:        ID of the statement.
        :param stmt:                The AIL statement that `expr` belongs to.
        :param expr:                The AIl expression to work on.
        :return:                    None
        """

        if type(expr) is ailment.Expr.Register:
            # find a register variable
            reg_vars = variable_manager.find_variables_by_atom(block.addr, stmt_idx, expr, block_idx=block.idx)
            final_reg_vars = set()
            if len(reg_vars) > 1:
                # take phi variables
                for reg_var in reg_vars:
                    if variable_manager.is_phi_variable(reg_var[0]):
                        final_reg_vars.add(reg_var)
            else:
                final_reg_vars = reg_vars
            if len(final_reg_vars) >= 1:
                reg_var, offset = next(iter(final_reg_vars))
                expr.variable = reg_var
                expr.variable_offset = offset

        elif type(expr) is ailment.Expr.VirtualVariable:
            vars_ = variable_manager.find_variables_by_atom(block.addr, stmt_idx, expr, block_idx=block.idx)
            if len(vars_) >= 1:
                var, offset = next(iter(vars_))
                expr.variable = var
                expr.variable_offset = offset

                if isinstance(expr, ailment.Expr.VirtualVariable) and expr.was_stack:
                    off = expr.stack_offset
                    if off in variable_manager.stack_offset_to_struct_member_info:
                        expr.tags["struct_member_info"] = variable_manager.stack_offset_to_struct_member_info[off]

        elif type(expr) is ailment.Expr.Load:
            variables = variable_manager.find_variables_by_atom(block.addr, stmt_idx, expr, block_idx=block.idx)
            if len(variables) == 0:
                # if it's a constant addr, maybe it's referencing an extern location
                base_addr, offset = self.parse_variable_addr(expr.addr)
                if offset is not None and isinstance(offset, ailment.Expr.Expression):
                    self._link_variables_on_expr(variable_manager, global_variables, block, stmt_idx, stmt, offset)
                if base_addr is not None:
                    self._link_variables_on_expr(variable_manager, global_variables, block, stmt_idx, stmt, base_addr)

                # if we are accessing the variable directly (offset == 0), we link the variable onto this expression
                if (
                    offset == 0 or (isinstance(offset, ailment.Expr.Const) and offset.value == 0)
                ) and "reference_variable" in base_addr.tags:
                    expr.variable = base_addr.reference_variable
                    expr.variable_offset = base_addr.reference_variable_offset

                if base_addr is None and offset is None:
                    # this is a local variable
                    self._link_variables_on_expr(variable_manager, global_variables, block, stmt_idx, stmt, expr.addr)
                    if "reference_variable" in expr.addr.tags and expr.addr.reference_variable is not None:
                        # copy over the variable to this expr since the variable on a constant is supposed to be a
                        # reference variable.
                        expr.variable = expr.addr.reference_variable
                        expr.variable_offset = expr.addr.reference_variable_offset
            else:
                if len(variables) > 1:
                    l.error(
                        "More than one variable are available for atom %s. Consider fixing it using phi nodes.", expr
                    )
                var, offset = next(iter(variables))
                expr.variable = var
                expr.variable_offset = offset

                if isinstance(var, SimStackVariable):
                    off = var.offset
                    if off in variable_manager.stack_offset_to_struct_member_info:
                        expr.tags["struct_member_info"] = variable_manager.stack_offset_to_struct_member_info[off]

        elif type(expr) is ailment.Expr.BinaryOp:
            variables = variable_manager.find_variables_by_atom(block.addr, stmt_idx, expr, block_idx=block.idx)
            if len(variables) >= 1:
                var, offset = next(iter(variables))
                expr.variable = var
                expr.variable_offset = offset
            else:
                self._link_variables_on_expr(
                    variable_manager, global_variables, block, stmt_idx, stmt, expr.operands[0]
                )
                self._link_variables_on_expr(
                    variable_manager, global_variables, block, stmt_idx, stmt, expr.operands[1]
                )

        elif type(expr) is ailment.Expr.UnaryOp:
            variables = variable_manager.find_variables_by_atom(block.addr, stmt_idx, expr, block_idx=block.idx)
            if len(variables) >= 1:
                var, offset = next(iter(variables))
                expr.variable = var
                expr.variable_offset = offset
            else:
                self._link_variables_on_expr(variable_manager, global_variables, block, stmt_idx, stmt, expr.operand)

        elif type(expr) in {ailment.Expr.Convert, ailment.Expr.Reinterpret}:
            self._link_variables_on_expr(variable_manager, global_variables, block, stmt_idx, stmt, expr.operand)

        elif type(expr) is ailment.Expr.ITE:
            variables = variable_manager.find_variables_by_atom(block.addr, stmt_idx, expr, block_idx=block.idx)
            if len(variables) >= 1:
                var, offset = next(iter(variables))
                expr.variable = var
                expr.variable_offset = offset
            else:
                self._link_variables_on_expr(variable_manager, global_variables, block, stmt_idx, stmt, expr.cond)
                self._link_variables_on_expr(variable_manager, global_variables, block, stmt_idx, stmt, expr.iftrue)
                self._link_variables_on_expr(variable_manager, global_variables, block, stmt_idx, stmt, expr.iffalse)

        elif isinstance(expr, ailment.Expr.BasePointerOffset):
            variables = variable_manager.find_variables_by_atom(block.addr, stmt_idx, expr, block_idx=block.idx)
            if len(variables) >= 1:
                var, offset = next(iter(variables))
                expr.variable = var
                expr.variable_offset = offset

        elif isinstance(expr, ailment.Expr.Const) and expr.is_int:
            # custom string?
            if hasattr(expr, "custom_string") and expr.custom_string is True:
                s = self.kb.custom_strings[expr.value]
                expr.tags["reference_values"] = {
                    SimTypePointer(SimTypeChar().with_arch(self.project.arch)).with_arch(self.project.arch): s.decode(
                        "latin-1"
                    ),
                }
            else:
                # global variable?
                global_vars = global_variables.get_global_variables(expr.value)
                # detect if there is a related symbol
                if not global_vars and self.project.loader.find_object_containing(expr.value):
                    symbol = self.project.loader.find_symbol(expr.value)
                    if symbol is not None:
                        # Create a new global variable if there isn't one already
                        global_vars = global_variables.get_global_variables(symbol.rebased_addr)
                        if not global_vars:
                            global_var = SimMemoryVariable(symbol.rebased_addr, symbol.size, name=symbol.name)
                            global_variables.add_variable("global", global_var.addr, global_var)
                            global_vars = {global_var}
                if global_vars:
                    global_var = next(iter(global_vars))
                    expr.tags["reference_variable"] = global_var
                    expr.tags["reference_variable_offset"] = 0

        elif isinstance(expr, ailment.Stmt.Call):
            self._link_variables_on_call(variable_manager, global_variables, block, stmt_idx, expr, is_expr=True)

        elif isinstance(expr, ailment.Expr.VEXCCallExpression):
            for operand in expr.operands:
                self._link_variables_on_expr(variable_manager, global_variables, block, stmt_idx, stmt, operand)

        elif isinstance(expr, ailment.Expr.DirtyExpression):
            for operand in expr.operands:
                self._link_variables_on_expr(variable_manager, global_variables, block, stmt_idx, stmt, operand)
            if expr.maddr:
                self._link_variables_on_expr(variable_manager, global_variables, block, stmt_idx, stmt, expr.maddr)
            if expr.guard:
                self._link_variables_on_expr(variable_manager, global_variables, block, stmt_idx, stmt, expr.guard)

        elif isinstance(expr, ailment.Expr.Phi):
            for _, vvar in expr.src_and_vvars:
                if vvar is not None:
                    self._link_variables_on_expr(variable_manager, global_variables, block, stmt_idx, stmt, vvar)

    def _function_graph_to_ail_graph(self, func_graph, blocks_by_addr_and_size=None):
        if blocks_by_addr_and_size is None:
            blocks_by_addr_and_size = self._blocks_by_addr_and_size
        assert blocks_by_addr_and_size is not None

        graph = networkx.DiGraph()

        entry_node = next(iter(node for node in func_graph if node.addr == self.entry_node_addr[0]), None)
        if entry_node is None:
            raise AngrDecompilationError(
                f"Entry node with address {self.entry_node_addr[0]:#x} not found in the function graph"
            )

        # add the entry node into the graph
        ail_block = blocks_by_addr_and_size.get((entry_node.addr, entry_node.size))
        if ail_block is None:
            raise AngrDecompilationError(f"AIL block at address {entry_node.addr:#x} not found")
        graph.add_node(ail_block)

        # get all descendants and only include them in the AIL graph.
        # this way all unreachable blocks will be excluded from the AIL graph.
        descendants = networkx.descendants(func_graph, entry_node) | {entry_node}
        for src_node, dst_node, data in networkx.subgraph_view(
            func_graph, filter_node=lambda n: n in descendants
        ).edges(data=True):
            src = blocks_by_addr_and_size.get((src_node.addr, src_node.size))
            dst = blocks_by_addr_and_size.get((dst_node.addr, dst_node.size))

            if src is not None and dst is not None:
                graph.add_edge(src, dst, **data)

        return graph

    @staticmethod
    def _duplicate_orphaned_cond_jumps(ail_graph) -> networkx.DiGraph:
        """
        Find conditional jumps that are orphaned (e.g., being the only instruction of the block). If these blocks have
        multiple predecessors, duplicate them to all predecessors. This is a workaround for cases where these
        conditional jumps rely on comparisons in more than one predecessor and we cannot resolve ccalls into
        comparisons.

        This pass runs before any SSA transformations.

        # 140017162     jz      short 1400171e1
        """

        for block in list(ail_graph):
            if len(block.statements) > 1 and block.statements[0].ins_addr == block.statements[-1].ins_addr:
                preds = list(ail_graph.predecessors(block))
                if len(preds) > 1 and block not in preds:
                    has_ccall = any(
                        isinstance(stmt, ailment.Stmt.Assignment)
                        and isinstance(stmt.src, ailment.Expr.VEXCCallExpression)
                        for stmt in block.statements
                    )
                    if has_ccall:
                        # duplicate this block to its predecessors!
                        preds = sorted(preds, key=lambda x: x.addr)
                        succs = sorted(ail_graph.successors(block), key=lambda x: x.addr)
                        # FIXME: We should track block IDs globally and ensure block IDs do not collide
                        block_idx_start = block.idx + 1 if block.idx is not None else 1
                        for pred in preds[1:]:
                            ail_graph.remove_edge(pred, block)
                            new_block = block.copy()
                            new_block.idx = block_idx_start
                            block_idx_start += 1
                            ail_graph.add_edge(pred, new_block)
                            for succ in succs:
                                ail_graph.add_edge(new_block, succ if succ is not block else new_block)

        return ail_graph

    def _rewrite_jump_rax_calls(self, ail_graph: networkx.DiGraph) -> networkx.DiGraph:
        """
        Rewrite calls to special functions (e.g., guard_dispatch_icall_nop) into `call rax`.
        """

        if self.project.arch.name != "AMD64":
            return ail_graph
        if self._cfg is None:
            return ail_graph

        for block in ail_graph:
            if not block.statements:
                continue
            assert block.addr is not None
            last_stmt = block.statements[-1]
            if isinstance(last_stmt, ailment.Stmt.Call):
                # we can't examine the call target at this point because constant propagation hasn't run yet; we consult
                # the CFG instead
                callsite_node = self._cfg.get_any_node(block.addr, anyaddr=True)
                if callsite_node is None:
                    break
                callees = self._cfg.get_successors(callsite_node, jumpkind="Ijk_Call")
                if len(callees) != 1:
                    break
                callee = callees[0].addr
                if self.kb.functions.contains_addr(callee):
                    callee_func = self.kb.functions.get_by_addr(callee)
                    if callee_func.info.get("jmp_rax", False) is True:
                        # rewrite this statement into Call(rax)
                        call_stmt = last_stmt.copy()
                        call_stmt.target = ailment.Expr.Register(
                            self._ail_manager.next_atom(),
                            None,
                            self.project.arch.registers["rax"][0],
                            64,
                            ins_addr=call_stmt.ins_addr,
                        )
                        block.statements[-1] = call_stmt

        return ail_graph

    def _rewrite_ite_expressions(self, ail_graph):
        cfg = self._cfg
        for block in list(ail_graph):
            if cfg is not None and block.addr in cfg.jump_tables:
                continue

            ite_ins_addrs = []
            cas_ins_addrs = set()
            for stmt in block.statements:
                if isinstance(stmt, ailment.Stmt.CAS):
                    # we do not rewrite ITE statements that are caused by CAS statements
                    cas_ins_addrs.add(stmt.ins_addr)
                elif (
                    isinstance(stmt, ailment.Stmt.Assignment)
                    and isinstance(stmt.src, ailment.Expr.ITE)
                    and stmt.ins_addr not in ite_ins_addrs
                    and stmt.ins_addr not in cas_ins_addrs
                ):
                    ite_ins_addrs.append(stmt.ins_addr)

            if ite_ins_addrs:
                block_addr = block.addr
                for ite_ins_addr in ite_ins_addrs:
                    block_addr = self._create_triangle_for_ite_expression(ail_graph, block_addr, ite_ins_addr)
                    if block_addr is None or block_addr >= block.addr + block.original_size:
                        break

    def _create_triangle_for_ite_expression(self, ail_graph, block_addr: int, ite_ins_addr: int):
        ite_insn_only_block = self.project.factory.block(ite_ins_addr, num_inst=1)
        ite_insn_size = ite_insn_only_block.size
        assert ite_insn_size is not None
        if ite_insn_size <= 2:  # we need an address for true_block and another address for false_block
            return None
        if ite_insn_only_block.vex.exit_statements:
            return None

        # relift the head and the ITE instruction
        new_head = self.project.factory.block(
            block_addr, size=ite_ins_addr - block_addr + ite_insn_size, cross_insn_opt=False
        )
        new_head_ail = ailment.IRSBConverter.convert(new_head.vex, self._ail_manager)
        # remove all statements between the ITE expression and the very end of the block
        ite_expr_stmt_idx = None
        ite_expr_stmt = None
        for idx, stmt in enumerate(new_head_ail.statements):
            if isinstance(stmt, ailment.Stmt.Assignment) and isinstance(stmt.src, ailment.Expr.ITE):
                ite_expr_stmt_idx = idx
                ite_expr_stmt = stmt
                break
        if ite_expr_stmt_idx is None:
            return None
        assert ite_expr_stmt is not None

        ite_expr: ailment.Expr.ITE = ite_expr_stmt.src  # type: ignore
        new_head_ail.statements = new_head_ail.statements[:ite_expr_stmt_idx]
        # build the conditional jump
        true_block_addr = ite_ins_addr + 1
        false_block_addr = ite_ins_addr + 2
        cond_jump_stmt = ailment.Stmt.ConditionalJump(
            ite_expr_stmt.idx,
            ite_expr.cond,
            ailment.Expr.Const(None, None, true_block_addr, self.project.arch.bits, **ite_expr_stmt.tags),
            ailment.Expr.Const(None, None, false_block_addr, self.project.arch.bits, **ite_expr_stmt.tags),
            **ite_expr_stmt.tags,
        )
        new_head_ail.statements.append(cond_jump_stmt)

        # build the true block
        true_block = self.project.factory.block(ite_ins_addr, num_inst=1)
        true_block_ail = ailment.IRSBConverter.convert(true_block.vex, self._ail_manager)
        true_block_ail.addr = true_block_addr

        ite_expr_stmt_idx = None
        ite_expr_stmt = None
        for idx, stmt in enumerate(true_block_ail.statements):
            if isinstance(stmt, ailment.Stmt.Assignment) and isinstance(stmt.src, ailment.Expr.ITE):
                ite_expr_stmt_idx = idx
                ite_expr_stmt = stmt
                break
        if ite_expr_stmt_idx is None:
            return None
        assert ite_expr_stmt is not None

        true_block_ail.statements[ite_expr_stmt_idx] = ailment.Stmt.Assignment(
            ite_expr_stmt.idx, ite_expr_stmt.dst, ite_expr_stmt.src.iftrue, **ite_expr_stmt.tags
        )

        # build the false block
        false_block = self.project.factory.block(ite_ins_addr, num_inst=1)
        false_block_ail = ailment.IRSBConverter.convert(false_block.vex, self._ail_manager)
        false_block_ail.addr = false_block_addr

        ite_expr_stmt_idx = None
        ite_expr_stmt = None
        for idx, stmt in enumerate(false_block_ail.statements):
            if isinstance(stmt, ailment.Stmt.Assignment) and isinstance(stmt.src, ailment.Expr.ITE):
                ite_expr_stmt_idx = idx
                ite_expr_stmt = stmt
                break
        if ite_expr_stmt_idx is None:
            return None
        assert ite_expr_stmt is not None

        false_block_ail.statements[ite_expr_stmt_idx] = ailment.Stmt.Assignment(
            ite_expr_stmt.idx, ite_expr_stmt.dst, ite_expr_stmt.src.iffalse, **ite_expr_stmt.tags
        )

        original_block = next(iter(b for b in ail_graph if b.addr == block_addr))

        original_block_in_edges = list(ail_graph.in_edges(original_block, data=True))
        original_block_out_edges = list(ail_graph.out_edges(original_block, data=True))

        # build the target block if the target block does not exist in the current function
        end_block_addr = ite_ins_addr + ite_insn_size
        if block_addr < end_block_addr < block_addr + original_block.original_size:
            end_block = self.project.factory.block(
                ite_ins_addr + ite_insn_size,
                size=block_addr + original_block.original_size - (ite_ins_addr + ite_insn_size),
                cross_insn_opt=False,
            )
            end_block_ail = ailment.IRSBConverter.convert(end_block.vex, self._ail_manager)
        else:
            try:
                end_block_ail = next(iter(b for b in ail_graph if b.addr == end_block_addr))
            except StopIteration:
                return None

        # last check: if the first instruction of the end block has Sar, then we bail (due to the peephole optimization
        # SarToSignedDiv)
        for stmt in end_block_ail.statements:
            if stmt.ins_addr > end_block_ail.addr:
                break
            if (
                isinstance(stmt, ailment.Stmt.Assignment)
                and isinstance(stmt.src, ailment.Expr.BinaryOp)
                and stmt.src.op == "Sar"
            ):
                return None

        # corner-case: the last statement of original_block might have been patched by _remove_redundant_jump_blocks.
        # we detect such case and fix it in new_head_ail
        self._remove_redundant_jump_blocks_repatch_relifted_block(original_block, end_block_ail)

        ail_graph.remove_node(original_block)

        if end_block_ail not in ail_graph:
            # newly created. add it and the necessary edges into the graph
            for _, dst, data in original_block_out_edges:
                if dst is original_block:
                    ail_graph.add_edge(end_block_ail, new_head_ail, **data)
                else:
                    ail_graph.add_edge(end_block_ail, dst, **data)

        # in edges
        for src, _, data in original_block_in_edges:
            if src is original_block:
                # loop
                ail_graph.add_edge(end_block_ail, new_head_ail, **data)
            else:
                ail_graph.add_edge(src, new_head_ail, **data)

        # triangle
        ail_graph.add_edge(new_head_ail, true_block_ail)
        ail_graph.add_edge(new_head_ail, false_block_ail)
        ail_graph.add_edge(true_block_ail, end_block_ail)
        ail_graph.add_edge(false_block_ail, end_block_ail)

        return end_block_ail.addr

    def _fix_abnormal_switch_case_heads(self, ail_graph: networkx.DiGraph) -> None:
        """
        Detect the existence of switch-case heads whose indirect jump node has more than one predecessor, and attempt
        to fix those cases by altering the graph.
        """

        if self._cfg is None:
            return

        if not self._cfg.jump_tables:
            return

        node_dict: defaultdict[int, list[ailment.Block]] = defaultdict(list)
        for node in ail_graph:
            node_dict[node.addr].append(node)

        candidates = []
        for block_addr in self._cfg.jump_tables:
            block_nodes = node_dict[block_addr]
            for block_node in block_nodes:
                if ail_graph.in_degree[block_node] > 1:
                    # found it
                    candidates.append(block_node)

        if not candidates:
            return

        sorted_nodes = GraphUtils.quasi_topological_sort_nodes(ail_graph)
        node_to_rank = {node: rank for rank, node in enumerate(sorted_nodes)}
        for candidate in candidates:
            # determine the "intended" switch-case head using topological order
            preds = list(ail_graph.predecessors(candidate))
            preds = sorted(preds, key=lambda n_: node_to_rank[n_])
            intended_head = preds[0]
            other_heads = preds[1:]

            # now here is the tricky part. there are two cases:
            # Case 1: the intended head and the other heads share the same suffix (of instructions)
            #    Example:
            #       ; binary 736cb27201273f6c4f83da362c9595b50d12333362e02bc7a77dd327cc6b045a
            #       0041DA97 mov     ecx, [esp+2Ch+var_18]  ; this is the intended head
            #       0041DA9B mov     ecx, [ecx]
            #       0041DA9D cmp     ecx, 9
            #       0041DAA0 jbe     loc_41D5A8
            #
            #       0041D599 mov     ecx, [ecx]             ; this is the other head
            #       0041D59B mov     [esp+2Ch+var_10], eax
            #       0041D59F cmp     ecx, 9
            #       0041D5A2 ja      loc_41DAA6             ; fallthrough to 0x41d5a8
            # given the overlap of two instructions at the end of both blocks, we will alter the second block to remove
            # the overlapped instructions and add an unconditional jump so that it jumps to 0x41da9d.
            # this is the most common case created by jump threading optimization in compilers. it's easy to handle.

            # Case 2 & 3: the intended head and the other heads do not share the same suffix of instructions. in this
            # case, we have two choices:
            #   Case 2: The intended head has two successors, but at least one unintended head has only one successor.
            #           we cannot reliably convert the blocks into a properly structured switch-case construct. we will
            #           last instruction of all other heads to jump to the cmp instruction in the intended head, but do
            #           not remove any other instructions in these other heads. this is unsound, but is the best we can
            #           do in this case.
            #   Case 3: The intended head has only one successor (which is the indirect jump node). during structuring,
            #           we expect it will be structured as a no-default-node switch-case construct. in this case, we
            #           can simply remove the edges from all other heads to the jump node and only leave the edge from
            #           the intended head to the jump node. we will see goto statements in the output, but this will
            #           lead to correct structuring result.

            overlaps = [self._get_overlapping_suffix_instructions(intended_head, head) for head in other_heads]
            if overlaps and (overlap := min(overlaps)) > 0:
                # Case 1
                self._fix_abnormal_switch_case_heads_case1(ail_graph, candidate, intended_head, other_heads, overlap)
            elif ail_graph.out_degree[intended_head] == 2:
                # Case 2
                l.warning("Switch-case at %#x has multiple head nodes but cannot be fixed soundly.", candidate.addr)
                # find the comparison instruction in the intended head
                comparison_stmt = None
                if "cc_op" in self.project.arch.registers:
                    comparison_stmt = next(
                        iter(
                            stmt
                            for stmt in intended_head.statements
                            if isinstance(stmt, ailment.Stmt.Assignment)
                            and isinstance(stmt.dst, ailment.Expr.Register)
                            and stmt.dst.reg_offset == self.project.arch.registers["cc_op"][0]
                        ),
                        None,
                    )
                intended_head_block = self.project.factory.block(intended_head.addr, size=intended_head.original_size)
                if comparison_stmt is not None:
                    cmp_rpos = len(intended_head_block.instruction_addrs) - intended_head_block.instruction_addrs.index(
                        comparison_stmt.ins_addr
                    )
                else:
                    cmp_rpos = min(len(intended_head_block.instruction_addrs), 2)
                self._fix_abnormal_switch_case_heads_case2(
                    ail_graph,
                    candidate,
                    intended_head,
                    other_heads,
                    intended_head_split_insns=cmp_rpos,
                    other_head_split_insns=0,
                )
            else:
                # Case 3
                self._fix_abnormal_switch_case_heads_case3(
                    candidate,
                    other_heads,
                )

    def _get_overlapping_suffix_instructions(self, ailblock_0: ailment.Block, ailblock_1: ailment.Block) -> int:
        # we first compare their ending conditional jumps
        if not self._get_overlapping_suffix_instructions_compare_conditional_jumps(ailblock_0, ailblock_1):
            return 0

        # we re-lift the blocks and compare the instructions
        block_0 = self.project.factory.block(ailblock_0.addr, size=ailblock_0.original_size)
        block_1 = self.project.factory.block(ailblock_1.addr, size=ailblock_1.original_size)

        i0 = len(block_0.capstone.insns) - 2
        i1 = len(block_1.capstone.insns) - 2
        overlap = 1
        while i0 >= 0 and i1 >= 0:
            same = self._get_overlapping_suffix_instructions_compare_instructions(
                block_0.capstone.insns[i0], block_1.capstone.insns[i1]
            )
            if not same:
                break
            overlap += 1
            i0 -= 1
            i1 -= 1

        return overlap

    @staticmethod
    def _get_overlapping_suffix_instructions_compare_instructions(insn_0, insn_1) -> bool:
        return insn_0.mnemonic == insn_1.mnemonic and insn_0.op_str == insn_1.op_str

    @staticmethod
    def _get_overlapping_suffix_instructions_compare_conditional_jumps(
        ailblock_0: ailment.Block, ailblock_1: ailment.Block
    ) -> bool:
        # TODO: The logic here is naive and highly customized to the only example I can access. Expand this method
        #  later to handle more cases if needed.
        if len(ailblock_0.statements) == 0 or len(ailblock_1.statements) == 0:
            return False

        # 12 | 0x41d5a2 | t17 = (t4 <= 0x9<32>)
        # 13 | 0x41d5a2 | t16 = Conv(1->32, t17)
        # 14 | 0x41d5a2 | t14 = t16
        # 15 | 0x41d5a2 | t18 = Conv(32->1, t14)
        # 16 | 0x41d5a2 | t9 = t18
        # 17 | 0x41d5a2 | if (t9) { Goto 0x41d5a8<32> } else { Goto 0x41daa6<32> }

        last_stmt_0 = ailblock_0.statements[-1]
        last_stmt_1 = ailblock_1.statements[-1]
        if not (isinstance(last_stmt_0, ailment.Stmt.ConditionalJump) and last_stmt_0.likes(last_stmt_1)):
            return False

        last_cmp_stmt_0 = next(
            iter(
                stmt
                for stmt in reversed(ailblock_0.statements)
                if isinstance(stmt, ailment.Stmt.Assignment)
                and isinstance(stmt.src, ailment.Expr.BinaryOp)
                and stmt.src.op in ailment.Expr.BinaryOp.COMPARISON_NEGATION
                and stmt.ins_addr == last_stmt_0.ins_addr
            ),
            None,
        )
        last_cmp_stmt_1 = next(
            iter(
                stmt
                for stmt in reversed(ailblock_1.statements)
                if isinstance(stmt, ailment.Stmt.Assignment)
                and isinstance(stmt.src, ailment.Expr.BinaryOp)
                and stmt.src.op in ailment.Expr.BinaryOp.COMPARISON_NEGATION
                and stmt.ins_addr == last_stmt_1.ins_addr
            ),
            None,
        )
        return (
            last_cmp_stmt_0 is not None
            and last_cmp_stmt_1 is not None
            and last_cmp_stmt_0.src.op == last_cmp_stmt_1.src.op
            and last_cmp_stmt_0.src.operands[1].likes(last_cmp_stmt_1.src.operands[1])
        )

    def _fix_abnormal_switch_case_heads_case1(
        self,
        ail_graph: networkx.DiGraph,
        indirect_jump_node: ailment.Block,
        intended_head: ailment.Block,
        other_heads: list[ailment.Block],
        overlap: int,
    ) -> None:
        self._fix_abnormal_switch_case_heads_case2(
            ail_graph,
            indirect_jump_node,
            intended_head,
            other_heads,
            intended_head_split_insns=overlap,
            other_head_split_insns=overlap,
        )

    def _fix_abnormal_switch_case_heads_case2(
        self,
        ail_graph: networkx.DiGraph,
        indirect_jump_node: ailment.Block,
        intended_head: ailment.Block,
        other_heads: list[ailment.Block],
        intended_head_split_insns: int = 1,
        other_head_split_insns: int = 0,
    ) -> None:

        # split the intended head into two
        intended_head_block = self.project.factory.block(intended_head.addr, size=intended_head.original_size)
        split_ins_addr = intended_head_block.instruction_addrs[-intended_head_split_insns]
        # note that the two blocks can be fully overlapping, so block_0 will be empty...
        intended_head_block_0 = (
            self.project.factory.block(intended_head.addr, size=split_ins_addr - intended_head.addr)
            if split_ins_addr != intended_head.addr
            else None
        )
        intended_head_block_1 = self.project.factory.block(
            split_ins_addr, size=intended_head.addr + intended_head.original_size - split_ins_addr
        )
        intended_head_0 = self._convert_vex(intended_head_block_0) if intended_head_block_0 is not None else None
        intended_head_1 = self._convert_vex(intended_head_block_1)

        # corner-case: the last statement of intended_head might have been patched by _remove_redundant_jump_blocks. we
        # detect such case and fix it in intended_head_1
        self._remove_redundant_jump_blocks_repatch_relifted_block(intended_head, intended_head_1)

        # adjust the graph accordingly
        preds = list(ail_graph.predecessors(intended_head))
        succs = list(ail_graph.successors(intended_head))
        ail_graph.remove_node(intended_head)

        if intended_head_0 is None:
            # perfect overlap; the first block is empty
            for pred in preds:
                if pred is intended_head:
                    ail_graph.add_edge(intended_head_1, intended_head_1)
                else:
                    ail_graph.add_edge(pred, intended_head_1)
            for succ in succs:
                if succ is intended_head:
                    ail_graph.add_edge(intended_head_1, intended_head_1)
                else:
                    ail_graph.add_edge(intended_head_1, succ)
        else:
            ail_graph.add_edge(intended_head_0, intended_head_1)
            for pred in preds:
                if pred is intended_head:
                    ail_graph.add_edge(intended_head_1, intended_head_0)
                else:
                    ail_graph.add_edge(pred, intended_head_0)
            for succ in succs:
                if succ is intended_head:
                    ail_graph.add_edge(intended_head_1, intended_head_0)
                else:
                    ail_graph.add_edge(intended_head_1, succ)

        # split other heads
        for o in other_heads:
            if other_head_split_insns > 0:
                o_block = self.project.factory.block(o.addr, size=o.original_size)
                o_split_addr = o_block.instruction_addrs[-other_head_split_insns]
                new_o_block = (
                    self.project.factory.block(o.addr, size=o_split_addr - o.addr) if o_split_addr != o.addr else None
                )
                new_head = self._convert_vex(new_o_block) if new_o_block is not None else None
            else:
                new_head = o

            if new_head is None:
                # the head is removed - let's replace it with a jump to the target
                jump_stmt = ailment.Stmt.Jump(
                    None,
                    ailment.Expr.Const(None, None, intended_head_1.addr, self.project.arch.bits),
                    target_idx=intended_head_1.idx,
                    ins_addr=o.addr,
                )
                new_head = ailment.Block(o.addr, 1, statements=[jump_stmt], idx=o.idx)
            else:
                if (
                    new_head.statements
                    and isinstance(new_head.statements[-1], ailment.Stmt.Jump)
                    and isinstance(new_head.statements[-1].target, ailment.Expr.Const)
                ):
                    # update the jump target
                    new_head.statements[-1] = ailment.Stmt.Jump(
                        new_head.statements[-1].idx,
                        ailment.Expr.Const(None, None, intended_head_1.addr, self.project.arch.bits),
                        target_idx=intended_head_1.idx,
                        **new_head.statements[-1].tags,
                    )

            # adjust the graph accordingly
            preds = list(ail_graph.predecessors(o))
            succs = list(ail_graph.successors(o))
            ail_graph.remove_node(o)
            for pred in preds:
                if pred is o:
                    ail_graph.add_edge(new_head, new_head)
                else:
                    ail_graph.add_edge(pred, new_head)
            for succ in succs:
                if succ is o:
                    ail_graph.add_edge(new_head, new_head)
                elif succ is indirect_jump_node:
                    ail_graph.add_edge(new_head, intended_head_1)
                else:
                    # it should be going to the default node. ignore it
                    pass

    def _fix_abnormal_switch_case_heads_case3(
        self, indirect_jump_node: ailment.Block, other_heads: list[ailment.Block]
    ) -> None:
        # remove all edges from other_heads to the indirect jump node
        for other_head in other_heads:
            # delay the edge removal so that we don't mess up the SSA analysis
            self.edges_to_remove.append(
                ((other_head.addr, other_head.idx), (indirect_jump_node.addr, indirect_jump_node.idx))
            )

    @staticmethod
    def _remove_redundant_jump_blocks(ail_graph):
        def first_conditional_jump(block: ailment.Block) -> ailment.Stmt.ConditionalJump | None:
            for stmt in block.statements:
                if isinstance(stmt, ailment.Stmt.ConditionalJump):
                    return stmt
            return None

        def patch_conditional_jump_target(cond_jump_stmt: ailment.Stmt.ConditionalJump, old_addr: int, new_addr: int):
            if (
                isinstance(cond_jump_stmt.true_target, ailment.Expr.Const)
                and cond_jump_stmt.true_target.value == old_addr
            ):
                cond_jump_stmt.true_target.value = new_addr
            if (
                isinstance(cond_jump_stmt.false_target, ailment.Expr.Const)
                and cond_jump_stmt.false_target.value == old_addr
            ):
                cond_jump_stmt.false_target.value = new_addr

        # note that blocks don't have labels inserted at this point
        for node in list(ail_graph.nodes):
            if (
                len(node.statements) == 1
                and isinstance(node.statements[0], ailment.Stmt.Jump)
                and isinstance(node.statements[0].target, ailment.Expr.Const)
            ):
                jump_target = node.statements[0].target.value
                succs = list(ail_graph.successors(node))
                if len(succs) == 1 and succs[0].addr == jump_target:
                    preds = list(ail_graph.predecessors(node))
                    if len(preds) == 1 and ail_graph.out_degree[preds[0]] == 2:
                        # remove this node
                        for pred in preds:
                            if pred.statements:
                                last_stmt = pred.statements[-1]
                                if (
                                    isinstance(last_stmt, ailment.Stmt.Jump)
                                    and isinstance(last_stmt.target, ailment.Expr.Const)
                                    and last_stmt.target.value == node.addr
                                ):
                                    last_stmt.target.value = succs[0].addr
                                elif isinstance(last_stmt, ailment.Stmt.ConditionalJump):
                                    patch_conditional_jump_target(last_stmt, node.addr, succs[0].addr)
                                    # if both branches jump to the same location, we replace it with a jump
                                    if (
                                        isinstance(last_stmt.true_target, ailment.Expr.Const)
                                        and isinstance(last_stmt.false_target, ailment.Expr.Const)
                                        and last_stmt.true_target.value == last_stmt.false_target.value
                                    ):
                                        last_stmt = ailment.Stmt.Jump(
                                            last_stmt.idx,
                                            last_stmt.true_target,
                                            target_idx=last_stmt.true_target.idx,
                                            ins_addr=last_stmt.ins_addr,
                                        )
                                        pred.statements[-1] = last_stmt
                                first_cond_jump = first_conditional_jump(pred)
                                if first_cond_jump is not None and first_cond_jump is not last_stmt:
                                    patch_conditional_jump_target(first_cond_jump, node.addr, succs[0].addr)
                            ail_graph.add_edge(pred, succs[0])
                        ail_graph.remove_node(node)

    @staticmethod
    def _remove_redundant_jump_blocks_repatch_relifted_block(
        patched_block: ailment.Block, new_block: ailment.Block
    ) -> None:
        """
        The last statement of patched_block might have been patched by _remove_redundant_jump_blocks. In this case, we
        fix the last instruction for new_block, which is a newly lifted (from VEX) block that ends at the same address
        as patched_block.

        :param patched_block:   Previously patched block.
        :param new_block:       Newly lifted block.
        """

        if (
            isinstance(patched_block.statements[-1], ailment.Stmt.Jump)
            and isinstance(patched_block.statements[-1].target, ailment.Expr.Const)
            and isinstance(new_block.statements[-1], ailment.Stmt.Jump)
            and isinstance(new_block.statements[-1].target, ailment.Expr.Const)
            and not patched_block.statements[-1].likes(new_block.statements[-1])
        ):
            new_block.statements[-1].target = patched_block.statements[-1].target
        if (
            isinstance(patched_block.statements[-1], ailment.Stmt.ConditionalJump)
            and isinstance(patched_block.statements[-1].true_target, ailment.Expr.Const)
            and isinstance(patched_block.statements[-1].false_target, ailment.Expr.Const)
            and isinstance(new_block.statements[-1], ailment.Stmt.ConditionalJump)
            and isinstance(new_block.statements[-1].true_target, ailment.Expr.Const)
            and isinstance(new_block.statements[-1].false_target, ailment.Expr.Const)
            and not patched_block.statements[-1].likes(new_block.statements[-1])
        ):
            new_block.statements[-1].true_target = patched_block.statements[-1].true_target
            new_block.statements[-1].false_target = patched_block.statements[-1].false_target

    @staticmethod
    def _insert_block_labels(ail_graph):
        for node in ail_graph.nodes:
            node: ailment.Block
            lbl = ailment.Stmt.Label(None, f"LABEL_{node.addr:x}", node.addr, block_idx=node.idx)
            node.statements.insert(0, lbl)

    @staticmethod
    def _collect_externs(ail_graph, variable_kb):
        global_vars = variable_kb.variables.global_manager.get_variables()
        walker = ailment.AILBlockWalker()
        variables = set()

        def handle_expr(
            expr_idx: int,
            expr: ailment.expression.Expression,
            stmt_idx: int,
            stmt: ailment.statement.Statement | None,
            block: ailment.Block | None,
        ):
            if expr is None:
                return None
            for v in [
                getattr(expr, "variable", None),
                expr.tags.get("reference_variable", None) if hasattr(expr, "tags") else None,
            ]:
                if v and v in global_vars:
                    variables.add(v)
            return ailment.AILBlockWalker._handle_expr(walker, expr_idx, expr, stmt_idx, stmt, block)

        def handle_Store(stmt_idx: int, stmt: ailment.statement.Store, block: ailment.Block | None):
            if stmt.variable and stmt.variable in global_vars:
                variables.add(stmt.variable)
            return ailment.AILBlockWalker._handle_Store(walker, stmt_idx, stmt, block)

        walker.stmt_handlers[ailment.statement.Store] = handle_Store
        walker._handle_expr = handle_expr
        AILGraphWalker(ail_graph, walker.walk).walk()
        return variables

    @staticmethod
    def _collect_data_refs(ail_graph) -> dict[int, list[DataRefDesc]]:
        # pylint:disable=unused-argument
        walker = ailment.AILBlockWalker()
        data_refs: dict[int, list[DataRefDesc]] = defaultdict(list)

        def handle_Const(
            expr_idx: int,
            expr: ailment.expression.Const,
            stmt_idx: int,
            stmt: ailment.statement.Statement,
            block: ailment.Block,
        ):
            if isinstance(expr.value, int) and hasattr(expr, "ins_addr"):
                data_refs[block.addr].append(
                    DataRefDesc(expr.value, 1, block.addr, stmt_idx, expr.ins_addr, MemoryDataSort.Unknown)
                )
            if hasattr(expr, "deref_src_addr"):
                data_refs[block.addr].append(
                    DataRefDesc(
                        expr.deref_src_addr, expr.size, block.addr, stmt_idx, expr.ins_addr, MemoryDataSort.Unknown
                    )
                )

        def handle_Load(
            expr_idx: int,
            expr: ailment.expression.Load,
            stmt_idx: int,
            stmt: ailment.statement.Statement,
            block: ailment.Block,
        ):
            if isinstance(expr.addr, ailment.expression.Const):
                addr = expr.addr
                if isinstance(addr.value, int) and hasattr(addr, "ins_addr"):
                    data_refs[block.addr].append(
                        DataRefDesc(
                            addr.value,
                            expr.size,
                            block.addr,
                            stmt_idx,
                            addr.ins_addr,
                            MemoryDataSort.Integer if expr.size == 4 else MemoryDataSort.Unknown,
                        )
                    )
                if hasattr(addr, "deref_src_addr"):
                    data_refs[block.addr].append(
                        DataRefDesc(
                            addr.deref_src_addr,
                            expr.size,
                            block.addr,
                            stmt_idx,
                            addr.ins_addr,
                            MemoryDataSort.Integer if expr.size == 4 else MemoryDataSort.Unknown,
                        )
                    )
                return None

            return ailment.AILBlockWalker._handle_Load(walker, expr_idx, expr, stmt_idx, stmt, block)

        def handle_Store(stmt_idx: int, stmt: ailment.statement.Store, block: ailment.Block):
            if isinstance(stmt.addr, ailment.expression.Const):
                addr = stmt.addr
                if isinstance(addr.value, int) and hasattr(addr, "ins_addr"):
                    data_refs[block.addr].append(
                        DataRefDesc(
                            addr.value,
                            stmt.size,
                            block.addr,
                            stmt_idx,
                            addr.ins_addr,
                            MemoryDataSort.Integer if stmt.size == 4 else MemoryDataSort.Unknown,
                        )
                    )
                if hasattr(addr, "deref_src_addr"):
                    data_refs[block.addr].append(
                        DataRefDesc(
                            addr.deref_src_addr,
                            stmt.size,
                            block.addr,
                            stmt_idx,
                            addr.ins_addr,
                            MemoryDataSort.Integer if stmt.size == 4 else MemoryDataSort.Unknown,
                        )
                    )
                return None

            return ailment.AILBlockWalker._handle_Store(walker, stmt_idx, stmt, block)

        walker.stmt_handlers[ailment.statement.Store] = handle_Store
        walker.expr_handlers[ailment.expression.Load] = handle_Load
        walker.expr_handlers[ailment.expression.Const] = handle_Const
        AILGraphWalker(ail_graph, walker.walk).walk()
        return data_refs

    def _next_atom(self) -> int:
        return self._ail_manager.next_atom()

    def parse_variable_addr(self, addr: ailment.Expr.Expression) -> tuple[Any, Any]:
        if isinstance(addr, ailment.Expr.Const):
            return addr, 0
        if isinstance(addr, ailment.Expr.BinaryOp) and addr.op == "Add":
            op0, op1 = addr.operands
            if (
                isinstance(op0, ailment.Expr.Const)
                and self.project.loader.find_object_containing(op0.value) is not None
            ):
                return op0, op1
            if (
                isinstance(op1, ailment.Expr.Const)
                and self.project.loader.find_object_containing(op1.value) is not None
            ):
                return op1, op0
            return op0, op1  # best-effort guess
        return None, None

    def new_block_addr(self) -> int:
        """
        Return a block address that does not conflict with any existing blocks.

        :return:    The block address.
        """
        if self._new_block_addrs:
            new_addr = max(self._new_block_addrs) + 1
        else:
            new_addr = max(self.function.block_addrs_set) + 2048
        self._new_block_addrs.add(new_addr)
        return new_addr

    @staticmethod
    @timethis
    def remove_empty_nodes(graph: networkx.DiGraph) -> networkx.DiGraph:
        def handle_node(node: ailment.Block):
            if not node.statements:
                preds = [pred for pred in graph.predecessors(node) if pred is not node]
                succs = [succ for succ in graph.successors(node) if succ is not node]
                if len(preds) == 1 and len(succs) == 1:
                    pred = preds[0]
                    succ = succs[0]
                    value_updated = False
                    # update the last statement of pred
                    if pred.statements and isinstance(pred.statements[-1], ailment.Stmt.ConditionalJump):
                        last_stmt = pred.statements[-1]
                        if (
                            isinstance(last_stmt.true_target, ailment.Expr.Const)
                            and last_stmt.true_target.value == node.addr
                        ):
                            last_stmt.true_target.value = succ.addr
                            value_updated = True
                        if (
                            isinstance(last_stmt.false_target, ailment.Expr.Const)
                            and last_stmt.false_target.value == node.addr
                        ):
                            last_stmt.false_target.value = succ.addr
                            value_updated = True

                    if value_updated:
                        graph.add_edge(pred, succ)
                        raise RemoveNodeNotice
                elif len(preds) >= 1 and len(succs) == 1:
                    succ = succs[0]
                    branch_updates = 0
                    for pred in preds:
                        # test how many last statements of pred can potentially be updated
                        if pred.statements and isinstance(pred.statements[-1], ailment.Stmt.ConditionalJump):
                            last_stmt = pred.statements[-1]
                            if (
                                isinstance(last_stmt.true_target, ailment.Expr.Const)
                                and last_stmt.true_target.value == node.addr
                            ):
                                branch_updates += 1
                            if (
                                isinstance(last_stmt.false_target, ailment.Expr.Const)
                                and last_stmt.false_target.value == node.addr
                            ):
                                branch_updates += 1

                    if branch_updates == len(preds):
                        # actually do the update
                        for pred in preds:
                            graph.add_edge(pred, succ)
                            if pred.statements and isinstance(pred.statements[-1], ailment.Stmt.ConditionalJump):
                                last_stmt = pred.statements[-1]
                                if (
                                    isinstance(last_stmt.true_target, ailment.Expr.Const)
                                    and last_stmt.true_target.value == node.addr
                                ):
                                    last_stmt.true_target.value = succ.addr
                                if (
                                    isinstance(last_stmt.false_target, ailment.Expr.Const)
                                    and last_stmt.false_target.value == node.addr
                                ):
                                    last_stmt.false_target.value = succ.addr
                        raise RemoveNodeNotice
                elif not preds or not succs:
                    raise RemoveNodeNotice

        AILGraphWalker(graph, handle_node, replace_nodes=True).walk()
        return graph

    def _find_regs_compared_against_sp(self, func_graph):
        # TODO: Implement this function for architectures beyond amd64
        extra_regs = set()
        if self.project.arch.name == "AMD64":
            for node in func_graph.nodes:
                block = self.project.factory.block(node.addr, size=node.size).capstone
                for insn in block.insns:
                    if insn.mnemonic == "cmp":
                        capstone_reg_offset = None
                        if (
                            insn.operands[0].type == capstone.x86.X86_OP_REG
                            and insn.operands[0].reg == capstone.x86.X86_REG_RSP
                            and insn.operands[1].type == capstone.x86.X86_OP_REG
                        ):
                            capstone_reg_offset = insn.operands[1].reg
                        elif (
                            insn.operands[1].type == capstone.x86.X86_OP_REG
                            and insn.operands[1].reg == capstone.x86.X86_REG_RSP
                            and insn.operands[0].type == capstone.x86.X86_OP_REG
                        ):
                            capstone_reg_offset = insn.operands[0].reg

                        if capstone_reg_offset is not None:
                            reg_name = insn.reg_name(capstone_reg_offset)
                            extra_regs.add(self.project.arch.registers[reg_name][0])

        return extra_regs

    def _rewrite_rust_probestack_call(self, ail_graph):
        for node in ail_graph:
            if not node.statements or ail_graph.out_degree[node] != 1:
                continue
            last_stmt = node.statements[-1]
            if isinstance(last_stmt, ailment.Stmt.Call) and isinstance(last_stmt.target, ailment.Expr.Const):
                func = (
                    self.project.kb.functions.get_by_addr(last_stmt.target.value)
                    if self.project.kb.functions.contains_addr(last_stmt.target.value)
                    else None
                )
                if func is not None and func.info.get("is_rust_probestack", False) is True:
                    # get rid of this call
                    node.statements = node.statements[:-1]
                    if self.project.arch.call_pushes_ret and node.statements:
                        last_stmt = node.statements[-1]
                        succ = next(iter(ail_graph.successors(node)))
                        if (
                            isinstance(last_stmt, ailment.Stmt.Store)
                            and isinstance(last_stmt.addr, ailment.Expr.StackBaseOffset)
                            and isinstance(last_stmt.addr.offset, int)
                            and last_stmt.addr.offset < 0
                            and isinstance(last_stmt.data, ailment.Expr.Const)
                            and last_stmt.data.value == succ.addr
                        ) or (
                            isinstance(last_stmt, ailment.Stmt.Assignment)
                            and last_stmt.dst.was_stack
                            and last_stmt.dst.stack_offset < 0
                            and isinstance(last_stmt.src, ailment.Expr.Const)
                            and last_stmt.src.value == succ.addr
                        ):
                            # remove the statement that pushes the return address
                            node.statements = node.statements[:-1]
                    break
        return ail_graph

    def _rewrite_windows_chkstk_call(self, ail_graph) -> networkx.DiGraph:
        if not (self.project.simos is not None and self.project.simos.name == "Win32"):
            return ail_graph

        for node in ail_graph:
            if not node.statements or ail_graph.out_degree[node] != 1:
                continue
            last_stmt = node.statements[-1]
            if isinstance(last_stmt, ailment.Stmt.Call) and isinstance(last_stmt.target, ailment.Expr.Const):
                func = (
                    self.project.kb.functions.get_by_addr(last_stmt.target.value)
                    if self.project.kb.functions.contains_addr(last_stmt.target.value)
                    else None
                )
                if func is not None and (func.name == "__chkstk" or func.info.get("is_alloca_probe", False) is True):
                    # get rid of this call
                    node.statements = node.statements[:-1]
                    if self.project.arch.call_pushes_ret and node.statements:
                        last_stmt = node.statements[-1]
                        succ = next(iter(ail_graph.successors(node)))
                        if (
                            isinstance(last_stmt, ailment.Stmt.Store)
                            and isinstance(last_stmt.addr, ailment.Expr.StackBaseOffset)
                            and isinstance(last_stmt.addr.offset, int)
                            and last_stmt.addr.offset < 0
                            and isinstance(last_stmt.data, ailment.Expr.Const)
                            and last_stmt.data.value == succ.addr
                        ) or (
                            isinstance(last_stmt, ailment.Stmt.Assignment)
                            and last_stmt.dst.was_stack
                            and last_stmt.dst.stack_offset < 0
                            and isinstance(last_stmt.src, ailment.Expr.Const)
                            and last_stmt.src.value == succ.addr
                        ):
                            # remove the statement that pushes the return address
                            node.statements = node.statements[:-1]
                    break
        return ail_graph

    def _rewrite_alloca(self, ail_graph):
        # pylint:disable=too-many-boolean-expressions
        alloca_node = None
        sp_equal_to = None

        for node in ail_graph:
            if ail_graph.in_degree[node] == 2 and ail_graph.out_degree[node] == 2:
                succs = ail_graph.successors(node)
                if node in succs and len(node.statements) >= 6:
                    # self loop!
                    stmt0 = node.statements[1]  # skip the LABEL statement
                    stmt1 = node.statements[2]
                    last_stmt = node.statements[-1]
                    if (
                        (
                            isinstance(stmt0, ailment.Stmt.Assignment)
                            and isinstance(stmt0.dst, ailment.Expr.Register)
                            and isinstance(stmt0.src, ailment.Expr.StackBaseOffset)
                            and stmt0.src.offset == -0x1000
                        )
                        and (
                            isinstance(stmt1, ailment.Stmt.Store)
                            and isinstance(stmt1.addr, ailment.Expr.StackBaseOffset)
                            and stmt1.addr.offset == -0x1000
                            and isinstance(stmt1.data, ailment.Expr.Load)
                            and isinstance(stmt1.data.addr, ailment.Expr.StackBaseOffset)
                            and stmt1.data.addr.offset == -0x1000
                        )
                        and (
                            isinstance(last_stmt, ailment.Stmt.ConditionalJump)
                            and isinstance(last_stmt.condition, ailment.Expr.BinaryOp)
                            and last_stmt.condition.op == "CmpEQ"
                            and isinstance(last_stmt.condition.operands[0], ailment.Expr.StackBaseOffset)
                            and last_stmt.condition.operands[0].offset == -0x1000
                            and isinstance(last_stmt.condition.operands[1], ailment.Expr.Register)
                            and isinstance(last_stmt.false_target, ailment.Expr.Const)
                            and last_stmt.false_target.value == node.addr
                        )
                    ):
                        # found it!
                        alloca_node = node
                        sp_equal_to = ailment.Expr.BinaryOp(
                            None,
                            "Sub",
                            [
                                ailment.Expr.Register(None, None, self.project.arch.sp_offset, self.project.arch.bits),
                                last_stmt.condition.operands[1],
                            ],
                            False,
                        )
                        break

        if alloca_node is not None and sp_equal_to is not None:
            stmt0 = alloca_node.statements[1]
            statements = [ailment.Stmt.Call(stmt0.idx, "alloca", args=[sp_equal_to], **stmt0.tags)]
            new_node = ailment.Block(alloca_node.addr, alloca_node.original_size, statements=statements)
            # replace the node
            preds = [pred for pred in ail_graph.predecessors(alloca_node) if pred is not alloca_node]
            succs = [succ for succ in ail_graph.successors(alloca_node) if succ is not alloca_node]
            ail_graph.remove_node(alloca_node)
            for pred in preds:
                ail_graph.add_edge(pred, new_node)
            for succ in succs:
                ail_graph.add_edge(new_node, succ)


register_analysis(Clinic, "Clinic")

from __future__ import annotations
import copy
from collections import defaultdict, namedtuple
import logging
import enum
from dataclasses import dataclass
from typing import Any, NamedTuple, TYPE_CHECKING
from collections.abc import Iterable

import networkx
import capstone

import ailment

from ...knowledge_base import KnowledgeBase
from ...knowledge_plugins.functions import Function
from ...knowledge_plugins.cfg.memory_data import MemoryDataSort
from ...codenode import BlockNode
from ...utils import timethis
from ...calling_conventions import SimRegArg, SimStackArg, SimStructArg, SimFunctionArgument
from ...sim_type import (
    SimTypeChar,
    SimTypeInt,
    SimTypeLongLong,
    SimTypeShort,
    SimTypeFunction,
    SimTypeBottom,
    SimTypeFloat,
    SimTypePointer,
)
from ..stack_pointer_tracker import Register, OffsetVal
from ...sim_variable import SimVariable, SimStackVariable, SimRegisterVariable, SimMemoryVariable
from ...knowledge_plugins.key_definitions.constants import OP_BEFORE
from ...procedures.stubs.UnresolvableCallTarget import UnresolvableCallTarget
from ...procedures.stubs.UnresolvableJumpTarget import UnresolvableJumpTarget
from .. import Analysis, register_analysis
from ..cfg.cfg_base import CFGBase
from ..reaching_definitions import ReachingDefinitionsAnalysis
from .return_maker import ReturnMaker
from .ailgraph_walker import AILGraphWalker, RemoveNodeNotice
from .optimization_passes import (
    get_default_optimization_passes,
    OptimizationPassStage,
    RegisterSaveAreaSimplifier,
    StackCanarySimplifier,
    SpilledRegisterFinder,
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


class Clinic(Analysis):
    """
    A Clinic deals with AILments.
    """

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
        inline_functions: set[Function] | None = frozenset(),
        inlined_counts: dict[int, int] | None = None,
        inlining_parents: set[int] | None = None,
    ):
        if not func.normalized and mode == ClinicMode.DECOMPILE:
            raise ValueError("Decompilation must work on normalized function graphs.")

        self.function = func

        self.graph = None
        self.cc_graph: networkx.DiGraph | None = None
        self.unoptimized_graph: networkx.DiGraph | None = None
        self.arg_list = None
        self.variable_kb = variable_kb
        self.externs: set[SimMemoryVariable] = set()
        self.data_refs: dict[int, int] = {}  # data address to instruction address

        self._func_graph: networkx.DiGraph | None = None
        self._ail_manager = None
        self._blocks_by_addr_and_size = {}

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

        # inlining help
        self._sp_shift = sp_shift
        self._max_stack_depth = 0
        self._inline_functions = inline_functions
        self._inlined_counts = {} if inlined_counts is None else inlined_counts
        self._inlining_parents = inlining_parents or ()

        self._register_save_areas_removed: bool = False

        self._new_block_addrs = set()

        # sanity checks
        if not self.kb.functions:
            l.warning("No function is available in kb.functions. It will lead to a suboptimal conversion result.")

        if optimization_passes is not None:
            self._optimization_passes = optimization_passes
        else:
            self._optimization_passes = get_default_optimization_passes(self.project.arch, self.project.simos.name)
            l.debug("Get %d optimization passes for the current binary.", len(self._optimization_passes))

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
            return self._blocks_by_addr_and_size[(addr, size)]
        except KeyError:
            return None

    def dbg_repr(self):
        """

        :return:
        """

        s = ""

        for block in sorted(self.graph.nodes(), key=lambda x: x.addr):
            s += str(block) + "\n\n"

        return s

    #
    # Private methods
    #

    def _analyze_for_decompiling(self):
        if not (ail_graph := self._decompilation_graph_recovery()):
            return
        ail_graph = self._decompilation_fixups(ail_graph)

        if self._inline_functions:
            self._max_stack_depth += self.calculate_stack_depth()
            ail_graph = self._inline_child_functions(ail_graph)

        ail_graph = self._decompilation_simplifications(ail_graph)
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

        # initialize the AIL conversion manager
        self._ail_manager = ailment.Manager(arch=self.project.arch)

        # Convert VEX blocks to AIL blocks and then simplify them

        self._update_progress(20.0, text="Converting VEX to AIL")
        self._convert_all()

        return self._make_ailgraph()

    def _decompilation_fixups(self, ail_graph):
        is_pcode_arch = ":" in self.project.arch.name

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
            inlining_parents=self._inlining_parents + (self.function.addr,),
            inlined_counts=self._inlined_counts,
            optimization_passes=[StackCanarySimplifier, SpilledRegisterFinder],
            sp_shift=self._max_stack_depth,
        )
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
        # and rewrite pseudoreg-tagged spills to actually use pseudoregs
        ail_graph = networkx.union(ail_graph, callee_graph)
        for blk in callee_graph.nodes():
            for idx, stmt in enumerate(list(blk.statements)):
                if isinstance(stmt, ailment.Stmt.Return):
                    blk.statements[idx] = ailment.Stmt.Jump(
                        None,
                        ailment.Expr.Const(None, None, caller_successor.addr, self.project.arch.bits),
                        caller_successor.idx,
                        **blk.statements[idx].tags,
                    )
                    blk.statements.pop(idx)
                    ail_graph.add_edge(blk, caller_successor)
                    break
                if "pseudoreg" in stmt.tags and isinstance(stmt, ailment.Stmt.Store):
                    new_stmt = ailment.Stmt.Assignment(
                        stmt.idx, ailment.Expr.Register(None, None, stmt.pseudoreg, stmt.size * 8), stmt.data
                    )
                    new_stmt.tags.update(stmt.tags)
                    new_stmt.tags.pop("pseudoreg")
                    blk.statements[idx] = new_stmt
                if "pseudoreg" in stmt.tags and isinstance(stmt, ailment.Stmt.Assignment):
                    new_stmt = ailment.Stmt.Assignment(
                        stmt.idx, stmt.dst, ailment.Expr.Register(None, None, stmt.pseudoreg, stmt.src.size * 8)
                    )
                    new_stmt.tags.update(stmt.tags)
                    new_stmt.tags.pop("pseudoreg")
                    blk.statements[idx] = new_stmt

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
        # Make returns
        self._update_progress(30.0, text="Making return sites")
        if self.function.prototype is None or not isinstance(self.function.prototype.returnty, SimTypeBottom):
            ail_graph = self._make_returns(ail_graph)

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

        # Track stack pointers
        self._update_progress(15.0, text="Tracking stack pointers")
        spt = self._track_stack_pointers()

        # Simplify blocks
        # we never remove dead memory definitions before making callsites. otherwise stack arguments may go missing
        # before they are recognized as stack arguments.
        self._update_progress(35.0, text="Simplifying blocks 1")
        ail_graph = self._simplify_blocks(
            ail_graph, stack_pointer_tracker=spt, remove_dead_memdefs=False, cache=block_simplification_cache
        )
        self._rewrite_alloca(ail_graph)

        # Run simplification passes
        self._update_progress(40.0, text="Running simplifications 1")
        ail_graph = self._run_simplification_passes(
            ail_graph, stage=OptimizationPassStage.AFTER_SINGLE_BLOCK_SIMPLIFICATION
        )

        # Simplify the entire function for the first time
        self._update_progress(45.0, text="Simplifying function 1")
        self._simplify_function(
            ail_graph,
            remove_dead_memdefs=False,
            unify_variables=False,
            narrow_expressions=True,
            fold_callexprs_into_conditions=self._fold_callexprs_into_conditions,
        )

        # Run simplification passes again. there might be more chances for peephole optimizations after function-level
        # simplification
        self._update_progress(48.0, text="Simplifying blocks 2")
        ail_graph = self._simplify_blocks(
            ail_graph, stack_pointer_tracker=spt, remove_dead_memdefs=False, cache=block_simplification_cache
        )

        # clear _blocks_by_addr_and_size so no one can use it again
        # TODO: Totally remove this dict
        self._blocks_by_addr_and_size = None

        # Make call-sites
        self._update_progress(50.0, text="Making callsites")
        _, stackarg_offsets = self._make_callsites(ail_graph, stack_pointer_tracker=spt)

        # Run simplification passes
        self._update_progress(53.0, text="Running simplifications 2")
        ail_graph = self._run_simplification_passes(ail_graph, stage=OptimizationPassStage.AFTER_MAKING_CALLSITES)

        # Simplify the entire function for the second time
        self._update_progress(55.0, text="Simplifying function 2")
        self._simplify_function(
            ail_graph,
            remove_dead_memdefs=self._remove_dead_memdefs,
            stack_arg_offsets=stackarg_offsets,
            unify_variables=True,
            narrow_expressions=True,
            fold_callexprs_into_conditions=self._fold_callexprs_into_conditions,
        )

        # After global optimization, there might be more chances for peephole optimizations.
        # Simplify blocks for the second time
        self._update_progress(60.0, text="Simplifying blocks 3")
        ail_graph = self._simplify_blocks(
            ail_graph,
            remove_dead_memdefs=self._remove_dead_memdefs,
            stack_pointer_tracker=spt,
            cache=block_simplification_cache,
        )

        # Run simplification passes
        self._update_progress(65.0, text="Running simplifications 3 ")
        ail_graph = self._run_simplification_passes(ail_graph, stage=OptimizationPassStage.AFTER_GLOBAL_SIMPLIFICATION)

        # Simplify the entire function for the third time
        self._update_progress(70.0, text="Simplifying function 3")
        self._simplify_function(
            ail_graph,
            remove_dead_memdefs=self._remove_dead_memdefs,
            stack_arg_offsets=stackarg_offsets,
            unify_variables=True,
            narrow_expressions=True,
            fold_callexprs_into_conditions=self._fold_callexprs_into_conditions,
        )

        self._update_progress(72.0, text="Simplifying blocks 4")
        ail_graph = self._simplify_blocks(
            ail_graph,
            remove_dead_memdefs=self._remove_dead_memdefs,
            stack_pointer_tracker=spt,
            cache=block_simplification_cache,
        )

        # Make function arguments
        self._update_progress(75.0, text="Making argument list")
        arg_list = self._make_argument_list()

        # Recover variables on AIL blocks
        self._update_progress(80.0, text="Recovering variables")
        variable_kb = self._recover_and_link_variables(ail_graph, arg_list)

        # Make function prototype
        self._update_progress(90.0, text="Making function prototype")
        self._make_function_prototype(arg_list, variable_kb)

        # Run simplification passes
        self._update_progress(95.0, text="Running simplifications 4")
        ail_graph = self._run_simplification_passes(
            ail_graph, stage=OptimizationPassStage.AFTER_VARIABLE_RECOVERY, variable_kb=variable_kb
        )

        # remove empty nodes from the graph
        ail_graph = self.remove_empty_nodes(ail_graph)

        self.arg_list = arg_list
        self.variable_kb = variable_kb
        self.cc_graph = self.copy_graph(ail_graph)
        self.externs = self._collect_externs(ail_graph, variable_kb)
        return ail_graph

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
        ail_graph = self._simplify_blocks(
            ail_graph, stack_pointer_tracker=spt, remove_dead_memdefs=False, cache=block_simplification_cache
        )

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
        self.externs = None
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
        return self._copy_graph(graph or self.graph)

    @timethis
    def _set_function_graph(self):
        self._func_graph = self.function.graph_ex(exception_edges=self._exception_edges)

    @timethis
    def _remove_alignment_blocks(self):
        """
        Alignment blocks are basic blocks that only consist of nops. They should not be included in the graph.
        """
        for node in list(self._func_graph.nodes()):
            if self._func_graph.in_degree(node) == 0 and CFGBase._is_noop_block(
                self.project.arch, self.project.factory.block(node.addr, node.size)
            ):
                self._func_graph.remove_node(node)

    @timethis
    def _recover_calling_conventions(self, func_graph=None) -> None:
        """
        Examine the calling convention and function prototype for each function called. For functions with missing
        calling conventions or function prototypes, analyze each *call site* and recover the calling convention and
        function prototype of the callee function.

        :return: None
        """

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
                continue

            # case 0: the calling convention and prototype are available
            if target_func.calling_convention is not None and target_func.prototype is not None:
                continue

            call_sites = []
            for pred in self.function.transition_graph.predecessors(node):
                call_sites.append(pred)
            # case 1: calling conventions and prototypes are available at every single call site
            if call_sites and all(self.kb.callsite_prototypes.has_prototype(callsite.addr) for callsite in call_sites):
                continue

            # case 2: the callee is a SimProcedure
            if target_func.is_simprocedure:
                cc = self.project.analyses.CallingConvention(target_func)
                if cc.cc is not None and cc.prototype is not None:
                    target_func.calling_convention = cc.cc
                    target_func.prototype = cc.prototype
                    continue

            # case 3: the callee is a PLT function
            if target_func.is_plt:
                cc = self.project.analyses.CallingConvention(target_func)
                if cc.cc is not None and cc.prototype is not None:
                    target_func.calling_convention = cc.cc
                    target_func.prototype = cc.prototype
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
                )

                if cc.cc is not None and cc.prototype is not None:
                    self.kb.callsite_prototypes.set_prototype(callsite.addr, cc.cc, cc.prototype, manual=False)
                    if func_graph is not None and cc.prototype.returnty is not None:
                        # patch the AIL call statement if we can find one
                        callsite_ail_block: ailment.Block = next(
                            iter(bb for bb in func_graph if bb.addr == callsite.addr), None
                        )
                        if callsite_ail_block is not None and callsite_ail_block.statements:
                            last_stmt = callsite_ail_block.statements[-1]
                            if isinstance(last_stmt, ailment.Stmt.Call) and last_stmt.ret_expr is None:
                                if isinstance(cc.cc.RETURN_VAL, SimRegArg):
                                    reg_offset, reg_size = self.project.arch.registers[cc.cc.RETURN_VAL.reg_name]
                                    last_stmt.ret_expr = ailment.Expr.Register(
                                        None,
                                        None,
                                        reg_offset,
                                        reg_size * 8,
                                        ins_addr=callsite_ins_addr,
                                        reg_name=cc.cc.RETURN_VAL.reg_name,
                                    )

        # finally, recover the calling convention of the current function
        if self.function.prototype is None or self.function.calling_convention is None:
            self.project.analyses.CompleteCallingConventions(
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
        Convert a VEX block to an AIL block.

        :param block_node:  A BlockNode instance.
        :return:            An converted AIL block.
        :rtype:             ailment.Block
        """

        if type(block_node) is not BlockNode:
            return block_node

        block = self.project.factory.block(block_node.addr, block_node.size, cross_insn_opt=False)
        if block.vex.jumpkind not in {"Ijk_Call", "Ijk_Boring", "Ijk_Ret"} and not block.vex.jumpkind.startswith(
            "Ijk_Sys"
        ):
            # we don't support lifting this block. use a dummy block instead
            statements = [
                ailment.Stmt.DirtyStatement(
                    self._ail_manager.next_atom(),
                    f"Unsupported jumpkind {block.vex.jumpkind} at address {block_node.addr}",
                    ins_addr=block_node.addr,
                )
            ]
            ail_block = ailment.Block(block_node.addr, block_node.size, statements=statements)
            return ail_block

        ail_block = ailment.IRSBConverter.convert(block.vex, self._ail_manager)
        return ail_block

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
                successors = self._cfg.get_successors(node, excluding_fakeret=True, jumpkind="Ijk_Call")
                if len(successors) == 1 and not isinstance(
                    self.project.hooked_by(successors[0].addr), UnresolvableCallTarget
                ):
                    # found a single successor - replace the last statement
                    new_last_stmt = last_stmt.copy()
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
                        if target_func.returning:
                            ret_reg_offset = self.project.arch.ret_offset
                            ret_expr = ailment.Expr.Register(
                                None,
                                None,
                                ret_reg_offset,
                                self.project.arch.bits,
                                reg_name=self.project.arch.translate_register_name(
                                    ret_reg_offset, size=self.project.arch.bits
                                ),
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

    @timethis
    def _make_ailgraph(self) -> networkx.DiGraph:
        graph = self._function_graph_to_ail_graph(self._func_graph)
        return graph

    @timethis
    def _simplify_blocks(
        self,
        ail_graph: networkx.DiGraph,
        remove_dead_memdefs=False,
        stack_pointer_tracker=None,
        cache: dict[ailment.Block, NamedTuple] | None = None,
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
                remove_dead_memdefs=remove_dead_memdefs,
                stack_pointer_tracker=stack_pointer_tracker,
                cache=cache,
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

    def _simplify_block(self, ail_block, remove_dead_memdefs=False, stack_pointer_tracker=None, cache=None):
        """
        Simplify a single AIL block.

        :param ailment.Block ail_block: The AIL block to simplify.
        :param stack_pointer_tracker:   The RegisterDeltaTracker analysis instance.
        :return:                        A simplified AIL block.
        """

        cached_rd, cached_prop = None, None
        cache_item = None
        if cache:
            cache_item = cache.get(ail_block, None)
            if cache_item:
                # cache hit
                cached_rd = cache_item.rd
                cached_prop = cache_item.prop

        simp = self.project.analyses.AILBlockSimplifier(
            ail_block,
            self.function.addr,
            remove_dead_memdefs=remove_dead_memdefs,
            stack_pointer_tracker=stack_pointer_tracker,
            peephole_optimizations=self.peephole_optimizations,
            cached_reaching_definitions=cached_rd,
            cached_propagator=cached_prop,
        )
        # update the cache
        if cache is not None:
            if cache_item:
                del cache[ail_block]
            cache[simp.result_block] = BlockCache(simp._reaching_definitions, simp._propagator)
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
    ):
        """
        Simplify the entire function once.

        :return:    None
        """

        simp = self.project.analyses.AILSimplifier(
            self.function,
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
            if pass_.STAGE != stage:
                continue

            if pass_ in DUPLICATING_OPTS + CONDENSING_OPTS and self.unoptimized_graph is None:
                # we should save a copy at the first time any optimization that could alter the structure
                # of the graph is applied
                self.unoptimized_graph = self._copy_graph(ail_graph)

            a = pass_(
                self.function,
                blocks_by_addr=addr_to_blocks,
                blocks_by_addr_and_idx=addr_and_idx_to_blocks,
                graph=ail_graph,
                variable_kb=variable_kb,
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

        return ail_graph

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
                            ident="arg_%d" % idx,
                            name=arg_names[idx],
                            region=self.function.addr,
                        )
                    elif isinstance(arg, SimStackArg):
                        argvar = SimStackVariable(
                            arg.stack_offset,
                            arg.size,
                            base="bp",
                            ident="arg_%d" % idx,
                            name=arg_names[idx],
                            region=self.function.addr,
                        )
                    elif isinstance(arg, SimStructArg):
                        argvar = SimVariable(
                            ident="arg_%d" % idx,
                            name=arg_names[idx],
                            region=self.function.addr,
                            size=arg.size,
                        )
                    else:
                        raise TypeError("Unsupported function argument type %s." % type(arg))
                    arg_vars.append(argvar)
            return arg_vars
        return []

    @timethis
    def _make_callsites(self, ail_graph, stack_pointer_tracker=None):
        """
        Simplify all function call statements.

        :return:    None
        """

        # Computing reaching definitions
        rd = self.project.analyses.ReachingDefinitions(
            subject=self.function,
            func_graph=ail_graph,
            observe_callback=self._make_callsites_rd_observe_callback,
            use_callee_saved_regs_at_return=not self._register_save_areas_removed,
        )

        class TempClass:  # pylint:disable=missing-class-docstring
            stack_arg_offsets = set()

        def _handler(block):
            csm = self.project.analyses.AILCallSiteMaker(
                block,
                reaching_definitions=rd,
                stack_pointer_tracker=stack_pointer_tracker,
                ail_manager=self._ail_manager,
            )
            if csm.stack_arg_offsets is not None:
                TempClass.stack_arg_offsets |= csm.stack_arg_offsets
            if csm.result_block:
                if csm.result_block != block:
                    ail_block = csm.result_block
                    simp = self.project.analyses.AILBlockSimplifier(
                        ail_block,
                        self.function.addr,
                        stack_pointer_tracker=stack_pointer_tracker,
                        peephole_optimizations=self.peephole_optimizations,
                        stack_arg_offsets=csm.stack_arg_offsets,
                    )
                    return simp.result_block
            return None

        # rewriting call-sites at this point, pre-inlining, causes issues with incorrect call signatures
        if not self._inlining_parents:
            AILGraphWalker(ail_graph, _handler, replace_nodes=True).walk()

        return ail_graph, TempClass.stack_arg_offsets

    @timethis
    def _make_returns(self, ail_graph: networkx.DiGraph) -> networkx.DiGraph:
        """
        Work on each return statement and fill in its return expressions.
        """
        if self._inlining_parents:
            # for inlining, we want to keep the return statement separate from the return value, so that
            # the former can be removed while preserving the latter
            return ail_graph

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
    def _recover_and_link_variables(self, ail_graph, arg_list):
        # variable recovery
        tmp_kb = KnowledgeBase(self.project) if self.variable_kb is None else self.variable_kb
        tmp_kb.functions = self.kb.functions
        vr = self.project.analyses.VariableRecoveryFast(
            self.function,  # pylint:disable=unused-variable
            func_graph=ail_graph,
            kb=tmp_kb,
            track_sp=False,
            func_args=arg_list,
            unify_variables=False,
        )
        # get ground-truth types
        var_manager = tmp_kb.variables[self.function.addr]
        groundtruth = {}
        for variable in var_manager.variables_with_manual_types:
            vartype = var_manager.variable_to_types.get(variable, None)
            if vartype is not None:
                for tv in vr.var_to_typevars[variable]:
                    groundtruth[tv] = vartype
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
        try:
            tp = self.project.analyses.Typehoon(
                vr.type_constraints,
                vr.func_typevar,
                kb=tmp_kb,
                var_mapping=vr.var_to_typevars,
                must_struct=must_struct,
                ground_truth=groundtruth,
            )
            # tp.pp_constraints()
            # tp.pp_solution()
            tp.update_variable_types(
                self.function.addr,
                {v: t for v, t in vr.var_to_typevars.items() if isinstance(v, (SimRegisterVariable, SimStackVariable))},
            )
            tp.update_variable_types(
                "global",
                {
                    v: t
                    for v, t in vr.var_to_typevars.items()
                    if isinstance(v, SimMemoryVariable) and not isinstance(v, SimStackVariable)
                },
            )
        except Exception:  # pylint:disable=broad-except
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
        var_manager.unify_variables()
        var_manager.assign_unified_variable_names(
            labels=self.kb.labels,
            arg_names=self.function.prototype.arg_names if self.function.prototype else None,
            reset=self._reset_variable_names,
        )

        # Link variables to each statement
        for block in ail_graph.nodes():
            self._link_variables_on_block(block, tmp_kb)

        # Link struct member info to Store statements
        for block in ail_graph.nodes():
            self._link_struct_member_info_on_block(block, tmp_kb)

        if self._cache is not None:
            self._cache.type_constraints = vr.type_constraints
            self._cache.func_typevar = vr.func_typevar
            self._cache.var_to_typevar = vr.var_to_typevars

        return tmp_kb

    def _link_struct_member_info_on_block(self, block, kb):
        variable_manager = kb.variables[self.function.addr]
        for stmt in block.statements:
            if isinstance(stmt, ailment.Stmt.Store) and isinstance((var := stmt.variable), SimStackVariable):
                offset = var.offset
                if offset in variable_manager.stack_offset_to_struct_member_info:
                    stmt.tags["struct_member_info"] = variable_manager.stack_offset_to_struct_member_info[offset]

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

            elif stmt_type is ailment.Stmt.Assignment:
                self._link_variables_on_expr(variable_manager, global_variables, block, stmt_idx, stmt, stmt.dst)
                self._link_variables_on_expr(variable_manager, global_variables, block, stmt_idx, stmt, stmt.src)

            elif stmt_type is ailment.Stmt.ConditionalJump:
                self._link_variables_on_expr(variable_manager, global_variables, block, stmt_idx, stmt, stmt.condition)

            elif stmt_type is ailment.Stmt.Call:
                self._link_variables_on_call(variable_manager, global_variables, block, stmt_idx, stmt, is_expr=False)

            elif stmt_type is ailment.Stmt.Return:
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
                if offset == 0 or (isinstance(offset, ailment.Expr.Const) and offset.value == 0):
                    if "reference_variable" in base_addr.tags:
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

        elif type(expr) is ailment.Expr.Convert:
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

        elif isinstance(expr, ailment.Expr.Const):
            # custom string?
            if hasattr(expr, "custom_string") and expr.custom_string is True:
                s = self.kb.custom_strings[expr.value]
                expr.tags["reference_values"] = {
                    SimTypePointer(SimTypeChar().with_arch(self.project.arch)).with_arch(self.project.arch): s.decode(
                        "ascii"
                    ),
                }
            else:
                # global variable?
                global_vars = global_variables.get_global_variables(expr.value)
                if not global_vars:
                    # detect if there is a related symbol
                    if self.project.loader.find_object_containing(expr.value):
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

    def _function_graph_to_ail_graph(self, func_graph, blocks_by_addr_and_size=None):
        if blocks_by_addr_and_size is None:
            blocks_by_addr_and_size = self._blocks_by_addr_and_size

        node_to_block_mapping = {}
        graph = networkx.DiGraph()

        for node in func_graph.nodes():
            ail_block = blocks_by_addr_and_size.get((node.addr, node.size), node)
            node_to_block_mapping[node] = ail_block

            if ail_block is not None:
                graph.add_node(ail_block)

        for src_node, dst_node, data in func_graph.edges(data=True):
            src = node_to_block_mapping[src_node]
            dst = node_to_block_mapping[dst_node]

            if dst is not None:
                graph.add_edge(src, dst, **data)

        return graph

    def _rewrite_ite_expressions(self, ail_graph):
        cfg = self._cfg
        for block in list(ail_graph):
            if cfg is not None and block.addr in cfg.jump_tables:
                continue

            ite_ins_addrs = []
            for stmt in block.statements:
                if isinstance(stmt, ailment.Stmt.Assignment) and isinstance(stmt.src, ailment.Expr.ITE):
                    if stmt.ins_addr not in ite_ins_addrs:
                        ite_ins_addrs.append(stmt.ins_addr)

            if ite_ins_addrs:
                block_addr = block.addr
                for ite_ins_addr in ite_ins_addrs:
                    block_addr = self._create_triangle_for_ite_expression(ail_graph, block_addr, ite_ins_addr)
                    if block_addr is None or block_addr >= block.addr + block.original_size:
                        break

    def _create_triangle_for_ite_expression(self, ail_graph, block_addr: int, ite_ins_addr: int):
        # lift the ite instruction to get its size
        ite_insn_size = self.project.factory.block(ite_ins_addr, num_inst=1).size
        if ite_insn_size <= 2:  # we need an address for true_block and another address for false_block
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

        ite_expr: ailment.Expr.ITE = ite_expr_stmt.src
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

        false_block_ail.statements[ite_expr_stmt_idx] = ailment.Stmt.Assignment(
            ite_expr_stmt.idx, ite_expr_stmt.dst, ite_expr_stmt.src.iffalse, **ite_expr_stmt.tags
        )

        original_block = next(iter(b for b in ail_graph if b.addr == block_addr))

        original_block_in_edges = list(ail_graph.in_edges(original_block))
        original_block_out_edges = list(ail_graph.out_edges(original_block))

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

        ail_graph.remove_node(original_block)

        if end_block_ail not in ail_graph:
            # newly created. add it and the necessary edges into the graph
            for _, dst in original_block_out_edges:
                if dst is original_block:
                    ail_graph.add_edge(end_block_ail, new_head_ail)
                else:
                    ail_graph.add_edge(end_block_ail, dst)

        # in edges
        for src, _ in original_block_in_edges:
            if src is original_block:
                # loop
                ail_graph.add_edge(end_block_ail, new_head_ail)
            else:
                ail_graph.add_edge(src, new_head_ail)

        # triangle
        ail_graph.add_edge(new_head_ail, true_block_ail)
        ail_graph.add_edge(new_head_ail, false_block_ail)
        ail_graph.add_edge(true_block_ail, end_block_ail)
        ail_graph.add_edge(false_block_ail, end_block_ail)

        return end_block_ail.addr

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
                                first_cond_jump = first_conditional_jump(pred)
                                if first_cond_jump is not None and first_cond_jump is not last_stmt:
                                    patch_conditional_jump_target(first_cond_jump, node.addr, succs[0].addr)
                            ail_graph.add_edge(pred, succs[0])
                        ail_graph.remove_node(node)

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
            stmt: ailment.statement.Statement,
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
            block: ailment.Block | None,
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
            block: ailment.Block | None,
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

        def handle_Store(stmt_idx: int, stmt: ailment.statement.Store, block: ailment.Block | None):
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

    @staticmethod
    def _make_callsites_rd_observe_callback(ob_type, **kwargs):
        if ob_type != "insn":
            return False
        stmt = kwargs.pop("stmt")
        op_type = kwargs.pop("op_type")
        return isinstance(stmt, ailment.Stmt.Call) and op_type == OP_BEFORE

    def parse_variable_addr(self, addr: ailment.Expr.Expression) -> tuple[Any, Any] | None:
        if isinstance(addr, ailment.Expr.Const):
            return addr, 0
        if isinstance(addr, ailment.Expr.BinaryOp):
            if addr.op == "Add":
                op0, op1 = addr.operands
                if (
                    isinstance(op0, ailment.Expr.Const)
                    and self.project.loader.find_object_containing(op0.value) is not None
                ):
                    return op0, op1
                elif (
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
                preds = list(pred for pred in graph.predecessors(node) if pred is not node)
                succs = list(succ for succ in graph.successors(node) if succ is not node)
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
                        raise RemoveNodeNotice()
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
                        raise RemoveNodeNotice()
                elif not preds or not succs:
                    raise RemoveNodeNotice()

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

    def _rewrite_alloca(self, ail_graph):
        # pylint:disable=too-many-boolean-expressions
        alloca_node = None
        sp_equal_to = None

        for node in ail_graph:
            if ail_graph.in_degree[node] == 2 and ail_graph.out_degree[node] == 2:
                succs = ail_graph.successors(node)
                if node in succs:
                    # self loop!
                    if len(node.statements) >= 6:
                        stmt0 = node.statements[1]  # skip the LABEL statement
                        stmt1 = node.statements[2]
                        last_stmt = node.statements[-1]
                        if (
                            isinstance(stmt0, ailment.Stmt.Assignment)
                            and isinstance(stmt0.dst, ailment.Expr.Register)
                            and isinstance(stmt0.src, ailment.Expr.StackBaseOffset)
                            and stmt0.src.offset == -0x1000
                        ):
                            if (
                                isinstance(stmt1, ailment.Stmt.Store)
                                and isinstance(stmt1.addr, ailment.Expr.StackBaseOffset)
                                and stmt1.addr.offset == -0x1000
                                and isinstance(stmt1.data, ailment.Expr.Load)
                                and isinstance(stmt1.data.addr, ailment.Expr.StackBaseOffset)
                                and stmt1.data.addr.offset == -0x1000
                            ):
                                if (
                                    isinstance(last_stmt, ailment.Stmt.ConditionalJump)
                                    and isinstance(last_stmt.condition, ailment.Expr.BinaryOp)
                                    and last_stmt.condition.op == "CmpEQ"
                                    and isinstance(last_stmt.condition.operands[0], ailment.Expr.StackBaseOffset)
                                    and last_stmt.condition.operands[0].offset == -0x1000
                                    and isinstance(last_stmt.condition.operands[1], ailment.Expr.Register)
                                    and isinstance(last_stmt.false_target, ailment.Expr.Const)
                                    and last_stmt.false_target.value == node.addr
                                ):
                                    # found it!
                                    alloca_node = node
                                    sp_equal_to = ailment.Expr.BinaryOp(
                                        None,
                                        "Sub",
                                        [
                                            ailment.Expr.Register(
                                                None, None, self.project.arch.sp_offset, self.project.arch.bits
                                            ),
                                            last_stmt.condition.operands[1],
                                        ],
                                        False,
                                    )
                                    break

        if alloca_node is not None:
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

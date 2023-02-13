import copy
from collections import defaultdict, namedtuple
import logging
from typing import Dict, List, Tuple, Set, Optional, Iterable, Union, Type, Any, NamedTuple, TYPE_CHECKING

import networkx

import ailment

from ...knowledge_base import KnowledgeBase
from ...knowledge_plugins.functions import Function
from ...codenode import BlockNode
from ...utils import timethis
from ...calling_conventions import SimRegArg, SimStackArg, SimFunctionArgument
from ...sim_type import (
    SimTypeChar,
    SimTypeInt,
    SimTypeLongLong,
    SimTypeShort,
    SimTypeFunction,
    SimTypeBottom,
    SimTypeFloat,
)
from ...sim_variable import SimVariable, SimStackVariable, SimRegisterVariable, SimMemoryVariable
from ...knowledge_plugins.key_definitions.constants import OP_BEFORE
from ...procedures.stubs.UnresolvableCallTarget import UnresolvableCallTarget
from ...procedures.stubs.UnresolvableJumpTarget import UnresolvableJumpTarget
from .. import Analysis, register_analysis
from ..cfg.cfg_base import CFGBase
from ..reaching_definitions import ReachingDefinitionsAnalysis
from .ailgraph_walker import AILGraphWalker, RemoveNodeNotice
from .ailblock_walker import AILBlockWalker
from .optimization_passes import get_default_optimization_passes, OptimizationPassStage

if TYPE_CHECKING:
    from angr.knowledge_plugins.cfg import CFGModel
    from .decompilation_cache import DecompilationCache
    from .peephole_optimizations import PeepholeOptimizationStmtBase, PeepholeOptimizationExprBase

l = logging.getLogger(name=__name__)


BlockCache = namedtuple("BlockCache", ("rd", "prop"))


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
        peephole_optimizations: Optional[
            Iterable[Union[Type["PeepholeOptimizationStmtBase"], Type["PeepholeOptimizationExprBase"]]]
        ] = None,  # pylint:disable=line-too-long
        must_struct: Optional[Set[str]] = None,
        variable_kb=None,
        reset_variable_names=False,
        cache: Optional["DecompilationCache"] = None,
    ):
        if not func.normalized:
            raise ValueError("Decompilation must work on normalized function graphs.")

        self.function = func

        self.graph = None
        self.cc_graph: Optional[networkx.DiGraph] = None
        self.arg_list = None
        self.variable_kb = variable_kb
        self.externs: Set[SimMemoryVariable] = set()

        self._func_graph: Optional[networkx.DiGraph] = None
        self._ail_manager = None
        self._blocks_by_addr_and_size = {}

        self._fold_callexprs_into_conditions = fold_callexprs_into_conditions
        self._insert_labels = insert_labels
        self._remove_dead_memdefs = remove_dead_memdefs
        self._exception_edges = exception_edges
        self._sp_tracker_track_memory = sp_tracker_track_memory
        self._cfg: Optional["CFGModel"] = cfg
        self.peephole_optimizations = peephole_optimizations
        self._must_struct = must_struct
        self._reset_variable_names = reset_variable_names
        self.reaching_definitions: Optional[ReachingDefinitionsAnalysis] = None
        self._cache = cache

        self._new_block_addrs = set()

        # sanity checks
        if not self.kb.functions:
            l.warning("No function is available in kb.functions. It will lead to a suboptimal conversion result.")

        if optimization_passes is not None:
            self._optimization_passes = optimization_passes
        else:
            self._optimization_passes = get_default_optimization_passes(self.project.arch, self.project.simos.name)
            l.debug("Get %d optimization passes for the current binary.", len(self._optimization_passes))

        self._analyze()

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

    def _analyze(self):
        is_pcode_arch = ":" in self.project.arch.name

        # Set up the function graph according to configurations
        self._update_progress(0.0, text="Setting up function graph")
        self._set_function_graph()

        # Remove alignment blocks
        self._update_progress(5.0, text="Removing alignment blocks")
        self._remove_alignment_blocks()

        # if the graph is empty, don't continue
        if not self._func_graph:
            return

        # Make sure calling conventions of all functions that the current function calls have been recovered
        if not is_pcode_arch:
            self._update_progress(10.0, text="Recovering calling conventions")
            self._recover_calling_conventions()

        # initialize the AIL conversion manager
        self._ail_manager = ailment.Manager(arch=self.project.arch)

        # Track stack pointers
        self._update_progress(15.0, text="Tracking stack pointers")
        spt = self._track_stack_pointers()

        # Convert VEX blocks to AIL blocks and then simplify them

        self._update_progress(20.0, text="Converting VEX to AIL")
        self._convert_all()

        ail_graph = self._make_ailgraph()
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
        block_simplification_cache: Optional[Dict[ailment.Block, NamedTuple]] = {}

        # Simplify blocks
        # we never remove dead memory definitions before making callsites. otherwise stack arguments may go missing
        # before they are recognized as stack arguments.
        self._update_progress(35.0, text="Simplifying blocks 1")
        ail_graph = self._simplify_blocks(
            ail_graph, stack_pointer_tracker=spt, remove_dead_memdefs=False, cache=block_simplification_cache
        )

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

        # Simplify the entire function for the third time
        self._update_progress(65.0, text="Simplifying function 3")
        self._simplify_function(
            ail_graph,
            remove_dead_memdefs=self._remove_dead_memdefs,
            stack_arg_offsets=stackarg_offsets,
            unify_variables=True,
            fold_callexprs_into_conditions=self._fold_callexprs_into_conditions,
        )

        self._update_progress(68.0, text="Simplifying blocks 4")
        ail_graph = self._simplify_blocks(
            ail_graph,
            remove_dead_memdefs=self._remove_dead_memdefs,
            stack_pointer_tracker=spt,
            cache=block_simplification_cache,
        )

        # Make function arguments
        self._update_progress(70.0, text="Making argument list")
        arg_list = self._make_argument_list()

        # Run simplification passes
        self._update_progress(75.0, text="Running simplifications 2")
        ail_graph = self._run_simplification_passes(ail_graph, stage=OptimizationPassStage.AFTER_GLOBAL_SIMPLIFICATION)

        # Recover variables on AIL blocks
        self._update_progress(80.0, text="Recovering variables")
        variable_kb = self._recover_and_link_variables(ail_graph, arg_list)

        # Make function prototype
        self._update_progress(90.0, text="Making function prototype")
        self._make_function_prototype(arg_list, variable_kb)

        # Run simplification passes
        self._update_progress(95.0, text="Running simplifications 3")
        ail_graph = self._run_simplification_passes(
            ail_graph, stage=OptimizationPassStage.AFTER_VARIABLE_RECOVERY, variable_kb=variable_kb
        )

        # remove empty nodes from the graph
        ail_graph = self.remove_empty_nodes(ail_graph)

        self.graph = ail_graph
        self.arg_list = arg_list
        self.variable_kb = variable_kb
        self.cc_graph = self.copy_graph()
        self.externs = self._collect_externs(ail_graph, variable_kb)

    def copy_graph(self) -> networkx.DiGraph:
        """
        Copy AIL Graph.

        :return: A copy of the AIl graph.
        """
        graph_copy = networkx.DiGraph()
        block_mapping = {}
        # copy all blocks
        for block in self.graph.nodes():
            new_block = copy.copy(block)
            new_stmts = copy.copy(block.statements)
            new_block.statements = new_stmts
            block_mapping[block] = new_block
            graph_copy.add_node(new_block)

        # copy all edges
        for src, dst, data in self.graph.edges(data=True):
            new_src = block_mapping[src]
            new_dst = block_mapping[dst]
            graph_copy.add_edge(new_src, new_dst, **data)
        return graph_copy

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
            if not isinstance(node, Function):
                continue

            # case 0: the calling convention and prototype are available
            if node.calling_convention is not None and node.prototype is not None:
                continue

            call_sites = []
            for pred in self.function.transition_graph.predecessors(node):
                call_sites.append(pred)
            # case 1: calling conventions and prototypes are available at every single call site
            if all(self.kb.callsite_prototypes.has_prototype(callsite.addr) for callsite in call_sites):
                continue

            # case 2: the callee is a SimProcedure
            if node.is_simprocedure:
                cc = self.project.analyses.CallingConvention(node)
                if cc.cc is not None and cc.prototype is not None:
                    node.calling_convention = cc.cc
                    node.prototype = cc.prototype
                    continue

            # case 3: the callee is a PLT function
            if node.is_plt:
                cc = self.project.analyses.CallingConvention(node)
                if cc.cc is not None and cc.prototype is not None:
                    node.calling_convention = cc.cc
                    node.prototype = cc.prototype
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

        # finally, recovery the calling convention of the current function
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
        if hasattr(self.project.arch, "bp_offset") and self.project.arch.bp_offset is not None:
            regs.add(self.project.arch.bp_offset)
        spt = self.project.analyses.StackPointerTracker(self.function, regs, track_memory=self._sp_tracker_track_memory)
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

        block = self.project.factory.block(block_node.addr, block_node.size)

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

                            ret_stmt = ailment.Stmt.Return(None, None, [], **last_stmt.tags)
                            ret_block = ailment.Block(self.new_block_addr(), 1, statements=[ret_stmt])
                            ail_graph.add_edge(block, ret_block)
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
        cache: Optional[Dict[ailment.Block, NamedTuple]] = None,
    ):
        """
        Simplify all blocks in self._blocks.

        :param ail_graph:               The AIL function graph.
        :param stack_pointer_tracker:   The RegisterDeltaTracker analysis instance.
        :param cache:                   A block-level cache that stores reaching definition analysis results and
                                        propagation results.
        :return:                        None
        """

        blocks_by_addr_and_idx: Dict[Tuple[int, Optional[int]], ailment.Block] = {}

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
        addr_and_idx_to_blocks: Dict[Tuple[int, Optional[int]], ailment.Block] = {}
        addr_to_blocks: Dict[int, Set[ailment.Block]] = defaultdict(set)

        # update blocks_map to allow node_addr to node lookup
        def _updatedict_handler(node):
            addr_and_idx_to_blocks[(node.addr, node.idx)] = node
            addr_to_blocks[node.addr].add(node)

        AILGraphWalker(ail_graph, _updatedict_handler).walk()

        # Run each pass
        for pass_ in self._optimization_passes:
            if pass_.STAGE != stage:
                continue

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

        return ail_graph

    @timethis
    def _make_argument_list(self) -> List[SimVariable]:
        if self.function.calling_convention is not None and self.function.prototype is not None:
            args: List[SimFunctionArgument] = self.function.calling_convention.arg_locs(self.function.prototype)
            arg_vars: List[SimVariable] = []
            if args:
                for idx, arg in enumerate(args):
                    if isinstance(arg, SimRegArg):
                        argvar = SimRegisterVariable(
                            self.project.arch.registers[arg.reg_name][0],
                            arg.size,
                            ident="arg_%d" % idx,
                            name="a%d" % idx,
                            region=self.function.addr,
                        )
                    elif isinstance(arg, SimStackArg):
                        argvar = SimStackVariable(
                            arg.stack_offset,
                            arg.size,
                            base="bp",
                            ident="arg_%d" % idx,
                            name="a%d" % idx,
                            region=self.function.addr,
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
            subject=self.function, func_graph=ail_graph, observe_callback=self._make_callsites_rd_observe_callback
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

        AILGraphWalker(ail_graph, _handler, replace_nodes=True).walk()

        return ail_graph, TempClass.stack_arg_offsets

    @timethis
    def _make_returns(self, ail_graph: networkx.DiGraph) -> networkx.DiGraph:
        """
        Work on each return statement and fill in its return expressions.
        """

        if self.function.calling_convention is None:
            # unknown calling convention. cannot do much about return expressions.
            return ail_graph

        # Block walker

        def _handle_Return(
            stmt_idx: int, stmt: ailment.Stmt.Return, block: Optional[ailment.Block]
        ):  # pylint:disable=unused-argument
            if (
                block is not None
                and not stmt.ret_exprs
                and self.function.prototype is not None
                and self.function.prototype.returnty is not None
                and type(self.function.prototype.returnty) is not SimTypeBottom
            ):
                new_stmt = stmt.copy()
                ret_val = self.function.calling_convention.return_val(self.function.prototype.returnty)
                if isinstance(ret_val, SimRegArg):
                    reg = self.project.arch.registers[ret_val.reg_name]
                    new_stmt.ret_exprs.append(
                        ailment.Expr.Register(
                            self._next_atom(),
                            None,
                            reg[0],
                            ret_val.size * self.project.arch.byte_width,
                            reg_name=self.project.arch.translate_register_name(reg[0], ret_val.size),
                        )
                    )
                else:
                    l.warning("Unsupported type of return expression %s.", type(ret_val))
                block.statements[stmt_idx] = new_stmt

        def _handler(block):
            walker = AILBlockWalker()
            # we don't need to handle any statement besides Returns
            walker.stmt_handlers.clear()
            walker.expr_handlers.clear()
            walker.stmt_handlers[ailment.Stmt.Return] = _handle_Return
            walker.walk(block)

        # Graph walker

        AILGraphWalker(ail_graph, _handler, replace_nodes=True).walk()

        return ail_graph

    @timethis
    def _make_function_prototype(self, arg_list: List[SimVariable], variable_kb):
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
        vr = self.project.analyses.VariableRecoveryFast(
            self.function,  # pylint:disable=unused-variable
            func_graph=ail_graph,
            kb=tmp_kb,
            track_sp=False,
            func_args=arg_list,
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
            reset=self._reset_variable_names,
        )

        # Link variables to each statement
        for block in ail_graph.nodes():
            self._link_variables_on_block(block, tmp_kb)

        if self._cache is not None:
            self._cache.type_constraints = vr.type_constraints
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
                mem_vars = variable_manager.find_variables_by_atom(block.addr, stmt_idx, stmt)
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
            reg_vars = variable_manager.find_variables_by_atom(block.addr, stmt_idx, expr)
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
            variables = variable_manager.find_variables_by_atom(block.addr, stmt_idx, expr)
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
            variables = variable_manager.find_variables_by_atom(block.addr, stmt_idx, expr)
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
            variables = variable_manager.find_variables_by_atom(block.addr, stmt_idx, expr)
            if len(variables) >= 1:
                var, offset = next(iter(variables))
                expr.variable = var
                expr.variable_offset = offset
            else:
                self._link_variables_on_expr(variable_manager, global_variables, block, stmt_idx, stmt, expr.operands)

        elif type(expr) is ailment.Expr.Convert:
            self._link_variables_on_expr(variable_manager, global_variables, block, stmt_idx, stmt, expr.operand)

        elif type(expr) is ailment.Expr.ITE:
            variables = variable_manager.find_variables_by_atom(block.addr, stmt_idx, expr)
            if len(variables) >= 1:
                var, offset = next(iter(variables))
                expr.variable = var
                expr.variable_offset = offset
            else:
                self._link_variables_on_expr(variable_manager, global_variables, block, stmt_idx, stmt, expr.cond)
                self._link_variables_on_expr(variable_manager, global_variables, block, stmt_idx, stmt, expr.iftrue)
                self._link_variables_on_expr(variable_manager, global_variables, block, stmt_idx, stmt, expr.iftrue)

        elif isinstance(expr, ailment.Expr.BasePointerOffset):
            variables = variable_manager.find_variables_by_atom(block.addr, stmt_idx, expr)
            if len(variables) >= 1:
                var, offset = next(iter(variables))
                expr.variable = var
                expr.variable_offset = offset

        elif isinstance(expr, ailment.Expr.Const):
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

    @staticmethod
    def _remove_redundant_jump_blocks(ail_graph):
        def first_conditional_jump(block: ailment.Block) -> Optional[ailment.Stmt.ConditionalJump]:
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
        walker = AILBlockWalker()
        variables = set()

        def handle_expr(
            expr_idx: int,
            expr: ailment.expression.Load,
            stmt_idx: int,
            stmt: ailment.statement.Statement,
            block: Optional[ailment.Block],
        ):
            if expr is None:
                return None
            for v in [
                getattr(expr, "variable", None),
                expr.tags.get("reference_variable", None) if hasattr(expr, "tags") else None,
            ]:
                if v and v in global_vars:
                    variables.add(v)
            return AILBlockWalker._handle_expr(walker, expr_idx, expr, stmt_idx, stmt, block)

        def handle_Store(stmt_idx: int, stmt: ailment.statement.Store, block: Optional[ailment.Block]):
            if stmt.variable and stmt.variable in global_vars:
                variables.add(stmt.variable)
            return AILBlockWalker._handle_Store(walker, stmt_idx, stmt, block)

        walker.stmt_handlers[ailment.statement.Store] = handle_Store
        walker._handle_expr = handle_expr
        AILGraphWalker(ail_graph, walker.walk).walk()
        return variables

    def _next_atom(self) -> int:
        return self._ail_manager.next_atom()

    @staticmethod
    def _make_callsites_rd_observe_callback(ob_type, **kwargs):
        if ob_type != "insn":
            return False
        stmt = kwargs.pop("stmt")
        op_type = kwargs.pop("op_type")
        return isinstance(stmt, ailment.Stmt.Call) and op_type == OP_BEFORE

    def parse_variable_addr(self, addr: ailment.Expr.Expression) -> Optional[Tuple[Any, Any]]:
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


register_analysis(Clinic, "Clinic")

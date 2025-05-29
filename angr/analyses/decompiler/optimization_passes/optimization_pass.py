# pylint:disable=unused-argument
from __future__ import annotations
import logging
from collections import namedtuple
from collections.abc import Generator
from typing import Any, TYPE_CHECKING
from enum import Enum

import networkx

import angr.ailment as ailment

from angr.analyses.decompiler import RegionIdentifier
from angr.analyses.decompiler.ailgraph_walker import AILGraphWalker
from angr.analyses.decompiler.condition_processor import ConditionProcessor
from angr.analyses.decompiler.goto_manager import Goto, GotoManager
from angr.analyses.decompiler.structuring import RecursiveStructurer, SAILRStructurer
from angr.analyses.decompiler.utils import add_labels, remove_edges_in_ailgraph
from angr.analyses.decompiler.counters import ControlFlowStructureCounter
from angr.project import Project

if TYPE_CHECKING:
    from angr.knowledge_plugins.functions import Function
    from angr.analyses.decompiler.stack_item import StackItem


_l = logging.getLogger(__name__)


BlockCache = namedtuple("BlockCache", ("rd", "prop"))


class MultipleBlocksException(Exception):
    """
    An exception that is raised in _get_block() where multiple blocks satisfy the criteria but only one block was
    requested.
    """


class OptimizationPassStage(Enum):
    """
    Enums about optimization pass stages.

    Note that the region identification pass (RegionIdentifier) may modify existing AIL blocks *without updating the
    topology of the original AIL graph*. For example, loop successor refinement may modify create a new AIL block with
    an artificial address, and alter existing jump targets of jump statements and conditional jump statements to point
    to this new block. However, loop successor refinement does not update the topology of the original AIL graph, which
    means this new AIL block does not exist in the original AIL graph. As a result, until this behavior of
    RegionIdentifier changes in the future, DURING_REGION_IDENTIFICATION optimization passes should not modify existing
    jump targets.
    """

    AFTER_AIL_GRAPH_CREATION = 0
    BEFORE_SSA_LEVEL0_TRANSFORMATION = 1
    AFTER_SINGLE_BLOCK_SIMPLIFICATION = 2
    BEFORE_SSA_LEVEL1_TRANSFORMATION = 3
    AFTER_MAKING_CALLSITES = 4
    AFTER_GLOBAL_SIMPLIFICATION = 5
    BEFORE_VARIABLE_RECOVERY = 6
    AFTER_VARIABLE_RECOVERY = 7
    BEFORE_REGION_IDENTIFICATION = 8
    DURING_REGION_IDENTIFICATION = 9
    AFTER_STRUCTURING = 10


class BaseOptimizationPass:
    """
    The base class for any optimization pass.
    """

    ARCHES = []  # strings of supported architectures
    PLATFORMS = []  # strings of supported platforms. Can be one of the following: "win32", "linux"
    STAGE: OptimizationPassStage  # Specifies when this optimization pass should be executed
    STRUCTURING: list[str] | None = (
        None  # specifies if this optimization pass is specific to a certain structuring algorithm
    )
    NAME = "N/A"
    DESCRIPTION = "N/A"

    def __init__(self, func):
        self._func: Function = func

    @property
    def project(self) -> Project:
        assert self._func.project is not None
        return self._func.project

    @property
    def kb(self):
        return self.project.kb

    def analyze(self):
        ret, cache = self._check()
        if ret:
            self._analyze(cache=cache)

    def _check(self):
        """
        Check if this optimization applies to this function.

        :returns: a tuple of (does_apply, cache) where cache is a way to pass
                  information to _analyze so it does not have to be recalculated
        """
        raise NotImplementedError

    def _analyze(self, cache=None):
        """
        Run the analysis.

        :param cache: information passed from _check so it does not have to be
                      recalculated
        :returns: None
        """
        raise NotImplementedError


class OptimizationPass(BaseOptimizationPass):
    """
    The base class for any function-level graph optimization pass.
    """

    _graph: networkx.DiGraph

    def __init__(
        self,
        func,
        *,
        graph,
        blocks_by_addr=None,
        blocks_by_addr_and_idx=None,
        variable_kb=None,
        region_identifier=None,
        reaching_definitions=None,
        vvar_id_start: int = 0,
        entry_node_addr=None,
        scratch: dict[str, Any] | None = None,
        force_loop_single_exit: bool = True,
        complete_successors: bool = False,
        avoid_vvar_ids: set[int] | None = None,
        arg_vvars: set[int] | None = None,
        peephole_optimizations=None,
        stack_pointer_tracker=None,
        **kwargs,
    ):
        super().__init__(func)
        # self._blocks is just a cache
        self._blocks_by_addr: dict[int, set[ailment.Block]] = blocks_by_addr or {}
        self._blocks_by_addr_and_idx: dict[tuple[int, int | None], ailment.Block] = blocks_by_addr_and_idx or {}
        self._graph = graph
        self._variable_kb = variable_kb
        self._ri = region_identifier
        self._rd = reaching_definitions
        self._scratch = scratch if scratch is not None else {}
        self._new_block_addrs = set()
        self._arg_vvars = arg_vvars
        self.vvar_id_start = vvar_id_start
        self.entry_node_addr: tuple[int, int | None] = (
            entry_node_addr if entry_node_addr is not None else (func.addr, None)
        )
        self._force_loop_single_exit = force_loop_single_exit
        self._complete_successors = complete_successors
        self._avoid_vvar_ids = avoid_vvar_ids or set()
        self._peephole_optimizations = peephole_optimizations
        self._stack_pointer_tracker = stack_pointer_tracker

        # output
        self.out_graph: networkx.DiGraph | None = None
        self.stack_items: dict[int, StackItem] = {}

    @property
    def blocks_by_addr(self) -> dict[int, set[ailment.Block]]:
        return self._blocks_by_addr

    @property
    def blocks_by_addr_and_idx(self) -> dict[tuple[int, int | None], ailment.Block]:
        return self._blocks_by_addr_and_idx

    #
    # Util methods
    #

    def bfs_nodes(self, depth: int | None = None, start_node: ailment.Block | None = None) -> Generator[ailment.Block]:
        seen = set()

        if start_node is None:
            start_node = self._get_block(self._func.addr)
        if start_node is None:
            return

        queue = [(0, start_node)]
        while queue:
            node_depth, node = queue.pop(0)
            if node in seen:
                continue
            seen.add(node)

            yield node

            if depth is not None and node_depth >= depth:
                continue

            for succ in sorted(self._graph.successors(node), key=lambda x: (x.addr, x.idx if hasattr(x, "idx") else 0)):
                if succ not in seen:
                    queue.append((node_depth + 1, succ))

    def new_block_addr(self) -> int:
        """
        Return a block address that does not conflict with any existing blocks.

        :return:    The block address.
        """
        new_addr = max(self._new_block_addrs) + 1 if self._new_block_addrs else max(self.blocks_by_addr) + 2048
        self._new_block_addrs.add(new_addr)
        return new_addr

    def _get_block(self, addr, **kwargs) -> ailment.Block | None:
        """
        Get exactly one block by its address and optionally, also considering its block ID. An exception,
        MultipleBlocksException, will be raised if there are more than one block satisfying the specified criteria.

        :param addr:        The address of the block.
        :param kwargs:      Optionally, you can specify "idx" to consider the block ID. If "idx" is not specified, this
                            method will return the only block at the specified address, None if there is no block at
                            that address, or raise an exception if there are more than one block at that address.
        :return:            The requested block or None if no block matching the specified criteria exists.
        """

        if not self._blocks_by_addr:
            return None
        idx_specified = "idx" in kwargs
        idx = kwargs.get("idx")
        if not idx_specified:
            blocks = self._blocks_by_addr.get(addr, None)
        else:
            blocks = [self._blocks_by_addr_and_idx.get((addr, idx), None)]
        if not blocks:
            return None
        if len(blocks) == 1:
            return next(iter(blocks))
        if idx_specified:
            raise MultipleBlocksException(
                f"There are {len(blocks)} blocks at address {addr:#x}.{idx} but only one is requested."
            )
        raise MultipleBlocksException(
            f"There are {len(blocks)} blocks at address {addr:#x} (block ID ignored) but only one is requested."
        )

    def _get_blocks(self, addr, idx=None) -> Generator[ailment.Block]:
        if not self._blocks_by_addr:
            return
        else:
            if idx is None:
                blocks = self._blocks_by_addr.get(addr, None)
                if blocks is not None:
                    yield from blocks
            else:
                block = self._blocks_by_addr_and_idx.get((addr, idx), None)
                if block is not None:
                    yield block

    def _update_block(self, old_block, new_block):
        if self.out_graph is None:
            self.out_graph = self._graph  # we do not make copy here for performance reasons. we can change it if needed
            assert self.out_graph is not None

        if old_block not in self.out_graph:
            return

        in_edges = list(self.out_graph.in_edges(old_block, data=True))
        out_edges = list(self.out_graph.out_edges(old_block, data=True))

        self._remove_block(old_block)
        self.out_graph.add_node(new_block)
        self._blocks_by_addr[new_block.addr].add(new_block)
        self._blocks_by_addr_and_idx[(new_block.addr, new_block.idx)] = new_block

        for src, _, data in in_edges:
            if src is old_block:
                src = new_block
            self.out_graph.add_edge(src, new_block, **data)

        for _, dst, data in out_edges:
            if dst is old_block:
                dst = new_block
            self.out_graph.add_edge(new_block, dst, **data)

    def _remove_block(self, block):
        if self.out_graph is None:
            self.out_graph = self._graph
            assert self.out_graph is not None

        if block in self.out_graph:
            self.out_graph.remove_node(block)

        if block.addr in self._blocks_by_addr and block in self._blocks_by_addr[block.addr]:
            self._blocks_by_addr[block.addr].remove(block)
            del self._blocks_by_addr_and_idx[(block.addr, block.idx)]

    @staticmethod
    def _is_add(expr):
        return isinstance(expr, ailment.Expr.BinaryOp) and expr.op == "Add"

    @staticmethod
    def _is_sub(expr):
        return isinstance(expr, ailment.Expr.BinaryOp) and expr.op == "Sub"

    def _simplify_blocks(
        self,
        ail_graph: networkx.DiGraph,
        cache: dict | None = None,
    ):
        """
        Simplify all blocks in self._blocks.

        :param ail_graph:               The AIL function graph.
        :param cache:                   A block-level cache that stores reaching definition analysis results and
                                        propagation results.
        :return:                        None
        """

        blocks_by_addr_and_idx: dict[tuple[int, int | None], ailment.Block] = {}

        for ail_block in ail_graph.nodes():
            simplified = self._simplify_block(
                ail_block,
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

    def _simplify_block(self, ail_block, cache=None):
        """
        Simplify a single AIL block.

        :param ailment.Block ail_block: The AIL block to simplify.
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
            self._func.addr,
            peephole_optimizations=self._peephole_optimizations,
            cached_reaching_definitions=cached_rd,
            cached_propagator=cached_prop,
        )
        # update the cache
        if cache is not None:
            if cache_item:
                del cache[cache_key]
            cache[cache_key] = BlockCache(simp._reaching_definitions, simp._propagator)
        return simp.result_block

    def _simplify_graph(self, graph):
        MAX_SIMP_ITERATION = 8
        for _ in range(MAX_SIMP_ITERATION):
            self._simplify_blocks(graph)
            simp = self.project.analyses.AILSimplifier(
                self._func,
                func_graph=graph,
                use_callee_saved_regs_at_return=False,
                gp=self._func.info.get("gp", None) if self.project.arch.name in {"MIPS32", "MIPS64"} else None,
                avoid_vvar_ids=self._avoid_vvar_ids,
            )
            if simp.simplified:
                graph = simp.func_graph
            else:
                break
        else:
            _l.warning("Failed to reach fixed point after %s simplification iterations.", MAX_SIMP_ITERATION)
        return graph

    def _recover_regions(self, graph: networkx.DiGraph, condition_processor=None, update_graph: bool = False):
        return self.project.analyses[RegionIdentifier].prep(kb=self.kb)(
            self._func,
            graph=graph,
            cond_proc=condition_processor or ConditionProcessor(self.project.arch),
            update_graph=update_graph,
            force_loop_single_exit=self._force_loop_single_exit,
            complete_successors=self._complete_successors,
            entry_node_addr=self.entry_node_addr,
        )


class SequenceOptimizationPass(BaseOptimizationPass):
    """
    The base class for any sequence node optimization pass.
    """

    def __init__(self, func, seq=None, **kwargs):
        super().__init__(func)
        self.seq = seq
        self.out_seq = None


class StructuringOptimizationPass(OptimizationPass):
    """
    The base class for any optimization pass that requires structuring. Optimization passes that inherit from this class
    should directly depend on structuring artifacts, such as regions and gotos. Otherwise, they should use
    OptimizationPass. This is the heaviest (computation time) optimization pass class.

    By default this type of optimization should work:
    - on any architecture
    - on any platform
    - during region identification (to have iterative structuring)
    - only with the SAILR structuring algorithm
    """

    ARCHES = None
    PLATFORMS = None
    STRUCTURING = [SAILRStructurer.NAME]
    STAGE = OptimizationPassStage.DURING_REGION_IDENTIFICATION

    _initial_gotos: set[Goto]
    _goto_manager: GotoManager
    _prev_graph: networkx.DiGraph

    def __init__(
        self,
        func,
        prevent_new_gotos: bool = True,
        strictly_less_gotos: bool = False,
        recover_structure_fails: bool = True,
        must_improve_rel_quality: bool = True,
        max_opt_iters: int = 1,
        simplify_ail: bool = True,
        require_gotos: bool = True,
        readd_labels: bool = False,
        edges_to_remove: list[tuple[tuple[int, int | None], tuple[int, int | None]]] | None = None,
        **kwargs,
    ):
        super().__init__(func, **kwargs)
        self._prevent_new_gotos = prevent_new_gotos
        self._strictly_less_gotos = strictly_less_gotos
        self._recover_structure_fails = recover_structure_fails
        self._max_opt_iters = max_opt_iters
        self._simplify_ail = simplify_ail
        self._require_gotos = require_gotos
        self._must_improve_rel_quality = must_improve_rel_quality
        self._readd_labels = readd_labels
        self._edges_to_remove = edges_to_remove or []

        # relative quality metrics (excludes gotos)
        self._initial_structure_counter = None
        self._current_structure_counter = None

    def _analyze(self, cache=None) -> bool:
        raise NotImplementedError

    def analyze(self):
        """
        Wrapper for _analyze() that verifies the graph is structurable before and after the optimization.
        """
        # replace the normal check in OptimizationPass.analyze()
        ret, cache = self._check()
        if not ret:
            return

        if not self._graph_is_structurable(self._graph, initial=True):
            return

        self._initial_gotos = self._goto_manager.gotos.copy()
        if self._require_gotos and not self._initial_gotos:
            return

        # setup for the very first analysis
        self.out_graph = networkx.DiGraph(self._graph)
        if self._max_opt_iters > 1:
            self._fixed_point_analyze(cache=cache)
        else:
            updates = self._analyze(cache=cache)
            if not updates:
                self.out_graph = None

        # analysis is complete, no out_graph means it failed somewhere along the way
        if self.out_graph is None:
            return

        # since all checks have completed, add labels back out here
        if self._readd_labels:
            self.out_graph = add_labels(self.out_graph)

        if not self._graph_is_structurable(self.out_graph, readd_labels=False):
            self.out_graph = None
            return

        # simplify the AIL graph
        if self._simplify_ail:
            # this should not (TM) change the structure of the graph but is needed for later optimizations
            self.out_graph = self._simplify_graph(self.out_graph)

        if self._prevent_new_gotos:
            prev_gotos = len(self._initial_gotos)
            new_gotos = len(self._get_new_gotos())
            if (self._strictly_less_gotos and (new_gotos >= prev_gotos)) or (
                not self._strictly_less_gotos and (new_gotos > prev_gotos)
            ):
                self.out_graph = None
                return

        if self._must_improve_rel_quality and not self._improves_relative_quality():
            self.out_graph = None
            return

    def _get_new_gotos(self):
        return self._goto_manager.gotos

    def _fixed_point_analyze(self, cache=None):
        had_any_changes = False
        for _ in range(self._max_opt_iters):
            if self._require_gotos and not self._goto_manager.gotos:
                break

            # backup the graph before the optimization
            if self._recover_structure_fails and self.out_graph is not None:
                self._prev_graph = networkx.DiGraph(self.out_graph)

            # run the optimization, output applied to self.out_graph
            changes = self._analyze(cache=cache)
            if not changes:
                break

            had_any_changes = True
            # check if the graph is structurable
            if not self._graph_is_structurable(self.out_graph, readd_labels=self._readd_labels):
                if self._recover_structure_fails:
                    self.out_graph = self._prev_graph
                else:
                    self.out_graph = None
                    break

        if not had_any_changes:
            self.out_graph = None

    def _graph_is_structurable(self, graph, readd_labels=False, initial=False) -> bool:
        """
        Checks weather the input graph is structurable under the Phoenix schema-matching structuring algorithm.
        As a side effect, this will also update the region identifier and goto manager of this optimization pass.
        Consequently, a true return guarantees up-to-date goto information in the goto manager.
        """
        if readd_labels:
            graph = add_labels(graph)

        remove_edges_in_ailgraph(graph, self._edges_to_remove)

        self._ri = self.project.analyses[RegionIdentifier].prep(kb=self.kb)(
            self._func,
            graph=graph,
            # never update the graph in-place, we need to keep the original graph for later use
            update_graph=False,
            cond_proc=self._ri.cond_proc,
            force_loop_single_exit=False,
            complete_successors=True,
            entry_node_addr=self.entry_node_addr,
        )
        if self._ri is None:
            return False

        # we should try-catch structuring here because we can often pass completely invalid graphs
        # that break the assumptions of the structuring algorithm
        try:
            rs = self.project.analyses[RecursiveStructurer].prep(kb=self.kb)(
                self._ri.region,
                cond_proc=self._ri.cond_proc,
                func=self._func,
                structurer_cls=SAILRStructurer,
            )
        # pylint:disable=broad-except
        except Exception:
            _l.warning("Internal structuring failed for OptimizationPass on %s", self._func.name)
            rs = None

        if not rs or not rs.result or not rs.result.nodes or rs.result_incomplete:
            return False

        rs = self.project.analyses.RegionSimplifier(self._func, rs.result, arg_vvars=self._arg_vvars, kb=self.kb)
        if not rs or rs.goto_manager is None or rs.result is None:
            return False

        self._analyze_simplified_region(rs.result, initial=initial)
        self._goto_manager = rs.goto_manager
        return True

    # pylint:disable=no-self-use
    def _analyze_simplified_region(self, region, initial=False):
        """
        Analyze the simplified regions after a successful structuring pass.
        This should be overridden by the subclass if it needs to do anything with the simplified regions for making
        optimizations decisions.
        """
        if region is None:
            return

        # record quality metrics
        if self._must_improve_rel_quality:
            if initial:
                self._initial_structure_counter = ControlFlowStructureCounter(region)
            else:
                self._current_structure_counter = ControlFlowStructureCounter(region)

    def _improves_relative_quality(self) -> bool:
        """
        Welcome to the unprincipled land of mahaloz. This function is a heuristic that tries to determine if the
        optimization pass improved the relative quality of the control flow structures in the function. These heuristics
        are based on mahaloz's observations of what bad code looks like.
        """
        if self._initial_structure_counter is None or self._current_structure_counter is None:
            _l.warning("Relative quality check failed due to missing structure counters")
            return True

        prev_wloops = self._initial_structure_counter.while_loops
        curr_wloops = self._current_structure_counter.while_loops
        prev_dloops = self._initial_structure_counter.do_while_loops
        curr_dloops = self._current_structure_counter.do_while_loops
        prev_floops = self._initial_structure_counter.for_loops
        curr_floops = self._current_structure_counter.for_loops
        total_prev_loops = prev_wloops + prev_dloops + prev_floops
        total_curr_loops = curr_wloops + curr_dloops + curr_floops

        # Sometimes, if we mess up structuring you can easily tell because we traded "good" loops for "bad" loops.
        # Generally, loops are ordered good -> bad as follows: for, while, do-while.
        # Note: this check is only for _trading_, meaning the total number of loops must be the same.
        #
        # 1. We traded to remove a for-loop
        if curr_floops < prev_floops and total_curr_loops == total_prev_loops:
            return False

        # Gotos play an important part in readability and control flow structure. We already count gotos in other parts
        # of the analysis, so we don't need to count them here. However, some gotos are worse than others. Much
        # like loops, trading gotos (keeping the same total, but getting worse types), is bad for decompilation.
        if len(self._initial_gotos) == len(self._goto_manager.gotos) != 0:
            prev_labels = self._initial_structure_counter.goto_targets
            curr_labels = self._current_structure_counter.goto_targets

            # 1. We traded gotos, but we increased the number of labels, which is generally worse
            if len(curr_labels) > len(prev_labels):
                return False

            ordered_curr_labels = self._current_structure_counter.ordered_labels

            # 2. We trade for a goto that occurs higher in the program (much like a back edge goto), these are bad
            for addr, curr_cnt in curr_labels.items():
                prev_cnt = prev_labels.get(addr, 0)
                # some label increased in gotos, check everything to the right in ordered labels, if it went down,
                # then we fail
                if curr_cnt > prev_cnt:
                    right_labels = ordered_curr_labels[ordered_curr_labels.index(addr) + 1 :]
                    for right_label in right_labels:
                        right_curr_label_cnt = curr_labels[right_label]
                        right_prev_label_cnt = prev_labels.get(right_label, 0)
                        if right_curr_label_cnt < right_prev_label_cnt:
                            return False

                # some label decreased in gotos, check everything to the left, if something went up, then we fail
                elif curr_cnt < prev_cnt:
                    left_labels = ordered_curr_labels[: ordered_curr_labels.index(addr)]
                    for left_label in left_labels:
                        left_curr_label_cnt = curr_labels[left_label]
                        left_prev_label_cnt = prev_labels.get(left_label, 0)
                        if left_curr_label_cnt > left_prev_label_cnt:
                            return False

        return True

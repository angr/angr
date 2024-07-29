# pylint:disable=unused-argument
from __future__ import annotations
import logging
from typing import TYPE_CHECKING
from collections.abc import Generator
from enum import Enum

import networkx  # pylint:disable=unused-import
import ailment

from angr.analyses.decompiler import RegionIdentifier
from angr.analyses.decompiler.condition_processor import ConditionProcessor
from angr.analyses.decompiler.goto_manager import GotoManager
from angr.analyses.decompiler.structuring import RecursiveStructurer, SAILRStructurer
from angr.analyses.decompiler.utils import add_labels
from angr.analyses.decompiler.counters import ControlFlowStructureCounter

if TYPE_CHECKING:
    from angr.knowledge_plugins.functions import Function


_l = logging.getLogger(__name__)


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
    AFTER_MAKING_CALLSITES = 3
    AFTER_GLOBAL_SIMPLIFICATION = 4
    AFTER_VARIABLE_RECOVERY = 5
    BEFORE_REGION_IDENTIFICATION = 6
    DURING_REGION_IDENTIFICATION = 7
    AFTER_STRUCTURING = 8


class BaseOptimizationPass:
    """
    The base class for any optimization pass.
    """

    ARCHES = []  # strings of supported architectures
    PLATFORMS = []  # strings of supported platforms. Can be one of the following: "win32", "linux"
    STAGE: int = None  # Specifies when this optimization pass should be executed
    STRUCTURING: str | None = None  # specifies if this optimization pass is specific to a certain structuring algorithm
    NAME = "N/A"
    DESCRIPTION = "N/A"

    def __init__(self, func):
        self._func: Function = func

    @property
    def project(self):
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

    def _simplify_graph(self, graph):
        MAX_SIMP_ITERATION = 8
        for _ in range(MAX_SIMP_ITERATION):
            simp = self.project.analyses.AILSimplifier(
                self._func,
                func_graph=graph,
                use_callee_saved_regs_at_return=False,
                gp=self._func.info.get("gp", None) if self.project.arch.name in {"MIPS32", "MIPS64"} else None,
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
            # TODO: find a way to pass Phoenix/DREAM options here (see decompiler.py for correct use)
            force_loop_single_exit=True,
            complete_successors=False,
        )


class OptimizationPass(BaseOptimizationPass):
    """
    The base class for any function-level graph optimization pass.
    """

    def __init__(
        self,
        func,
        blocks_by_addr=None,
        blocks_by_addr_and_idx=None,
        graph=None,
        variable_kb=None,
        region_identifier=None,
        reaching_definitions=None,
        vvar_id_start=None,
        **kwargs,
    ):
        super().__init__(func)
        # self._blocks is just a cache
        self._blocks_by_addr: dict[int, set[ailment.Block]] = blocks_by_addr
        self._blocks_by_addr_and_idx: dict[tuple[int, int | None], ailment.Block] = blocks_by_addr_and_idx
        self._graph: networkx.DiGraph | None = graph
        self._variable_kb = variable_kb
        self._ri = region_identifier
        self._rd = reaching_definitions
        self._new_block_addrs = set()
        self.vvar_id_start = vvar_id_start

        # output
        self.out_graph: networkx.DiGraph | None = None

    @property
    def blocks_by_addr(self) -> dict[int, set[ailment.Block]]:
        return self._blocks_by_addr

    @property
    def blocks_by_addr_and_idx(self) -> dict[tuple[int, int | None], ailment.Block]:
        return self._blocks_by_addr_and_idx

    #
    # Util methods
    #

    def new_block_addr(self) -> int:
        """
        Return a block address that does not conflict with any existing blocks.

        :return:    The block address.
        """
        new_addr = max(self._new_block_addrs) + 1 if self._new_block_addrs else max(self.blocks_by_addr) + 2048
        self._new_block_addrs.add(new_addr)
        return new_addr

    def _get_block(self, addr, idx=None) -> ailment.Block | None:
        if not self._blocks_by_addr:
            return None
        if idx is None:
            blocks = self._blocks_by_addr.get(addr, None)
        else:
            blocks = [self._blocks_by_addr_and_idx.get((addr, idx), None)]
        if not blocks:
            return None
        if len(blocks) == 1:
            return next(iter(blocks))
        raise MultipleBlocksException(
            "There are %d blocks at address %#x.%s but only one is requested." % (len(blocks), addr, idx)
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


class SequenceOptimizationPass(BaseOptimizationPass):
    """
    The base class for any sequence node optimization pass.
    """

    ARCHES = []  # strings of supported architectures
    PLATFORMS = []  # strings of supported platforms. Can be one of the following: "win32", "linux"
    STAGE: int = None  # Specifies when this optimization pass should be executed

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

    def __init__(
        self,
        func,
        prevent_new_gotos=True,
        strictly_less_gotos=False,
        recover_structure_fails=True,
        must_improve_rel_quality=True,
        max_opt_iters=1,
        simplify_ail=True,
        require_gotos=True,
        readd_labels=False,
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

        self._initial_gotos = None
        self._goto_manager: GotoManager | None = None
        self._prev_graph: networkx.DiGraph | None = None

        # relative quality metrics (excludes gotos)
        self._initial_structure_counter = None
        self._current_structure_counter = None

    def _analyze(self, cache=None) -> bool:
        raise NotImplementedError

    def analyze(self):
        """
        Wrapper for _analyze() that verifies the graph is structurable before and after the optimization.
        """
        if not self._graph_is_structurable(self._graph, initial=True):
            return

        self._initial_gotos = self._goto_manager.gotos.copy()
        if self._require_gotos and not self._initial_gotos:
            return

        # replace the normal check in OptimizationPass.analyze()
        ret, cache = self._check()
        if not ret:
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

        self._ri = self.project.analyses[RegionIdentifier].prep(kb=self.kb)(
            self._func,
            graph=graph,
            # never update the graph in-place, we need to keep the original graph for later use
            update_graph=False,
            cond_proc=self._ri.cond_proc,
            force_loop_single_exit=False,
            complete_successors=True,
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

        rs = self.project.analyses.RegionSimplifier(self._func, rs.result, kb=self.kb, variable_kb=self._variable_kb)
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

# pylint:disable=unused-argument
from typing import Optional, Dict, Set, Tuple, Generator, TYPE_CHECKING
from enum import Enum

import networkx  # pylint:disable=unused-import
import ailment

from angr.analyses.decompiler import RegionIdentifier
from angr.analyses.decompiler.goto_manager import GotoManager
from angr.analyses.decompiler.structuring import RecursiveStructurer, PhoenixStructurer
from angr.analyses.decompiler.utils import add_labels

if TYPE_CHECKING:
    from angr.knowledge_plugins.functions import Function


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
    AFTER_SINGLE_BLOCK_SIMPLIFICATION = 1
    AFTER_MAKING_CALLSITES = 2
    AFTER_GLOBAL_SIMPLIFICATION = 3
    AFTER_VARIABLE_RECOVERY = 4
    BEFORE_REGION_IDENTIFICATION = 5
    DURING_REGION_IDENTIFICATION = 6
    AFTER_STRUCTURING = 7


class BaseOptimizationPass:
    """
    The base class for any optimization pass.
    """

    ARCHES = []  # strings of supported architectures
    PLATFORMS = []  # strings of supported platforms. Can be one of the following: "win32", "linux"
    STAGE: int = None  # Specifies when this optimization pass should be executed
    STRUCTURING: Optional[str] = (
        None  # specifies if this optimization pass is specific to a certain structuring algorithm
    )
    NAME = "N/A"
    DESCRIPTION = "N/A"

    def __init__(self, func):
        self._func: "Function" = func

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
        raise NotImplementedError()

    def _analyze(self, cache=None):
        """
        Run the analysis.

        :param cache: information passed from _check so it does not have to be
                      recalculated
        :returns: None
        """
        raise NotImplementedError()


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
        **kwargs,
    ):
        super().__init__(func)
        # self._blocks is just a cache
        self._blocks_by_addr: Dict[int, Set[ailment.Block]] = blocks_by_addr
        self._blocks_by_addr_and_idx: Dict[Tuple[int, Optional[int]], ailment.Block] = blocks_by_addr_and_idx
        self._graph: Optional[networkx.DiGraph] = graph
        self._variable_kb = variable_kb
        self._ri = region_identifier
        self._rd = reaching_definitions
        self._new_block_addrs = set()

        # output
        self.out_graph: Optional[networkx.DiGraph] = None

    @property
    def blocks_by_addr(self) -> Dict[int, Set[ailment.Block]]:
        return self._blocks_by_addr

    @property
    def blocks_by_addr_and_idx(self) -> Dict[Tuple[int, Optional[int]], ailment.Block]:
        return self._blocks_by_addr_and_idx

    #
    # Util methods
    #

    def new_block_addr(self) -> int:
        """
        Return a block address that does not conflict with any existing blocks.

        :return:    The block address.
        """
        if self._new_block_addrs:
            new_addr = max(self._new_block_addrs) + 1
        else:
            new_addr = max(self.blocks_by_addr) + 2048
        self._new_block_addrs.add(new_addr)
        return new_addr

    def _get_block(self, addr, idx=None) -> Optional[ailment.Block]:
        if not self._blocks_by_addr:
            return None
        else:
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

    def _get_blocks(self, addr, idx=None) -> Generator[ailment.Block, None, None]:
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
    """

    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.DURING_REGION_IDENTIFICATION

    def __init__(
        self,
        func,
        prevent_new_gotos=True,
        strictly_less_gotos=False,
        recover_structure_fails=True,
        max_opt_iters=1,
        simplify_ail=True,
        **kwargs,
    ):
        super().__init__(func, **kwargs)
        self._prevent_new_gotos = prevent_new_gotos
        self._strictly_less_gotos = strictly_less_gotos
        self._recover_structure_fails = recover_structure_fails
        self._max_opt_iters = max_opt_iters
        self._simplify_ail = simplify_ail

        self._goto_manager: Optional[GotoManager] = None
        self._prev_graph: Optional[networkx.DiGraph] = None

    def _analyze(self, cache=None) -> bool:
        raise NotImplementedError()

    def analyze(self):
        """
        Wrapper for _analyze() that verifies the graph is structurable before and after the optimization.
        """
        if not self._graph_is_structurable(self._graph):
            return

        initial_gotos = self._goto_manager.gotos.copy()
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

        if not self._graph_is_structurable(self.out_graph):
            self.out_graph = None
            return

        # simplify the AIL graph
        if self._simplify_ail:
            # this should not (TM) change the structure of the graph but is needed for later optimizations
            self.out_graph = self._simplify_ail_graph(self.out_graph)

        if self._prevent_new_gotos:
            prev_gotos = len(initial_gotos)
            new_gotos = len(self._goto_manager.gotos)
            if (self._strictly_less_gotos and (new_gotos >= prev_gotos)) or (
                not self._strictly_less_gotos and (new_gotos > prev_gotos)
            ):
                self.out_graph = None
                return

    def _fixed_point_analyze(self, cache=None):
        for _ in range(self._max_opt_iters):
            # backup the graph before the optimization
            if self._recover_structure_fails and self.out_graph is not None:
                self._prev_graph = networkx.DiGraph(self.out_graph)

            # run the optimization, output applied to self.out_graph
            changes = self._analyze(cache=cache)
            if not changes:
                break

            # check if the graph is structurable
            if not self._graph_is_structurable(self.out_graph):
                self.out_graph = self._prev_graph if self._recover_structure_fails else None
                break

    def _simplify_ail_graph(self, graph):
        simp = self.project.analyses.AILSimplifier(
            self._func,
            func_graph=graph,
            use_callee_saved_regs_at_return=False,
            gp=self._func.info.get("gp", None) if self.project.arch.name in {"MIPS32", "MIPS64"} else None,
        )
        return simp.func_graph if simp.simplified else graph

    def _graph_is_structurable(self, graph, readd_labels=False) -> bool:
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

        rs = self.project.analyses[RecursiveStructurer].prep(kb=self.kb)(
            self._ri.region,
            cond_proc=self._ri.cond_proc,
            func=self._func,
            structurer_cls=PhoenixStructurer,
        )
        if not rs or not rs.result or not rs.result.nodes:
            return False

        rs = self.project.analyses.RegionSimplifier(self._func, rs.result, kb=self.kb, variable_kb=self._variable_kb)
        if not rs or rs.goto_manager is None:
            return False

        self._goto_manager = rs.goto_manager
        return True

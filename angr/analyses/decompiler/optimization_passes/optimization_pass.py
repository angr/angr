from typing import Optional, Dict, Set, Tuple, Generator, TYPE_CHECKING  # pylint:disable=unused-import

import networkx  # pylint:disable=unused-import

import ailment

from ...analysis import Analysis

if TYPE_CHECKING:
    from angr.knowledge_plugins.functions import Function


class MultipleBlocksException(Exception):
    pass


class OptimizationPassStage:
    AFTER_SINGLE_BLOCK_SIMPLIFICATION = 0
    AFTER_GLOBAL_SIMPLIFICATION = 1
    AFTER_VARIABLE_RECOVERY = 2
    DURING_REGION_IDENTIFICATION = 3


class OptimizationPass:
    """
    The base class for any function-level graph optimization pass.
    """

    ARCHES = [ ]  # strings of supported architectures
    PLATFORMS = [ ]  # strings of supported platforms. Can be one of the following: "win32", "linux"
    STAGE: int = None  # Specifies when this optimization pass should be executed

    def __init__(self, func, blocks_by_addr=None, blocks_by_addr_and_idx=None, graph=None):
        self._func: 'Function' = func
        # self._blocks is just a cache
        self._blocks_by_addr: Dict[int,Set[ailment.Block]] = blocks_by_addr
        self._blocks_by_addr_and_idx: Dict[Tuple[int,Optional[int]],ailment.Block] = blocks_by_addr_and_idx
        self._graph = graph  # type: Optional[networkx.DiGraph]

        # output
        self.out_graph = None  # type: Optional[networkx.DiGraph]

    @property
    def project(self):
        return self._func.project

    @property
    def kb(self):
        return self.project.kb

    @property
    def blocks_by_addr(self) -> Dict[int,Set[ailment.Block]]:
        return self._blocks_by_addr

    @property
    def blocks_by_addr_and_idx(self) -> Dict[Tuple[int,Optional[int]],ailment.Block]:
        return self._blocks_by_addr_and_idx

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

    #
    # Util methods
    #

    def _get_block(self, addr, idx=None) -> Optional[ailment.Block]:

        if not self._blocks_by_addr:
            return None
        else:
            if idx is None:
                blocks = self._blocks_by_addr.get(addr, None)
            else:
                blocks = [ self._blocks_by_addr_and_idx.get((addr, idx), None) ]
            if not blocks:
                return None
            if len(blocks) == 1:
                return next(iter(blocks))
            raise MultipleBlocksException("There are %d blocks at address %#x.%s but only one is requested." % (
                len(blocks), addr, idx
            ))

    def _get_blocks(self, addr, idx=None) -> Generator[ailment.Block,None,None]:
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

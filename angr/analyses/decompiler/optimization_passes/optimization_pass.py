from typing import Optional  # pylint:disable=unused-import

import networkx  # pylint:disable=unused-import

import ailment

from ...analysis import Analysis


class MultipleBlocksException(Exception):
    pass


class OptimizationPass(Analysis):

    ARCHES = [ ]  # strings of supported architectures
    PLATFORMS = [ ]  # strings of supported platforms. Can be one of the following: "win32", "linux"

    def __init__(self, func, blocks=None, graph=None):

        self._func = func
        # self._blocks is just a cache
        self._blocks = blocks  # type: defaultdict(set)
        self._graph = graph  # type: Optional[networkx.DiGraph]

        # output
        self.out_graph = None  # type: Optional[networkx.DiGraph]

    @property
    def blocks(self):
        return self._blocks

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

    def _get_block(self, addr):

        if not self._blocks:
            return None
        else:
            blocks = self._blocks.get(addr, None)
            if not blocks:
                return None
            if len(blocks) == 1:
                return next(iter(blocks))
            raise MultipleBlocksException("There are %d blocks at address %#x but only one is requested." % (
                len(blocks), addr
            ))

    def _update_block(self, old_block, new_block):

        if self.out_graph is None:
            self.out_graph = self._graph  # we do not make copy here for performance reasons. we can change it if needed

        if old_block not in self.out_graph:
            return

        in_edges = list(self.out_graph.in_edges(old_block, data=True))
        out_edges = list(self.out_graph.out_edges(old_block, data=True))

        self._remove_block(old_block)
        self.out_graph.add_node(new_block)
        self._blocks[new_block.addr].add(new_block)

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

        if block.addr in self._blocks and block in self._blocks[block.addr]:
            self._blocks[block.addr].remove(block)

    def _is_add(self, expr):
        return isinstance(expr, ailment.Expr.BinaryOp) and expr.op == "Add"

    def _is_sub(self, expr):
        return isinstance(expr, ailment.Expr.BinaryOp) and expr.op == "Sub"

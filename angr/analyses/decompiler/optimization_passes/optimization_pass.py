
import ailment

from ...analysis import Analysis


class OptimizationPass(Analysis):

    ARCHES = [ ]  # strings of supported architectures
    PLATFORMS = [ ]  # strings of supported platforms. Can be one of the following: "win32", "linux"

    def __init__(self, func, blocks=None):

        self._func = func
        self._blocks = blocks

    @property
    def blocks(self):
        return self._blocks

    def analyze(self):

        ret, cache = self._check()
        if ret:
            self._analyze(cache=cache)

    def _check(self):
        raise NotImplementedError()

    def _analyze(self, cache=None):
        raise NotImplementedError()

    #
    # Util methods
    #

    def _get_block(self, addr, size=None):

        original_block = self._func.get_node(addr)
        if original_block is None:
            # this block does not exist
            return None

        if size is None:
            size = original_block.size

        if not self._blocks:
            return original_block
        else:
            return self._blocks.get((addr, size), original_block)

    def _update_block(self, old_block, new_block):

        addr, size = old_block.addr, old_block.original_size
        if self._blocks is None:
            self._blocks = { }
        self._blocks[(addr, size)] = new_block

    def _remove_block(self, block):

        addr, size = block.addr, block.original_size
        if self._blocks is None:
            self._blocks = { }
        self._blocks[(addr, size)] = None

    def _is_add(self, expr):
        return isinstance(expr, ailment.Expr.BinaryOp) and expr.op == "Add"

    def _is_sub(self, expr):
        return isinstance(expr, ailment.Expr.BinaryOp) and expr.op == "Sub"

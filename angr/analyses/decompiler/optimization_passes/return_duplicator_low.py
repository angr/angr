import logging
import inspect

import networkx

from ailment import Block
from ailment.statement import ConditionalJump

from .return_duplicator_base import ReturnDuplicatorBase
from .optimization_pass import StructuringOptimizationPass

_l = logging.getLogger(name=__name__)


class ReturnDuplicatorLow(StructuringOptimizationPass, ReturnDuplicatorBase):
    """
    An optimization pass that reverts a subset of Irreducible Statement Condensing (ISC) optimizations, as described
    in the USENIX 2024 paper SAILR. This is the heavy/goto version of the ReturnDuplicator optimization pass.

    Some compilers, including GCC, Clang, and MSVC, apply various optimizations to reduce the number of statements in
    code. These optimizations will take equivalent statements, or a subset of them, and replace them with a single
    copy that is jumped to by gotos -- optimizing for space and sometimes speed.

    This optimization pass will revert those gotos by re-duplicating the condensed blocks. Since Return statements
    are the most common, we use this optimization pass to revert only gotos to return statements. Additionally, we
    perform some additional readability fixups, like not re-duplicating returns to shared components.

    Args:
        func: The function to optimize.
        node_idx_start: The index to start at when creating new nodes. This is used by Clinic to ensure that
            node indices are unique across multiple passes.
        max_opt_iters: The maximum number of optimization iterations to perform.
        max_calls_in_regions: The maximum number of calls that can be in a region. This is used to prevent
            duplicating too much code.
        prevent_new_gotos: If True, this optimization pass will prevent new gotos from being created.
        minimize_copies_for_regions: If True, this optimization pass will minimize the number of copies by doing only
            a single copy for connected in_edges that form a region.
    """

    ARCHES = None
    PLATFORMS = None
    NAME = "Duplicate returns connect with gotos (low)"
    DESCRIPTION = inspect.cleandoc(__doc__[: __doc__.index("Args:")])  # pylint:disable=unsubscriptable-object

    def __init__(
        self,
        func,
        # internal parameters that should be used by Clinic
        node_idx_start: int = 0,
        # settings
        max_opt_iters: int = 4,
        max_calls_in_regions: int = 2,
        prevent_new_gotos: bool = True,
        minimize_copies_for_regions: bool = True,
        **kwargs,
    ):
        ReturnDuplicatorBase.__init__(
            self,
            func,
            node_idx_start=node_idx_start,
            max_calls_in_regions=max_calls_in_regions,
            minimize_copies_for_regions=minimize_copies_for_regions,
            **kwargs,
        )
        StructuringOptimizationPass.__init__(
            self, func, max_opt_iters=max_opt_iters, prevent_new_gotos=prevent_new_gotos, require_gotos=True, **kwargs
        )
        self.analyze()

    def _check(self):
        return ReturnDuplicatorBase._check(self)

    def _should_duplicate_dst(self, src, dst, graph, dst_is_const_ret=False):
        return self._is_goto_edge(src, dst, graph=graph, check_for_ifstmts=True)

    def _is_goto_edge(
        self,
        src: Block,
        dst: Block,
        graph: networkx.DiGraph = None,
        check_for_ifstmts=True,
        max_level_check=1,
    ):
        """
        TODO: correct how goto edge addressing works
        This function only exists because a long-standing bug that sometimes reports the if-stmt addr
        above a goto edge as the goto src. Because of this, we need to check for predecessors above the goto and
        see if they are a goto. This needs to include Jump to deal with loops.
        """
        if check_for_ifstmts and graph is not None:
            blocks = [src]
            level_blocks = [src]
            for _ in range(max_level_check):
                new_level_blocks = []
                for lblock in level_blocks:
                    new_level_blocks += list(graph.predecessors(lblock))

                blocks += new_level_blocks
                level_blocks = new_level_blocks

            src_direct_parents = list(graph.predecessors(src))
            for block in blocks:
                if not block or not block.statements:
                    continue

                # special case if-stmts that are next to each other
                if block in src_direct_parents and isinstance(block.statements[-1], ConditionalJump):
                    continue

                if self._goto_manager.is_goto_edge(block, dst):
                    return True
        else:
            return self._goto_manager.is_goto_edge(src, dst)

        return False

    def _analyze(self, cache=None):
        """
        This analysis is run in a loop in analyze() for a maximum of max_opt_iters times.
        """
        return self._analyze_core(self.out_graph)

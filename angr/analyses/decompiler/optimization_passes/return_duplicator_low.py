from __future__ import annotations
import logging
import inspect

import networkx

from ailment import Block
from ailment.statement import ConditionalJump, Label

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
        return self._is_goto_edge(src, dst, graph=graph)

    def _is_goto_edge(
        self,
        src: Block,
        dst: Block,
        graph: networkx.DiGraph = None,
        max_level_check=1,
    ):
        """
        TODO: Implement a more principled way of checking if an edge is a goto edge with Phoenix's structuring info
        This function only exists because a long-standing bug that sometimes reports the if-stmt addr
        above a goto edge as the goto src.
        """
        # Do a simple and fast check first
        is_simple_goto = self._goto_manager.is_goto_edge(src, dst)
        if is_simple_goto:
            return True

        if graph is not None:
            # Special case 1:
            # We need to check for predecessors above the goto and see if they are a goto.
            # This needs to include Jump to deal with loops.
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

            # Special case 2: A "goto edge" that ReturnDuplicator wants to test might be an edge that Phoenix
            # includes in its loop region (during the cyclic refinement). In fact, Phoenix tends to include as many
            # nodes as possible into the loop region, and generate a goto edge (which ends up in the structured code)
            # from `dst` to the loop successor.
            # an example of this is captured by the test case `TestDecompiler.test_stty_recover_mode_ret_dup_region`.
            # until someone (ideally @mahaloz) implements a more principled way of translating "goto statements" that
            # Phoenix generates and "goto edges" that ReturnDuplicator tests, we rely on the following stopgap to
            # handle this case.
            node = dst
            while True:
                succs = list(graph.successors(node))
                if len(succs) != 1:
                    break
                succ = succs[0]
                if succ is node:
                    # loop!
                    break
                succ_preds = list(graph.predecessors(succ))
                if len(succ_preds) != 1:
                    break
                if self._goto_manager.is_goto_edge(node, succ):
                    return True
                # keep testing the next edge
                node = succ

            # Special case 3: In Phoenix, regions full of only if-stmts can be collapsed and moved. This causes
            # the goto manager to report gotos that are at the top of the region instead of ones in the middle of it.
            # Because of this, we need to gather all the nodes above the original src and check if any of them
            # go to the destination. Additionally, we need to do this on the supergraph to get rid of
            # goto edges that are removed by Phoenix.
            # This case is observed in the test case `TestDecompiler.test_tail_tail_bytes_ret_dup`.
            if self._supergraph is None:
                return False

            super_to_og_nodes = {n: self._supergraph.nodes[n]["original_nodes"] for n in self._supergraph.nodes}
            og_to_super_nodes = {og: super_n for super_n, ogs in super_to_og_nodes.items() for og in ogs}
            super_src = og_to_super_nodes.get(src)
            super_dst = og_to_super_nodes.get(dst)
            if super_src is None or super_dst is None:
                return False

            # collect all nodes which have only an if-stmt in them that are ancestors of super_src
            check_blks = {super_src}
            level_blocks = {super_src}
            for _ in range(10):
                done = False
                if_blks = set()
                for lblock in level_blocks:
                    preds = list(self._supergraph.predecessors(lblock))
                    for pred in preds:
                        only_cond_jump = all(isinstance(s, (ConditionalJump, Label)) for s in pred.statements)
                        if only_cond_jump:
                            if_blks.add(pred)

                    done = len(if_blks) == 0

                if done:
                    break

                check_blks |= if_blks
                level_blocks = if_blks

            # convert all the found if-only super-blocks back into their original blocks
            og_check_blocks = set()
            for blk in check_blks:
                og_check_blocks |= set(super_to_og_nodes[blk])

            # check if any of the original blocks are gotos to the destination
            goto_hits = 0
            for block in og_check_blocks:
                if self._goto_manager.is_goto_edge(block, dst):
                    goto_hits += 1

            # Although it is good to find a goto in the if-only block region, having more than a single goto
            # existing that goes to the same dst is a bad sign. This can be seen in the the following test:
            # TestDecompiler.test_dd_iread_ret_dup_region
            #
            # It occurs when you have something like:
            # ```
            # if (a || c)
            #     goto target;
            # target:
            # return 0;
            # ```
            #
            #
            # This looks like an edge from (a, target) and (c, target) but it is actually a single edge.
            # If you allow both to duplicate you get the following:
            # ```
            # if (a):
            #    return
            # if (c):
            #    return
            # ```
            # This is not the desired behavior.
            # So we need to check if there is only a single goto that goes to the destination.
            return goto_hits == 1

        return False

    def _analyze(self, cache=None):
        """
        This analysis is run in a loop in analyze() for a maximum of max_opt_iters times.
        """
        return self._analyze_core(self.out_graph)

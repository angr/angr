from __future__ import annotations

import itertools
import logging
from typing import TYPE_CHECKING

from angr import ailment
from angr.analyses.analysis import Analysis, register_analysis
from angr.analyses.decompiler.condition_processor import ConditionProcessor
from angr.analyses.decompiler.empty_node_remover import EmptyNodeRemover
from angr.analyses.decompiler.jump_target_collector import JumpTargetCollector
from angr.analyses.decompiler.jumptable_entry_condition_rewriter import JumpTableEntryConditionRewriter
from angr.analyses.decompiler.redundant_label_remover import RedundantLabelRemover
from angr.analyses.decompiler.region_overlay import RegionOverlay
from angr.analyses.decompiler.structurer_nodes import (
    BaseNode,
    BreakNode,
    CascadingConditionNode,
    CodeNode,
    ConditionNode,
    ContinueNode,
    IncompleteSwitchCaseHeadStatement,
    MultiNode,
    SequenceNode,
)
from angr.utils.graph import GraphUtils

from .dream import DreamStructurer
from .structurer_base import StructurerBase

if TYPE_CHECKING:
    from angr.ailment.manager import Manager
    from angr.knowledge_plugins.functions import Function


_l = logging.getLogger(__name__)


class RecursiveStructurer(Analysis):
    """
    Recursively structure a region and all of its subregions.
    """

    def __init__(
        self,
        region,
        cond_proc=None,
        func: Function | None = None,
        structurer_cls: type | None = None,
        *,
        ail_manager: Manager,
        **kwargs,
    ):
        self._region = region
        self.function = func
        self.structurer_cls = structurer_cls if structurer_cls is not None else DreamStructurer
        self.structurer_options = kwargs
        self.ail_manager = ail_manager
        self.cond_proc = cond_proc if cond_proc is not None else ConditionProcessor(self.project.arch, self.ail_manager)

        self.result: BaseNode | ailment.Block | MultiNode | None = None
        self.result_incomplete: bool = False

        self._analyze()

    def _analyze(self):
        self._case_entry_to_switch_head: dict[int, int] = self._get_switch_case_entries()
        self.result_incomplete = False

        assert isinstance(self._region, RegionOverlay), "RecursiveStructurer requires a RegionOverlay region"
        self._structure_overlay_tree()
        self._post_process_result()

    def _structure_overlay_tree(self):
        """
        Structure an overlay tree natively and destructively: structuring algorithms mutate the shared graph
        through the region overlay, so a structured region becomes a single node of its parent without any
        region replacement step (and a failed region simply dissolves into its parent). The whole shared graph
        and the overlay tree are restored from the undo log afterwards, keeping the region identifier's result
        intact for later consumers.
        """
        root: RegionOverlay = self._region
        manager = root.manager
        checkpoint = manager.checkpoint()

        try:
            parent_map = {}
            stack: list[RegionOverlay] = [root]

            while stack:
                current_region = stack[-1]

                has_region = False
                for node in GraphUtils.dfs_postorder_nodes_deterministic(current_region.graph, current_region.head):
                    if isinstance(node, RegionOverlay):
                        if node in stack:
                            stack.remove(node)
                        stack.append(node)
                        parent_map[node] = current_region
                        has_region = True

                if not has_region:
                    # pop this region from the stack
                    stack.pop()

                    parent_region = parent_map.get(current_region)
                    # capture the region's successors before structuring mutates the shared graph, so finalize can
                    # re-establish the region-to-successor edges that refinement/virtualization removes
                    succ_snapshot = current_region.snapshot_successors()
                    # structure this region
                    st: StructurerBase = self.project.analyses[self.structurer_cls].prep(
                        kb=self.kb, fail_fast=self._fail_fast
                    )(
                        current_region,
                        parent_map=parent_map,
                        condition_processor=self.cond_proc,
                        case_entry_to_switch_head=self._case_entry_to_switch_head,
                        func=self.function,
                        parent_region=parent_region,
                        jump_tables=self.kb.cfgs["CFGFast"].jump_tables,
                        ail_manager=self.ail_manager,
                        **self.structurer_options,
                    )
                    if not parent_region:
                        # this is the top-level region. we are done!
                        if st.result is None:
                            # take the partial result out of the graph
                            _l.warning(
                                "Structuring failed to complete (most likely due to bugs in structuring). The "
                                "output will miss code blocks."
                            )
                            self.result = self._pick_incomplete_result_from_region(current_region)
                            self.result_incomplete = True
                        else:
                            self.result = st.result
                        break

                    if st.result is None:
                        current_region.dissolve()
                    elif st.result in current_region.members:
                        # the structurer destructively reduced the region to a single member node (e.g. Phoenix):
                        # that node is the result and takes the region's place in the parent
                        current_region.finalize(st.result, succ_snapshot=succ_snapshot)
                    else:
                        # the structurer produced an external result without reducing the shared graph (e.g. Dream):
                        # collapse all member nodes onto the result node
                        current_region.collapse_to(st.result)
        finally:
            # restore the shared graph and the overlay tree for post-structuring consumers of the region tree
            manager.rollback(checkpoint)
            manager.commit(checkpoint)

    def _post_process_result(self):
        if self.structurer_cls is DreamStructurer:
            # rewrite conditions in the result to remove all jump table entry conditions
            rewriter = JumpTableEntryConditionRewriter(set(itertools.chain(*self.cond_proc.jump_table_conds.values())))
            rewriter.walk(self.result)  # update SequenceNodes in-place

            # remove all goto statements
            # TODO: Properly implement support for multi-entry regions
            StructurerBase._remove_all_jumps(self.result)

        else:
            StructurerBase.remove_redundant_jumps(self.result, self.ail_manager)

        # remove redundant labels
        jtc = JumpTargetCollector(self.result)
        self.result = RedundantLabelRemover(self.result, jtc.jump_targets).result

        # remove empty nodes (if any)
        self.result = EmptyNodeRemover(self.result, self.ail_manager).result

        if self.structurer_cls is DreamStructurer:
            # remove conditional jumps
            StructurerBase._remove_conditional_jumps(self.result)

        self.result = self.cond_proc.remove_claripy_bool_asts(self.result)

    def _get_switch_case_entries(self) -> dict[int, int]:
        if self.function is None:
            return {}

        entries = {}
        func_block_addrs = self.function.block_addrs_set

        jump_tables = self.kb.cfgs["CFGFast"].jump_tables
        for jump_table_head_addr, jumptable in jump_tables.items():
            if jump_table_head_addr not in func_block_addrs:
                continue
            assert jumptable.jumptable_entries is not None
            for entry_addr in jumptable.jumptable_entries:
                entries[entry_addr] = jump_table_head_addr

        return entries

    @staticmethod
    def _exits_explicitly(node) -> bool:
        """
        Return True when control cannot fall out of the bottom of ``node``, i.e. every path through it ends in a
        jump or a return. Anything this does not understand counts as falling through.
        """
        if isinstance(node, ailment.Block):
            if not node.statements:
                return False
            last_stmt = node.statements[-1]
            if isinstance(last_stmt, (ailment.Stmt.Jump, ailment.Stmt.ConditionalJump, ailment.Stmt.Return)):
                return True
            if isinstance(last_stmt, IncompleteSwitchCaseHeadStatement):
                # the code generator renders this as an if-goto cascade, which only covers every path when the
                # statement carries a default case
                return any(case_value == "default" for _, case_value, _, _, _ in last_stmt.case_addrs)
            return False
        if isinstance(node, (SequenceNode, MultiNode)):
            return bool(node.nodes) and RecursiveStructurer._exits_explicitly(node.nodes[-1])
        if isinstance(node, CodeNode):
            return RecursiveStructurer._exits_explicitly(node.node)
        if isinstance(node, ConditionNode):
            return (
                node.true_node is not None
                and node.false_node is not None
                and RecursiveStructurer._exits_explicitly(node.true_node)
                and RecursiveStructurer._exits_explicitly(node.false_node)
            )
        if isinstance(node, CascadingConditionNode):
            return node.else_node is not None and all(
                RecursiveStructurer._exits_explicitly(child)
                for child in [n for _, n in node.condition_and_nodes] + [node.else_node]
            )
        return isinstance(node, (BreakNode, ContinueNode))

    def _pick_incomplete_result_from_region(self, region):
        """
        Structuring did not complete for this region, so no single node covers it. Emit every leftover node instead
        of one of them.

        Keeping one node silently truncates the function: the transfers into the discarded nodes survive as jump
        statements that name addresses no emitted block carries, GotoSimplifier then drops those jumps because
        their targets are missing, and the remaining code falls through edges the binary does not have. Emitting
        the whole leftover graph keeps every one of those transfers addressable.

        Edges between leftover nodes are already explicit jump statements -- the structurer only strips a
        terminator when it absorbs the edge into a matched schema -- so the order the nodes are emitted in is a
        layout choice and not a semantic one. Where a node can still fall out of its bottom, an explicit jump to
        its sole successor is appended so that the order stays inert there too.
        """
        nodes = [node for node in region.graph.nodes if not isinstance(node, RegionOverlay)]
        if not nodes:
            return None

        entry_addr = self.function.addr if self.function is not None else region.head.addr
        nodes.sort(key=lambda node: self._incomplete_result_sort_key(node, entry_addr))
        if len(nodes) == 1:
            return nodes[0]

        emitted = []
        for idx, node in enumerate(nodes):
            successors = list(region.graph.successors(node))
            following = nodes[idx + 1] if idx + 1 < len(nodes) else None
            if (
                len(successors) == 1
                and successors[0] is not following
                and successors[0].addr is not None
                and not self._exits_explicitly(node)
            ):
                goto_block = ailment.Block(
                    node.addr,
                    0,
                    statements=[
                        ailment.Stmt.Jump(
                            self.ail_manager.next_atom(),
                            ailment.Expr.Const(
                                self.ail_manager.next_atom(), successors[0].addr, self.project.arch.bits
                            ),
                            ins_addr=node.addr,
                            stmt_idx=0,
                        )
                    ],
                )
                node = SequenceNode(node.addr, nodes=[node, goto_block])
            emitted.append(node)

        return SequenceNode(emitted[0].addr, nodes=emitted)

    @staticmethod
    def _incomplete_result_sort_key(node, entry_addr: int | None):
        """
        Order the leftover nodes: the function entry first, then by address. Graph iteration order is not stable
        across processes, so every component of this key must be derived from the node itself.
        """
        addr = node.addr
        return (
            0 if (entry_addr is not None and addr == entry_addr) else 1,
            addr is None,
            addr if addr is not None else 0,
            type(node).__name__,
            getattr(node, "idx", None) or 0,
        )


register_analysis(RecursiveStructurer, "RecursiveStructurer")

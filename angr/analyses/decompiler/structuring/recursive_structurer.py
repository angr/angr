from __future__ import annotations
import itertools
from typing import TYPE_CHECKING
import logging

from angr.analyses import Analysis, register_analysis
from angr.analyses.decompiler.condition_processor import ConditionProcessor
from angr.analyses.decompiler.graph_region import GraphRegion
from angr.analyses.decompiler.jumptable_entry_condition_rewriter import JumpTableEntryConditionRewriter
from angr.analyses.decompiler.empty_node_remover import EmptyNodeRemover
from angr.analyses.decompiler.jump_target_collector import JumpTargetCollector
from angr.analyses.decompiler.redundant_label_remover import RedundantLabelRemover
from angr.utils.graph import GraphUtils
from .structurer_nodes import BaseNode
from .structurer_base import StructurerBase
from .dream import DreamStructurer


if TYPE_CHECKING:
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
        **kwargs,
    ):
        self._region = region
        self.cond_proc = cond_proc if cond_proc is not None else ConditionProcessor(self.project.arch)
        self.function = func
        self.structurer_cls = structurer_cls if structurer_cls is not None else DreamStructurer
        self.structurer_options = kwargs

        self.result: BaseNode | None = None
        self.result_incomplete: bool = False

        self._analyze()

    def _analyze(self):
        region = self._region.recursive_copy()
        self._case_entry_to_switch_head: dict[int, int] = self._get_switch_case_entries()
        self.result_incomplete = False

        # visit the region in post-order DFS
        parent_map = {}
        stack = [region]

        while stack:
            current_region = stack[-1]

            has_region = False
            for node in GraphUtils.dfs_postorder_nodes_deterministic(current_region.graph, current_region.head):
                subnodes = []
                if type(node) is GraphRegion:
                    if node.cyclic:
                        subnodes.append(node)
                    else:
                        subnodes.insert(0, node)
                    parent_map[node] = current_region
                    has_region = True
                # remove existing regions
                for subnode in subnodes:
                    if subnode in stack:
                        stack.remove(subnode)
                stack.extend(subnodes)

            if not has_region:
                # pop this region from the stack
                stack.pop()

                # Get the parent region
                parent_region = parent_map.get(current_region)
                # structure this region
                st: StructurerBase = self.project.analyses[self.structurer_cls].prep(
                    kb=self.kb, fail_fast=self._fail_fast
                )(
                    current_region.copy(),
                    parent_map=parent_map,
                    condition_processor=self.cond_proc,
                    case_entry_to_switch_head=self._case_entry_to_switch_head,
                    func=self.function,
                    parent_region=parent_region,
                    jump_tables=self.kb.cfgs["CFGFast"].jump_tables,
                    **self.structurer_options,
                )
                # replace this region with the resulting node in its parent region... if it's not an orphan
                if not parent_region:
                    # this is the top-level region. we are done!
                    if st.result is None:
                        # take the partial result out of the graph
                        _l.warning(
                            "Structuring failed to complete (most likely due to bugs in structuring). The "
                            "output will miss code blocks."
                        )
                        self.result = self._pick_incomplete_result_from_region(st._region)
                        self.result_incomplete = True
                    else:
                        self.result = st.result
                    break

                if st.result is None:
                    self._replace_region_with_region(parent_region, current_region, st._region)
                else:
                    self._replace_region_with_node(
                        parent_region, current_region, st._region, st.result, st.virtualized_edges
                    )

        if self.structurer_cls is DreamStructurer:
            # rewrite conditions in the result to remove all jump table entry conditions
            rewriter = JumpTableEntryConditionRewriter(set(itertools.chain(*self.cond_proc.jump_table_conds.values())))
            rewriter.walk(self.result)  # update SequenceNodes in-place

            # remove all goto statements
            # TODO: Properly implement support for multi-entry regions
            StructurerBase._remove_all_jumps(self.result)

        else:
            StructurerBase._remove_redundant_jumps(self.result)

        # remove redundant labels
        jtc = JumpTargetCollector(self.result)
        self.result = RedundantLabelRemover(self.result, jtc.jump_targets).result

        # remove empty nodes (if any)
        self.result = EmptyNodeRemover(self.result).result

        if self.structurer_cls is DreamStructurer:
            # remove conditional jumps
            StructurerBase._remove_conditional_jumps(self.result)

        self.result = self.cond_proc.remove_claripy_bool_asts(self.result)

    @staticmethod
    def _replace_region_with_node(parent_region, sub_region, updated_sub_region, node, virtualized_edges):
        parent_region.replace_region(sub_region, updated_sub_region, node, virtualized_edges)

    @staticmethod
    def _replace_region_with_region(parent_region, sub_region, new_region):
        parent_region.replace_region_with_region(sub_region, new_region)

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

    def _pick_incomplete_result_from_region(self, region):
        """
        Parse the region graph and get (a) the node with address equal to the function address, or (b) the node with
        the lowest address.
        """

        min_node = None
        for node in region.graph.nodes:
            if not isinstance(node, BaseNode):
                continue
            if self.function is not None and node.addr == self.function.addr:
                return node
            if min_node is None or (min_node.addr is not None and node.addr is not None and min_node.addr < node.addr):
                min_node = node

        return min_node


register_analysis(RecursiveStructurer, "RecursiveStructurer")

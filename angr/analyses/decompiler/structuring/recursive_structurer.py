import itertools
from typing import Optional, Type, Dict, TYPE_CHECKING

import networkx
from ... import Analysis, register_analysis
from ..condition_processor import ConditionProcessor
from ..graph_region import GraphRegion
from ..jumptable_entry_condition_rewriter import JumpTableEntryConditionRewriter
from ..empty_node_remover import EmptyNodeRemover
from ..jump_target_collector import JumpTargetCollector
from ..redundant_label_remover import RedundantLabelRemover
from .structurer_base import StructurerBase
from .dream import DreamStructurer


if TYPE_CHECKING:
    from angr.knowledge_plugins.functions import Function


class RecursiveStructurer(Analysis):
    """
    Recursively structure a region and all of its subregions.
    """

    def __init__(
        self,
        region,
        cond_proc=None,
        func: Optional["Function"] = None,
        structurer_cls: Optional[Type] = None,
        improve_structurer=True,
    ):
        self._region = region
        self.cond_proc = cond_proc if cond_proc is not None else ConditionProcessor(self.project.arch)
        self.function = func
        self.structurer_cls = structurer_cls if structurer_cls is not None else DreamStructurer
        self.improve_structurer = improve_structurer

        self.result = None

        self._analyze()

    def _analyze(self):
        region = self._region.recursive_copy()
        self._case_entry_to_switch_head: Dict[int, int] = self._get_switch_case_entries()

        # visit the region in post-order DFS
        parent_map = {}
        stack = [region]

        while stack:
            current_region = stack[-1]

            has_region = False
            for node in networkx.dfs_postorder_nodes(current_region.graph, current_region.head):
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
                parent_region = parent_map.get(current_region, None)
                # structure this region
                st = self.project.analyses[self.structurer_cls].prep()(
                    current_region.copy(),
                    parent_map=parent_map,
                    condition_processor=self.cond_proc,
                    case_entry_to_switch_head=self._case_entry_to_switch_head,
                    func=self.function,
                    parent_region=parent_region,
                    improve_structurer=self.improve_structurer,
                )
                # replace this region with the resulting node in its parent region... if it's not an orphan
                if not parent_region:
                    # this is the top-level region. we are done!
                    self.result = st.result
                    break

                if st.result is None:
                    self._replace_region_with_region(parent_region, current_region, st._region)
                else:
                    self._replace_region_with_node(parent_region, current_region, st._region, st.result)

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
    def _replace_region_with_node(parent_region, sub_region, updated_sub_region, node):
        parent_region.replace_region(sub_region, updated_sub_region, node)

    @staticmethod
    def _replace_region_with_region(parent_region, sub_region, new_region):
        parent_region.replace_region_with_region(sub_region, new_region)

    def _get_switch_case_entries(self) -> Dict[int, int]:
        if self.function is None:
            return {}

        entries = {}
        func_block_addrs = self.function.block_addrs_set

        jump_tables = self.kb.cfgs["CFGFast"].jump_tables
        for jump_table_head_addr, jumptable in jump_tables.items():
            if jump_table_head_addr not in func_block_addrs:
                continue
            for entry_addr in jumptable.jumptable_entries:
                entries[entry_addr] = jump_table_head_addr

        return entries


register_analysis(RecursiveStructurer, "RecursiveStructurer")

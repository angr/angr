from __future__ import annotations

import copy
import itertools
import logging
from collections import defaultdict
from collections.abc import Iterable, Mapping
from typing import TYPE_CHECKING

from angr import ailment
from angr.analyses.analysis import Analysis, register_analysis
from angr.analyses.decompiler.condition_processor import ConditionProcessor
from angr.analyses.decompiler.empty_node_remover import EmptyNodeRemover
from angr.analyses.decompiler.jump_target_collector import JumpTargetCollector
from angr.analyses.decompiler.jumptable_entry_condition_rewriter import JumpTableEntryConditionRewriter
from angr.analyses.decompiler.redundant_label_remover import RedundantLabelRemover
from angr.analyses.decompiler.region_overlay import RegionOverlay
from angr.analyses.decompiler.structurer_nodes import BaseNode, MultiNode
from angr.utils.graph import GraphUtils

from .dream import DreamStructurer
from .phoenix import PhoenixStructurer
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

        self.result: BaseNode | None = None
        self.result_incomplete: bool = False
        self.result_structurer_cls: type = self.structurer_cls

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
        payload_snapshot = self._snapshot_mutable_graph_payload(manager.graph)
        fallback_eligible = issubclass(self.structurer_cls, PhoenixStructurer) and self.function is not None
        dream_input_graph = copy.deepcopy(manager.graph) if fallback_eligible else None

        try:
            primary_result, complete = self._structure_overlay_tree_once(root, self.structurer_cls)
            # Structurers intentionally edit the blocks they consume. Keep those edits in an isolated result tree,
            # then restore the live RegionIdentifier/Clinic graph in the outer finally block. OverlayManager can undo
            # topology, but it cannot observe direct ``block.statements = ...`` assignments inside structurers.
            isolated_primary_result = copy.deepcopy(primary_result)

            if not complete and issubclass(self.structurer_cls, PhoenixStructurer) and self.function is not None:
                # Phoenix-style structurers destructively refine the overlay graph. A root-level failure means there
                # is no structured result that can own those mutations, so restore the exact input before giving the
                # independent DREAM algorithm a chance to structure it. DREAM requires a different region invariant
                # (single-exit loops), so it must get a fresh RegionIdentifier result built from the restored AIL graph,
                # never the Phoenix-compatible region tree. Child-level failures are handled transactionally in
                # _structure_overlay_tree_once() and do not trigger this whole-function fallback.
                # Clone condition state *after* the primary attempt. Phoenix may materialize mappings for symbolic
                # conditions already present in the pristine input graph; DREAM needs those mappings to turn its
                # result back into AIL. The clone preserves that evidence while ensuring a failed optional fallback
                # cannot contaminate the partial Phoenix result we retain.
                dream_cond_proc = self._copy_condition_processor(self.cond_proc)
                manager.rollback(checkpoint)
                try:
                    assert dream_input_graph is not None
                    dream_root = self._make_dream_region_tree(root, dream_input_graph, dream_cond_proc)
                    dream_manager = dream_root.manager
                    dream_checkpoint = dream_manager.checkpoint()
                    try:
                        dream_result, dream_complete = self._structure_overlay_tree_once(
                            dream_root, DreamStructurer, condition_processor=dream_cond_proc
                        )
                    finally:
                        dream_manager.rollback(dream_checkpoint)
                        dream_manager.commit(dream_checkpoint)
                except Exception:  # pylint:disable=broad-exception-caught
                    # This is an optional recovery path for output that was already incomplete. It must not turn the
                    # traditional partial Phoenix result into a decompilation failure.
                    _l.info(
                        "DREAM fallback after %s root failure did not complete", self.structurer_cls.NAME, exc_info=True
                    )
                else:
                    if dream_complete:
                        _l.info(
                            "%s could not structure the root region; DREAM completed it after an exact overlay "
                            "rollback and fresh region identification",
                            self.structurer_cls.NAME,
                        )
                        self.result = dream_result
                        self.result_structurer_cls = DreamStructurer
                        self.cond_proc = dream_cond_proc
                        return

            self.result = isolated_primary_result
            if complete:
                self.result_structurer_cls = self.structurer_cls
            else:
                _l.warning(
                    "Structuring failed to complete (most likely due to bugs in structuring). The output will miss "
                    "code blocks."
                )
                self.result_incomplete = True
        finally:
            # restore the shared graph and the overlay tree for post-structuring consumers of the region tree
            manager.rollback(checkpoint)
            manager.commit(checkpoint)
            self._restore_mutable_graph_payload(payload_snapshot)

    @staticmethod
    def _snapshot_mutable_graph_payload(graph) -> list[tuple[object, dict[str, object]]]:
        """Capture mutable payload on the input nodes without changing their identities.

        A deep graph copy is suitable as independent fallback input, but replacing the live graph with that copy
        would invalidate RegionOverlay ownership and every external node reference. This snapshot instead preserves
        each original object and the mutable containers that structuring is allowed to rewrite.
        """

        snapshots: list[tuple[object, dict[str, object]]] = []
        pending = list(graph)
        seen: set[int] = set()

        def snapshot_value(value):
            if isinstance(value, list):
                return list(value)
            if isinstance(value, dict):
                return value.copy()
            if isinstance(value, set):
                return set(value)
            return value

        def contained_nodes(value) -> Iterable[object]:
            if isinstance(value, (ailment.Block, BaseNode, MultiNode)):
                yield value
            elif isinstance(value, Mapping):
                for key, item in value.items():
                    yield from contained_nodes(key)
                    yield from contained_nodes(item)
            elif isinstance(value, (list, tuple, set)):
                for item in value:
                    yield from contained_nodes(item)

        while pending:
            node = pending.pop()
            if id(node) in seen:
                continue
            seen.add(id(node))

            if isinstance(node, ailment.Block):
                payload = {"statements": list(node.statements)}
            else:
                payload = {}
                for cls in type(node).__mro__:
                    slots = getattr(cls, "__slots__", ())
                    if isinstance(slots, str):
                        slots = (slots,)
                    for slot in slots:
                        if slot not in payload and hasattr(node, slot):
                            payload[slot] = snapshot_value(getattr(node, slot))

            snapshots.append((node, payload))
            for value in payload.values():
                pending.extend(contained_nodes(value))

        return snapshots

    @staticmethod
    def _restore_mutable_graph_payload(snapshots: list[tuple[object, dict[str, object]]]) -> None:
        for node, payload in snapshots:
            for attr, value in payload.items():
                # Assign fresh containers so the snapshot itself cannot become an alias of a restored mutable field.
                if isinstance(value, list):
                    value = list(value)
                elif isinstance(value, dict):
                    value = value.copy()
                elif isinstance(value, set):
                    value = set(value)
                setattr(node, attr, value)

    @staticmethod
    def _copy_condition_processor(cond_proc: ConditionProcessor) -> ConditionProcessor:
        """Fork mutable condition state so a failed optional fallback cannot contaminate the primary result."""

        clone = copy.copy(cond_proc)
        clone._condition_mapping = dict(cond_proc._condition_mapping)  # pylint:disable=protected-access
        clone.jump_table_conds = defaultdict(
            set, {key: set(values) for key, values in cond_proc.jump_table_conds.items()}
        )
        clone.reaching_conditions = dict(cond_proc.reaching_conditions)
        clone.guarding_conditions = dict(cond_proc.guarding_conditions)
        clone._ast2annotations = {  # pylint:disable=protected-access
            ast: dict(tags)
            for ast, tags in cond_proc._ast2annotations.items()  # pylint:disable=protected-access
        }
        clone._peephole_expr_optimizations = list(  # pylint:disable=protected-access
            cond_proc._peephole_expr_optimizations  # pylint:disable=protected-access
        )
        return clone

    def _make_dream_region_tree(
        self, root: RegionOverlay, input_graph, dream_cond_proc: ConditionProcessor
    ) -> RegionOverlay:
        """Recover a DREAM-compatible region tree from a Phoenix attempt's restored input graph."""
        # The graph may contain condition variables introduced before structuring. Preserve their established AIL
        # mappings while RegionIdentifier adds the reaching conditions needed by the DREAM-compatible region tree.
        ri = self.project.analyses.RegionIdentifier.prep(kb=self.kb, fail_fast=self._fail_fast)(
            self.function,
            # Phoenix mutates AIL statements outside OverlayManager's topology transaction. ``input_graph`` is the
            # deep snapshot captured before that attempt, including MultiNodes and statement lists; using the merely
            # topology-restored live graph here would feed DREAM stale or missing control transfers.
            graph=input_graph,
            cond_proc=dream_cond_proc,
            ail_manager=self.ail_manager,
            update_graph=True,
            force_loop_single_exit=True,
            refine_loops_with_single_successor=False,
            expose_loop_head_backedges=False,
            entry_node_addr=(root.head.addr, getattr(root.head, "idx", None)),
        )
        assert ri.region is not None
        return ri.region

    def _structure_overlay_tree_once(
        self,
        root: RegionOverlay,
        structurer_cls: type[StructurerBase],
        *,
        condition_processor: ConditionProcessor | None = None,
    ) -> tuple[BaseNode | None, bool]:
        """Destructively structure one overlay-tree attempt, returning the root result and its completeness."""
        manager = root.manager
        condition_processor = self.cond_proc if condition_processor is None else condition_processor
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
                region_checkpoint = manager.checkpoint()
                # structure this region
                st: StructurerBase = self.project.analyses[structurer_cls].prep(kb=self.kb, fail_fast=self._fail_fast)(
                    current_region,
                    parent_map=parent_map,
                    condition_processor=condition_processor,
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
                        # Take the partial result out of the graph. The caller decides whether to retry another
                        # structurer or retain the traditional incomplete output.
                        return self._pick_incomplete_result_from_region(current_region), False
                    return st.result, True

                if st.result is None:
                    # A structurer may virtualize edges and collapse nodes before discovering that the region is
                    # not reducible. Those partial mutations describe statements inside a result that does not
                    # exist; leaking them into the parent disconnects the shared graph when the region dissolves.
                    # Restore the exact pre-attempt region first, then let the intact members fall back to the
                    # enclosing region.
                    manager.rollback(region_checkpoint)
                    current_region.dissolve()
                elif st.result in current_region.members:
                    # the structurer destructively reduced the region to a single member node (e.g. Phoenix):
                    # that node is the result and takes the region's place in the parent
                    current_region.finalize(st.result, succ_snapshot=succ_snapshot)
                else:
                    # the structurer produced an external result without reducing the shared graph (e.g. Dream):
                    # collapse all member nodes onto the result node
                    current_region.collapse_to(st.result)

        return None, False

    def _post_process_result(self):
        if self.result_structurer_cls is DreamStructurer:
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

        if self.result_structurer_cls is DreamStructurer:
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

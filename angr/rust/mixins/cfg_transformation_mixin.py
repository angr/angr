import logging

from ailment import Const, Block
from ailment.expression import VirtualVariable, Phi
from ailment.statement import Jump, ConditionalJump, Assignment
from networkx import NetworkXError


l = logging.getLogger(name=__name__)


class CFGTransformationMixin:
    def __init__(self, graph):
        self._graph = graph
        self._block_by_addr_and_idx = None

        self.update_block_indexes()

    def update_block_indexes(self):
        self._block_by_addr_and_idx = {}
        for block in self._graph.nodes:
            self._block_by_addr_and_idx[(block.addr, block.idx)] = block

    def remove_jump_target(self, block: Block, jump_target: Const | int, jump_target_idx: int | None):
        removed = False
        last_stmt = block.statements[-1] if block.statements else None
        if isinstance(jump_target, Const):
            jump_target = jump_target.value
        if isinstance(last_stmt, Jump):
            if (
                isinstance(last_stmt.target, Const)
                and last_stmt.target.value == jump_target
                and last_stmt.target_idx == jump_target_idx
            ):
                block.statements = block.statements[:-1]
                removed = True
        elif isinstance(last_stmt, ConditionalJump):
            new_target, new_target_idx = None, None
            if (
                isinstance(last_stmt.true_target, Const)
                and last_stmt.true_target.value == jump_target
                and last_stmt.true_target_idx == jump_target_idx
            ):
                new_target = last_stmt.false_target
                new_target_idx = last_stmt.false_target_idx
            elif (
                isinstance(last_stmt.false_target, Const)
                and last_stmt.false_target.value == jump_target
                and last_stmt.false_target_idx == jump_target_idx
            ):
                new_target = last_stmt.true_target
                new_target_idx = last_stmt.true_target_idx
            if new_target:
                new_stmt = Jump(
                    last_stmt.idx,
                    new_target,
                    new_target_idx,
                    **last_stmt.tags,
                )
                block.statements[-1] = new_stmt
                removed = True
        if removed:
            target_block = self._block_by_addr_and_idx.get((jump_target, jump_target_idx), None)
            if target_block:
                try:
                    self._graph.remove_edge(block, target_block)
                except NetworkXError:
                    pass
        return removed

    def remove_false_branch(self, block: Block):
        if block.statements and isinstance(block.statements[-1], ConditionalJump):
            jump = block.statements[-1]
            self.remove_jump_target(block, jump.false_target, jump.false_target_idx)

    @staticmethod
    def _update_phi_variables_after_removing_block(graph, preds, removed_block: Block) -> None:
        rblock_phi_to_src: dict[int, dict[tuple[int, int | None], int]] = {}
        for stmt in removed_block.statements:
            if isinstance(stmt, Assignment) and isinstance(stmt.dst, VirtualVariable) and isinstance(stmt.src, Phi):
                rblock_phi_to_src[stmt.dst.varid] = dict(stmt.src.src_and_vvars)

        for block in graph.nodes:
            for idx in range(len(block.statements)):  # pylint:disable=consider-using-enumerate
                stmt = block.statements[idx]
                if isinstance(stmt, Assignment) and isinstance(stmt.src, Phi) and isinstance(stmt.dst, VirtualVariable):
                    # remove the variable from the specified source
                    new_src_and_vvars = {}
                    for src, vvar in stmt.src.src_and_vvars:
                        if src != (removed_block.addr, removed_block.idx):
                            new_src_and_vvars[src] = vvar
                        else:
                            # we need to handle two cases:
                            # - vvar might be defined in the removed block
                            # - pred is already a predecessor of the current block
                            if vvar and vvar.varid in rblock_phi_to_src:
                                # vvar is defined in the removed block
                                replacements = rblock_phi_to_src[vvar.varid]
                            else:
                                replacements = {(pred.addr, pred.idx): vvar for pred in preds}
                            for repl_src, repl_vvar in replacements.items():
                                if repl_src not in new_src_and_vvars:
                                    new_src_and_vvars[repl_src] = repl_vvar
                    # make it a list
                    new_src_and_vvars_lst = list(new_src_and_vvars.items())
                    new_phi = Phi(stmt.src.idx, stmt.src.bits, new_src_and_vvars_lst, **stmt.src.tags)
                    block.statements[idx] = Assignment(stmt.idx, stmt.dst, new_phi, **stmt.tags)

    def replace_jump_target(
        self,
        block,
        old_target: Const | int | None,
        old_target_idx: int | None,
        new_target: Const | int,
        new_target_idx: int | None,
    ):
        if isinstance(old_target, Const):
            old_target = old_target.value
        if isinstance(new_target, Const):
            new_target = new_target.value
        last_stmt = block.statements[-1] if block.statements else None
        if isinstance(last_stmt, Jump):
            if old_target is None or (
                isinstance(last_stmt.target, Const)
                and last_stmt.target.value == old_target
                and last_stmt.target_idx == old_target_idx
            ):
                new_stmt = last_stmt.copy()
                new_stmt.target = Const(0, None, new_target, last_stmt.target.bits)
                new_stmt.target_idx = new_target_idx
                block.statements[-1] = new_stmt
        elif isinstance(last_stmt, ConditionalJump):
            if old_target is None or (
                isinstance(last_stmt.true_target, Const)
                and isinstance(last_stmt.false_target, Const)
                and (
                    (last_stmt.true_target.value == old_target and last_stmt.false_target.value == new_target)
                    or (last_stmt.false_target.value == old_target and last_stmt.true_target.value == new_target)
                )
            ):
                target = Const(0, None, new_target, last_stmt.true_target.bits)
                if last_stmt.true_target.value == old_target and last_stmt.false_target.value == new_target:
                    new_target_idx = last_stmt.false_target_idx
                else:
                    new_target_idx = last_stmt.true_target_idx
                block.statements[-1] = Jump(
                    last_stmt.idx,
                    target,
                    new_target_idx,
                    **last_stmt.tags,
                )
            elif (
                isinstance(last_stmt.true_target, Const)
                and last_stmt.true_target.value == old_target
                and last_stmt.true_target_idx == old_target_idx
            ):
                last_stmt.true_target.value = new_target
                last_stmt.true_target_idx = new_target_idx
            elif (
                isinstance(last_stmt.false_target, Const)
                and last_stmt.false_target.value == old_target
                and last_stmt.false_target_idx == old_target_idx
            ):
                last_stmt.false_target.value = new_target
                last_stmt.false_target_idx = new_target_idx

        if old_target:
            try:
                old_target_block = self._block_by_addr_and_idx.get((old_target, old_target_idx), None)
                if old_target_block:
                    self._graph.remove_edge(block, old_target_block)
            except NetworkXError:
                pass
        else:
            for succ in list(self._graph.successors(block)):
                try:
                    self._graph.remove_edge(block, succ)
                except NetworkXError:
                    pass
        new_target_block = self._block_by_addr_and_idx.get((new_target, new_target_idx), None)
        assert new_target_block is not None
        self._graph.add_edge(block, new_target_block)

    def remove_block(self, block: Block):
        graph = self._graph

        if block not in graph:
            l.warning(f"{block} not in graph")
            return False

        succs = list(graph.successors(block))
        num_successors = len(succs)
        preds = list(graph.predecessors(block))

        if num_successors == 2:
            # We only handle a special case here, where one of the successors is the removed block itself
            self.remove_jump_target(block, block.addr, block.idx)
            num_successors = len(list(graph.successors(block)))
            if num_successors != 1:
                # l.warning("Failed to remove block with more two successor")
                return False

        if num_successors == 1:
            new_target_block = list(graph.successors(block))[0]
            for pred in list(graph.predecessors(block)):
                self.replace_jump_target(pred, block.addr, block.idx, new_target_block.addr, new_target_block.idx)
        elif num_successors == 0:
            for pred in list(graph.predecessors(block)):
                self.remove_jump_target(pred, block.addr, block.idx)
        else:
            l.warning("Can not remove block with more than two successors")
            return False

        # Remove block from graph
        graph.remove_node(block)
        self._update_phi_variables_after_removing_block(graph, preds, block)
        if (block.addr, block.idx) in self._block_by_addr_and_idx:
            del self._block_by_addr_and_idx[(block.addr, block.idx)]
        l.debug(f"Block:\n{str(block)}removed by {self.__class__.__module__}.{self.__class__.__name__}")

        # Remove old successors (and their successors recursively) with no predecessor
        # Notice that old successors may not be connected to the predecessors of original block
        while succs:
            succ = succs.pop(0)
            if succ in graph and graph.in_degree(succ) == 0:
                succs += list(self._graph.successors(succ))
                graph.remove_node(succ)
                if (succ.addr, succ.idx) in self._block_by_addr_and_idx:
                    del self._block_by_addr_and_idx[(succ.addr, succ.idx)]
                l.debug(
                    f"Successor:\n{str(block)}removed by {self.__class__.__module__}.{self.__class__.__name__} because of zero in-degree"
                )

        return True

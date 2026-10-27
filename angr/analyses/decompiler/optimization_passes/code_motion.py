from __future__ import annotations

import itertools
import logging
from collections import defaultdict

import networkx as nx

from angr.ailment import Block
from angr.ailment.block_walker import AILBlockViewer
from angr.ailment.expression import (
    BinaryOp,
    Const,
    Expression,
    Phi,
    StackBaseOffset,
    UnaryOp,
    VirtualVariable,
    VirtualVariableCategory,
)
from angr.ailment.statement import Assignment, ConditionalJump, DirtyStatement, Jump, Statement
from angr.analyses.decompiler.block_io_finder import BlockIOFinder
from angr.analyses.decompiler.block_similarity import index_of_similar_stmts, is_similar
from angr.analyses.decompiler.optimization_passes.optimization_pass import OptimizationPass, OptimizationPassStage
from angr.analyses.decompiler.utils import add_labels, remove_labels, to_ail_supergraph
from angr.utils.ssa import get_vvar_deflocs

_l = logging.getLogger(name=__name__)


class CodeMotionOptimization(OptimizationPass):
    """
    Moves common statements out of blocks that share the same predecessors or the same
    successors. This is done to reduce the number of statements in a block and to make the
    blocks more similar to each other.

    As an example::

        if (x) {
            b = 2;
            a = 1;
            c = 3;
        } else {
            b = 2;
            c = 3;
        }

    Will be turned into::

        if (x) {
            a = 1;
        }
        b = 2;
        c = 3;

    Current limitations (for very conservative operations):

    - moving statements above conditional jumps is not supported
    - only immediate children and parents are considered for moving statements
    - when moving statements down, a block is only considered if already has a matching statement at the end
    """

    ARCHES = None
    PLATFORMS = None
    NAME = "Merge common statements in sub-scopes"
    STAGE = OptimizationPassStage.AFTER_GLOBAL_SIMPLIFICATION
    DESCRIPTION = __doc__ or ""

    def __init__(self, *args, max_iters=10, node_idx_start: int = 1, **kwargs):
        super().__init__(*args, **kwargs)
        self._node_idx_start = node_idx_start
        self._max_optimization_runs = max_iters
        self.analyze()

    def _check(self):
        return True, None

    def _analyze(self, cache=None):
        _l.warning("CodeMotionOptimization is likely broken right now, use with caution!")
        optimization_runs = 0
        graph_copy = remove_labels(nx.DiGraph(self._graph))
        updates = True
        graph_changed = False
        while optimization_runs < self._max_optimization_runs and updates:
            optimization_runs += 1
            super_graph = to_ail_supergraph(graph_copy)
            updates, updated_blocks = self._move_common_code(super_graph)
            if updates:
                critical_fail = self.update_graph_with_super_edits(graph_copy, super_graph, updated_blocks)
                if critical_fail:
                    _l.error("Critical failure in updating graph with super edits, aborting")
                    break
                graph_changed = True

        if graph_changed:
            self.out_graph = add_labels(graph_copy, self.manager)

    @staticmethod
    def update_graph_with_super_edits(
        original_graph: nx.DiGraph, super_graph: nx.DiGraph, updated_blocks: dict[Block, Block]
    ) -> bool:
        """
        This function updates an graph when doing block edits on a supergraph version of that same graph.
        The updated blocks must be provided as a dictionary where the keys are original block in the supergraph and
        the values are the new blocks that should replace them.

        The supergraph MUST be generated using the to_ail_supergraph function, since it stores the original nodes
        each super node represents. This is necessary to update the original graph with the new super nodes.
        """
        og_to_super = {}
        for old_super, new_super in updated_blocks.items():
            original_blocks = super_graph.nodes[old_super]["original_nodes"]
            for original_block in original_blocks:
                og_to_super[original_block] = new_super

        for old_super, new_super in updated_blocks.items():
            original_blocks = super_graph.nodes[old_super]["original_nodes"]
            first_node_preds = []
            last_node_preds = []
            for original_block in original_blocks:
                if original_block not in original_graph.nodes:
                    return True

                external_preds = [
                    pred for pred in original_graph.predecessors(original_block) if pred not in original_blocks
                ]
                external_succs = [
                    succ for succ in original_graph.successors(original_block) if succ not in original_blocks
                ]
                if external_preds:
                    first_node_preds = external_preds
                if external_succs:
                    last_node_preds = external_succs

            original_graph.remove_nodes_from(original_blocks)
            original_graph.add_node(new_super)
            for pred in first_node_preds:
                original_graph.add_edge(og_to_super.get(pred, pred), new_super)
            for succ in last_node_preds:
                original_graph.add_edge(new_super, og_to_super.get(succ, succ))

        return False

    def _move_common_code(self, graph) -> tuple[bool, dict[Block, Block] | None]:
        """
        Does two things at a high level:
        1. rearrange code in blocks to maximize the number of similar statements at the end of the block
        2. move common code out of blocks

        To understand the limitations of this approach, see the TODOs.
        """
        # TODO: how can you handle an odd-numbered switch case? or many blocks with the same child?
        for b0, b1 in itertools.combinations(graph.nodes, 2):
            if (
                b0 is b1
                or not b0.statements
                or not b1.statements
                or any(isinstance(stmt, DirtyStatement) for stmt in b0.statements + b1.statements)
                or is_similar(b0, b1)
            ):
                continue

            # TODO: add support for moving code to a shared parent block, which requires that we figure out how to
            #   move code above conditional jumps. Hard since you need to know if the condition executes code.
            # TODO: also, how do you deal with short-circuiting, which is a region parent, not just a block?

            # target any blocks that have a shared child and move common code to the child
            b0_succs = list(graph.successors(b0))
            b1_succs = list(graph.successors(b1))
            if (len(b0_succs) == len(b1_succs) == 1) and b0_succs[0] == b1_succs[0]:
                common_succ = b0_succs[0]
                common_succ_preds = list(graph.predecessors(common_succ))
                # you can only safely move code to a child if all the common_succ's preds are the ones
                # we are moving code from (2 nodes).
                if all(csp in (b0, b1) for csp in common_succ_preds):
                    success, updated_blocks = self._move_common_code_to_child(b0, b1, common_succ)
                    if success:
                        return True, updated_blocks

        return False, None

    def _move_common_code_to_parent(self, b0: Block, b1: Block, parent: Block):
        # TODO: this function does not work yet because you need to figure out if you can move a stmt above
        #   a conditional jump, which requires cross-block analysis
        changed, new_b0, new_b1 = self._make_stmts_end_similar(b0, b1, up=True)
        if not changed:
            return False, None

        # move the longest common suffix to the parent
        new_b0_stmts = new_b0.statements
        new_b1_stmts = new_b1.statements
        common_len = 0
        for idx, new_b0_stmt in enumerate(new_b0_stmts):
            if not new_b0_stmt.likes(new_b1_stmts[idx]):
                break
            common_len += 1

        if not common_len:
            raise ValueError("No common statements found, this is unexpected")

        common_stmts = [new_b0_stmts.pop(0) for _ in range(common_len)]
        for _ in range(common_len):
            new_b1_stmts.pop(0)

        parent_stmts = parent.statements.copy() or []
        if isinstance(parent_stmts[-1], (ConditionalJump, Jump)):
            parent_stmts = parent_stmts[:-1] + common_stmts + [parent_stmts[-1]]
        new_parent = parent.copy(statements=parent_stmts)

        return True, {b0: new_b0, b1: new_b1, parent: new_parent}

    def _move_common_code_to_child(self, b0: Block, b1: Block, child: Block):
        changed, new_b0, new_b1 = self._make_stmts_end_similar(b0, b1, down=True)
        if not changed:
            return False, None

        # move the longest common suffix to the parent
        new_b0_stmts = new_b0.statements
        new_b1_stmts = new_b1.statements
        common_len = 0
        # start from the -1 index and go backwards
        for idx in range(-1, -(min(len(new_b0_stmts), len(new_b1_stmts))) - 1, -1):
            if not new_b0_stmts[idx].likes(new_b1_stmts[idx]):
                break
            common_len += 1

        if not common_len:
            raise ValueError("No common statements found, this is unexpected")

        common_stmts = [new_b0_stmts.pop() for _ in range(common_len)]
        for _ in range(common_len):
            new_b1_stmts.pop()

        child_stmts = child.statements.copy() or []
        new_child = child.copy(statements=common_stmts[::-1] + child_stmts)

        return True, {b0: new_b0, b1: new_b1, child: new_child}

    def _make_stmts_end_similar(
        self, b0: Block, b1: Block, up=False, down=False
    ) -> tuple[bool, Block | None, Block | None]:
        """
        This algorithm attempts to rearrange two blocks to have the longest common sequence of statements
        at either ends of the blocks. It is flawed in that it currently only attempts to do this rearrangement
        if the blocks have at least one matching statement at the end.

        This algorithm iteratively removes statements from the ends of the blocks and then attempts to match
        the ends of the blocks. It will only do this if one of the two ends has a matching statement in the other.
        """
        self._assert_up_or_down(up, down)
        # copy the statements while filtering out statements that are not needed in the specific
        # movement case (up or down)
        curr_stmts = {}
        for blk in (b0, b1):
            new_stmts = blk.statements.copy()
            if down:
                last_stmt = new_stmts[-1]
                if isinstance(last_stmt, Jump):
                    new_stmts.pop()
                elif isinstance(last_stmt, ConditionalJump):
                    _l.warning("ConditionalJump at the end of block %s, this should never happen!", blk)
                    return False, None, None

            curr_stmts[blk] = new_stmts
        if not curr_stmts[b0] or not curr_stmts[b1]:
            return False, None, None

        # attempt to do a swapping algorithm to maximize the number of similar statements at the end
        changed = True
        stmts_updated = False
        matched_stmts = {b0: [], b1: []}
        max_iters = len(curr_stmts[b0]) * len(curr_stmts[b1])
        curr_iters = 0
        while changed and curr_iters < max_iters:
            changed = False
            try_next_swap = False
            for tgt0, tgt1 in ((b0, b1), (b1, b0)):
                t0_stmts = curr_stmts[tgt0]
                t1_stmts = curr_stmts[tgt1]
                if not t0_stmts or not t1_stmts:
                    break

                if up:
                    # maximize up
                    while t0_stmts and t1_stmts:
                        if t0_stmts[0].likes(t1_stmts[0]):
                            matched_stmts[b0].append((t0_stmts.pop(0), 0))
                            matched_stmts[b1].append((t1_stmts.pop(0), 0))
                            try_next_swap = True
                        else:
                            break
                    if not t0_stmts or not t1_stmts:
                        break
                elif down:
                    # maximize down
                    while t0_stmts and t1_stmts:
                        if t0_stmts[-1].likes(t1_stmts[-1]):
                            matched_stmts[b0].append((t0_stmts.pop(), -1))
                            matched_stmts[b1].append((t1_stmts.pop(), -1))
                            try_next_swap = True
                        else:
                            break
                    if not t0_stmts or not t1_stmts:
                        break

                if not try_next_swap:
                    continue

                stmts_updated = True
                swap_occurred, new_stmts = self._maximize_ends(t0_stmts, t1_stmts, up=up, down=down)
                if swap_occurred:
                    changed = True
                    curr_stmts[b0], curr_stmts[b1] = new_stmts
                    break

                try_next_swap = True

            curr_iters += 1
            if curr_iters > max_iters:
                raise ValueError("Exceeded max iterations, likely stuck in infinite loop")

        # did any changes occur?
        if not stmts_updated:
            return False, None, None

        # reconstruct the blocks and return them
        new_blks = {}
        for blk in (b0, b1):
            new_stmts = curr_stmts[blk]
            for stmt, idx in matched_stmts[blk][::-1]:
                if idx == -1:
                    new_stmts.append(stmt)
                else:
                    new_stmts.insert(idx, stmt)

            new_blks[blk] = blk.copy(statements=new_stmts)

        return True, new_blks[b0], new_blks[b1]

    def _maximize_ends(
        self, b0_stmts, b1_stmts, up=False, down=False
    ) -> tuple[bool, tuple[list[Statement], list[Statement]]]:
        self._assert_up_or_down(up, down)

        similar_stmt = b0_stmts[0] if up else b0_stmts[-1]
        idx_similar = index_of_similar_stmts([similar_stmt], b1_stmts)
        if idx_similar is None or len(b1_stmts) == 1:
            return False, (b0_stmts, b1_stmts)

        target_stmt = b1_stmts[idx_similar]
        success, new_b1_stmts = self._move_to_end(target_stmt, b1_stmts, up=up, down=down)
        return (success and (b1_stmts != new_b1_stmts)), (b0_stmts, new_b1_stmts)

    def _move_to_end(self, stmt, stmts, up=False, down=False) -> tuple[bool, list[Statement]]:
        """
        Attempts to move a stmt to either the top or the bottom of stmts.
        It does this by attempting to swap, 1 by 1, in either direction it is targeting.
        """
        new_stmts = stmts.copy()
        stmt_idx = new_stmts.index(stmt)
        swap_offset = -1 if up else 1
        swap_order = range(stmt_idx + 1, len(new_stmts)) if down else range(stmt_idx - 1, -1, -1)
        io_finder = BlockIOFinder(new_stmts, self.project)
        for swap_pos in swap_order:
            src_stmt = new_stmts[stmt_idx]
            if io_finder.can_swap(src_stmt, new_stmts, 1 if down else -1):
                new_stmts[stmt_idx], new_stmts[swap_pos] = new_stmts[swap_pos], new_stmts[stmt_idx]
                stmt_idx += swap_offset
            else:
                return False, stmts

        return True, new_stmts

    @staticmethod
    def _assert_up_or_down(up, down):
        if up and down:
            raise ValueError("Cannot maximize both up and down")
        if not up and not down:
            raise ValueError("Must maximize either up or down")


class _PureExprScanner(AILBlockViewer):
    """
    Collects the virtual variables an expression reads, and whether it reads memory or has side effects.
    """

    def __init__(self):
        super().__init__()
        self.vvars: set[int] = set()
        self.impure = False

    def _handle_VirtualVariable(self, expr_idx, expr, stmt_idx, stmt, block):
        self.vvars.add(expr.varid)

    def _handle_UnaryOp(self, expr_idx, expr, stmt_idx, stmt, block):
        # the address of a slot does not read the variable
        if expr.op == "Reference" and isinstance(expr.operand, VirtualVariable):
            return None
        return super()._handle_UnaryOp(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_Load(self, expr_idx, expr, stmt_idx, stmt, block):
        self.impure = True

    def _handle_Call(self, expr_idx, expr, stmt_idx, stmt, block):
        self.impure = True

    def _handle_DirtyExpression(self, expr_idx, expr, stmt_idx, stmt, block):
        self.impure = True

    def _handle_Phi(self, expr_idx, expr, stmt_idx, stmt, block):
        self.impure = True

    def _handle_MultiStatementExpression(self, expr_idx, expr, stmt_idx, stmt, block):
        self.impure = True

    def _top(self, expr_idx, expr, stmt_idx, stmt, block):
        if not isinstance(expr, StackBaseOffset):
            self.impure = True


class _StackReferenceScanner(AILBlockViewer):
    """
    Collects the stack ranges whose address appears in the graph, as ``(offset, size)``.
    """

    def __init__(self):
        super().__init__()
        self.ranges: set[tuple[int, int]] = set()
        self.refs: dict[int, UnaryOp] = {}

    def _handle_UnaryOp(self, expr_idx, expr, stmt_idx, stmt, block):
        if expr.op == "Reference" and isinstance(expr.operand, VirtualVariable) and expr.operand.was_stack:
            self.ranges.add((expr.operand.stack_offset, expr.operand.size))
            self.refs.setdefault(expr.operand.stack_offset, expr)
        return super()._handle_UnaryOp(expr_idx, expr, stmt_idx, stmt, block)

    def _top(self, expr_idx, expr, stmt_idx, stmt, block):
        if isinstance(expr, StackBaseOffset):
            self.ranges.add((expr.offset, 1))


class EquivalentDefinitionSinker:
    """
    Sink equivalent definitions of a variable out of the arms of a branch and into the join.

    In a devirtualized VM body each arm of a branch ends by resetting the VM's stack pointer (a frame slot), each arm
    computing the same address its own way: ``iter = &v2.field_10 - 16`` on one side and ``iter = &v2`` on the other.
    In SSA these definitions meet in a phi at the join. When every phi operand provably holds the same value, the phi
    is replaced by one definition of that value and the per-arm definitions are left for dead-code elimination.

    Operands are compared by resolving them through their SSA definitions into ``root + offset``, where the root is
    the frame base, a constant, or a virtual variable that is not itself an add/sub of a constant. Operands that do
    not resolve are equal only if their defining expressions are identical and read no memory.
    """

    MAX_CHAIN_DEPTH = 16
    MAX_CHAIN_LENGTH = 4096

    def __init__(self, graph: nx.DiGraph, entry: Block, manager):
        self._graph = graph
        self._entry = entry
        self._manager = manager
        self._defs: dict[int, tuple[Block, int]] = {}
        self._vvars: dict[int, VirtualVariable] = {}
        self._defs_by_block: defaultdict[tuple[int, int | None], list[tuple[int, VirtualVariable]]] = defaultdict(list)
        # stack slot offset -> a Reference expression naming it
        self._stack_refs: dict[int, UnaryOp] = {}
        self._affine_cache: dict[int, tuple | None] = {}
        self._doms: dict[Block, Block] = {}
        # blocks that may execute more than once
        self._cyclic: set[tuple[int, int | None]] = set()
        self._between_cache: dict[tuple, set[tuple[int, int | None]]] = {}
        self.sunk = 0
        self.replacements: dict[Block, Block] = {}

    def run(self) -> dict[Block, Block]:
        """
        Compute the rewritten blocks. The graph is not modified; ``{old block: new block}`` is returned.
        """
        blocks = {(b.addr, b.idx): b for b in self._graph}
        for varid, (vvar, loc) in get_vvar_deflocs(self._graph).items():
            self._defs[varid] = blocks[(loc.block_addr, loc.block_idx)], loc.stmt_idx
            self._vvars[varid] = vvar
            self._defs_by_block[(loc.block_addr, loc.block_idx)].append((loc.stmt_idx, vvar))
        self._doms = nx.immediate_dominators(self._graph, self._entry)
        for scc in nx.strongly_connected_components(self._graph):
            if len(scc) > 1 or any(self._graph.has_edge(b, b) for b in scc):
                self._cyclic |= {(b.addr, b.idx) for b in scc}

        escaped = _StackReferenceScanner()
        for block in self._graph:
            escaped.walk(block)
        self._stack_refs = escaped.refs

        for block in self._graph:
            # in a cycle, a join may also merge a value with a later instance of itself; leave it alone
            if block not in self._doms or self._graph.in_degree(block) < 2 or (block.addr, block.idx) in self._cyclic:
                continue
            new_stmts = self._sink_into(block, escaped.ranges)
            if new_stmts is not None:
                self.replacements[block] = block.copy(statements=new_stmts)
        return self.replacements

    def _sink_into(self, block: Block, escaped: set[tuple[int, int]]) -> list[Statement] | None:
        phis = [i for i, stmt in enumerate(block.statements) if isinstance(stmt, Assignment) and stmt.is_phi_assignment]
        if not phis:
            return None

        sunk: dict[int, Assignment] = {}
        for stmt_idx in phis:
            stmt = block.statements[stmt_idx]
            dst = stmt.dst
            if dst.was_stack and any(
                self._overlaps(("stack", dst.stack_offset, dst.size), ("stack", off, size)) for off, size in escaped
            ):
                continue
            value = self._common_value(stmt.src, block)
            if value is not None:
                sunk[stmt_idx] = Assignment(stmt.idx, dst, value, **stmt.tags)
        if not sunk:
            return None

        # the new definitions go after the remaining phis, which must stay at the top of the block
        last_phi = phis[-1]
        new_stmts = [s for i, s in enumerate(block.statements[: last_phi + 1]) if i not in sunk]
        new_stmts += [sunk[i] for i in phis if i in sunk]
        new_stmts += block.statements[last_phi + 1 :]
        self.sunk += len(sunk)
        return new_stmts

    def _common_value(self, phi: Phi, join: Block) -> Expression | None:
        operands = [vvar for _, vvar in phi.src_and_vvars]
        if len(operands) < 2 or any(v is None or v.bits != phi.bits for v in operands):
            return None

        keys = [self._affine_vvar(v, 0) for v in operands]
        if not (keys[0] is not None and all(k == keys[0] for k in keys[1:])):
            srcs = [self._def_src(v) for v in operands]
            read = self._scan(srcs[0]) if srcs[0] is not None else None
            if not (
                read is not None
                and all(s is not None and s.likes(srcs[0]) for s in srcs[1:])
                and all(self._single_instance(varid) for varid in read | {v.varid for v in operands})
            ):
                return None

        # prefer a value already available at the join, then an arm's own expression of it
        for vvar in operands:
            if self._usable_at(vvar, join):
                return vvar
        for vvar in operands:
            src = self._def_src(vvar)
            if src is None or src.bits != phi.bits:
                continue
            read = self._scan(src)
            if read is not None and all(self._usable_at(self._vvars.get(varid), join) for varid in read):
                return src
        if keys[0] is None:
            return None
        # the latest variable on an operand's chain that the join may read, then the chain's root
        for vvar in operands:
            cur = vvar
            for _ in range(self.MAX_CHAIN_LENGTH):
                src = self._def_src(cur)
                step = self._vvar_step(src) if src is not None else None
                if step is None:
                    break
                cur = step[0]
                cur_key = self._affine_cache.get(cur.varid)
                if cur_key is None or cur_key[0] != keys[0][0]:
                    break
                if self._usable_at(cur, join):
                    return self._offset_from(cur, (keys[0][1] - cur_key[1]) & ((1 << phi.bits) - 1), phi.bits)
        return self._materialize(keys[0], phi.bits, join)

    def _materialize(self, key: tuple, bits: int, join: Block) -> Expression | None:
        root, off = key
        if root is None:
            return Const(self._manager.next_atom(), off, bits)
        if root == "stack":
            target = off - (1 << bits) if off >> (bits - 1) else off
            # the slot closest to the address, so it reads as &slot +- a small offset
            refs = sorted(self._stack_refs.items(), key=lambda kv: (abs(kv[0] - target), kv[0]))
            base = next((ref for _, ref in refs if self._available_at(ref.operand.varid, join)), None)
            if base is None:
                return None
            off = (off - base.operand.stack_offset) & ((1 << bits) - 1)
        else:
            vvar = self._vvars.get(root[1])
            if vvar is None or vvar.bits != bits or not self._usable_at(vvar, join):
                return None
            base = vvar
        return self._offset_from(base, off, bits)

    def _offset_from(self, base: Expression, off: int, bits: int) -> Expression:
        if off == 0:
            return base
        op = "Add"
        if off >> (bits - 1):
            op, off = "Sub", (1 << bits) - off
        return BinaryOp(
            self._manager.next_atom(), op, [base, Const(self._manager.next_atom(), off, bits)], False, bits=bits
        )

    def _usable_at(self, vvar: VirtualVariable | None, join: Block) -> bool:
        """
        Whether the join may read ``vvar``. Besides dominance, its location must not be redefined on the way:
        reading it there would make it interfere with the redefinition, and dephication would split it into a
        separate variable.
        """
        if vvar is None:
            # an argument without a definition in the graph
            return True
        if not self._available_at(vvar.varid, join):
            return False
        loc = self._location(vvar)
        if loc is None:
            return True
        def_block, def_idx = self._defs.get(vvar.varid, (self._entry, -1))
        def_key = def_block.addr, def_block.idx
        join_key = join.addr, join.idx

        between = self._blocks_between(def_block, join)
        for block_key, defs in self._defs_by_block.items():
            if block_key == join_key:
                continue
            if block_key == def_key and def_key not in between:
                defs = [(i, v) for i, v in defs if i > def_idx]
            elif block_key not in between:
                continue
            for _, other in defs:
                if other.varid != vvar.varid and self._overlaps(loc, self._location(other)):
                    return False
        return True

    def _blocks_between(self, start: Block, end: Block) -> set[tuple[int, int | None]]:
        """
        Blocks on some path from ``start`` to ``end``, excluding both unless a cycle passes through ``start``.
        """
        cache_key = (start.addr, start.idx), (end.addr, end.idx)
        if cache_key in self._between_cache:
            return self._between_cache[cache_key]
        fwd: set[Block] = set()
        stack = [s for s in self._graph.successors(start) if s is not end]
        while stack:
            b = stack.pop()
            if b in fwd or (b.addr, b.idx) == (end.addr, end.idx):
                continue
            fwd.add(b)
            stack.extend(self._graph.successors(b))
        bwd: set[Block] = set()
        stack = list(self._graph.predecessors(end))
        while stack:
            b = stack.pop()
            if b in bwd:
                continue
            bwd.add(b)
            if (b.addr, b.idx) != (start.addr, start.idx):
                stack.extend(self._graph.predecessors(b))
        r = self._between_cache[cache_key] = {(b.addr, b.idx) for b in fwd & bwd}
        return r

    @staticmethod
    def _location(vvar: VirtualVariable | None) -> tuple | None:
        if vvar is None:
            return None
        if vvar.was_stack:
            return "stack", vvar.stack_offset, vvar.size
        if vvar.was_reg:
            return "reg", vvar.reg_offset, vvar.size
        if vvar.was_parameter:
            if vvar.parameter_category == VirtualVariableCategory.STACK:
                return "stack", vvar.parameter_stack_offset, vvar.size
            if vvar.parameter_category == VirtualVariableCategory.REGISTER:
                return "reg", vvar.parameter_reg_offset, vvar.size
        return None

    @staticmethod
    def _overlaps(a: tuple, b: tuple | None) -> bool:
        return b is not None and a[0] == b[0] and a[1] < b[1] + b[2] and b[1] < a[1] + a[2]

    def _available_at(self, varid: int, join: Block) -> bool:
        defloc = self._defs.get(varid)
        if defloc is None:
            # no definition in the graph: a function argument
            return True
        def_block = defloc[0]
        return (def_block.addr, def_block.idx) != (join.addr, join.idx) and self._dominates(def_block, join)

    def _dominates(self, a: Block, b: Block) -> bool:
        a_key = a.addr, a.idx
        while b is not None:
            if (b.addr, b.idx) == a_key:
                return True
            idom = self._doms.get(b)
            if idom is None or (idom.addr, idom.idx) == (b.addr, b.idx):
                return False
            b = idom
        return False

    def _def_src(self, vvar: VirtualVariable) -> Expression | None:
        defloc = self._defs.get(vvar.varid)
        if defloc is None:
            return None
        block, stmt_idx = defloc
        stmt = block.statements[stmt_idx]
        if (
            not isinstance(stmt, Assignment)
            or stmt.is_phi_assignment
            or not isinstance(stmt.dst, VirtualVariable)
            or stmt.dst.varid != vvar.varid
        ):
            return None
        return stmt.src

    @staticmethod
    def _scan(expr: Expression) -> set[int] | None:
        """
        The virtual variables a pure expression reads, or None if it is not pure.
        """
        scanner = _PureExprScanner()
        scanner.walk_expression(expr)
        return None if scanner.impure else scanner.vvars

    @staticmethod
    def _vvar_step(src: Expression) -> tuple[VirtualVariable, int] | None:
        """
        ``(v, c)`` if ``src`` is ``v``, ``v + c`` or ``v - c``.
        """
        if isinstance(src, VirtualVariable):
            return src, 0
        if not isinstance(src, BinaryOp) or src.op not in {"Add", "Sub"} or len(src.operands) != 2:
            return None
        op0, op1 = src.operands
        if isinstance(op0, VirtualVariable) and isinstance(op1, Const) and isinstance(op1.value, int):
            return op0, op1.value if src.op == "Add" else -op1.value
        if (
            src.op == "Add"
            and isinstance(op1, VirtualVariable)
            and isinstance(op0, Const)
            and isinstance(op0.value, int)
        ):
            return op1, op0.value
        return None

    def _single_instance(self, varid: int) -> bool:
        """
        Whether the variable is defined at most once per execution, so that its name stands for one value. Strict
        SSA would make names safe across loop iterations too, but the VM transforms rewire edges after SSA
        construction, so this does not rely on it.
        """
        defloc = self._defs.get(varid)
        return defloc is None or (defloc[0].addr, defloc[0].idx) not in self._cyclic

    def _affine_vvar(self, vvar: VirtualVariable, depth: int) -> tuple | None:
        # VM stack pointers are chains of hundreds of `v_n = v_(n-1) +- 8`; walk them iteratively
        chain: list[tuple[int, int]] = []
        cur = vvar
        base = None
        while cur.varid not in self._affine_cache:
            if not self._single_instance(cur.varid):
                self._affine_cache[cur.varid] = None
                break
            src = self._def_src(cur)
            if src is None or src.bits != cur.bits or len(chain) >= self.MAX_CHAIN_LENGTH:
                break
            step = self._vvar_step(src)
            if step is None or step[0].bits != cur.bits:
                if depth < self.MAX_CHAIN_DEPTH:
                    base = self._affine(src, depth + 1)
                break
            chain.append((cur.varid, step[1]))
            cur = step[0]
        if cur.varid in self._affine_cache:
            base = self._affine_cache[cur.varid]
        else:
            if base is None:
                base = ("vvar", cur.varid), 0
            self._affine_cache[cur.varid] = base
        if base is None:
            for varid, _ in chain:
                self._affine_cache[varid] = None
            return None
        mask = (1 << vvar.bits) - 1
        root, off = base
        for varid, delta in reversed(chain):
            off = (off + delta) & mask
            self._affine_cache[varid] = root, off
        return self._affine_cache[vvar.varid]

    def _affine(self, expr: Expression, depth: int) -> tuple | None:
        """
        ``(root, offset)`` for an expression whose value is ``root + offset``, or None.
        """
        mask = (1 << expr.bits) - 1
        if isinstance(expr, Const):
            return (None, expr.value & mask) if isinstance(expr.value, int) else None
        if isinstance(expr, StackBaseOffset):
            return "stack", expr.offset & mask
        if isinstance(expr, UnaryOp):
            if expr.op == "Reference" and isinstance(expr.operand, VirtualVariable) and expr.operand.was_stack:
                return "stack", expr.operand.stack_offset & mask
            return None
        if isinstance(expr, VirtualVariable):
            return self._affine_vvar(expr, depth)
        if isinstance(expr, BinaryOp) and expr.op in {"Add", "Sub"} and len(expr.operands) == 2:
            op0, op1 = expr.operands
            if op0.bits != expr.bits or op1.bits != expr.bits:
                return None
            a = self._affine(op0, depth + 1)
            b = self._affine(op1, depth + 1)
            if a is None or b is None:
                return None
            if expr.op == "Add":
                if b[0] is None:
                    return a[0], (a[1] + b[1]) & mask
                if a[0] is None:
                    return b[0], (a[1] + b[1]) & mask
                return None
            if b[0] is None:
                return a[0], (a[1] - b[1]) & mask
            if a[0] == b[0]:
                return None, (a[1] - b[1]) & mask
        return None


class EquivalenceAwareCodeMotionOptimization(OptimizationPass):
    """
    Runs EquivalentDefinitionSinker on the function graph.
    """

    ARCHES = None
    PLATFORMS = None
    NAME = "Merge equivalent definitions in sub-scopes"
    STAGE = OptimizationPassStage.AFTER_GLOBAL_SIMPLIFICATION
    DESCRIPTION = __doc__ or ""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.analyze()

    def _check(self):
        return True, None

    def _analyze(self, cache=None):
        entry = next((b for b in self._graph if (b.addr, b.idx) == self.entry_node_addr), None)
        if entry is None:
            return
        for old, new in EquivalentDefinitionSinker(self._graph, entry, self.manager).run().items():
            self._update_block(old, new)

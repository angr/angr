from __future__ import annotations

import logging
from collections import Counter

from angr.ailment import AILBlockViewer, Block
from angr.ailment.expression import (
    BinaryOp,
    Call,
    Const,
    Convert,
    Expression,
    Load,
    Phi,
    VEXCCallExpression,
    VirtualVariable,
)
from angr.ailment.statement import Assignment, ConditionalJump, Jump, Label, Return, SideEffectStatement, Store
from angr.analyses.decompiler.mixins import CFGTransformationMixin
from angr.analyses.decompiler.optimization_passes.optimization_pass import OptimizationPass, OptimizationPassStage
from angr.go.utils.names import call_target_name, normalize_go_func_name
from angr.utils.ail import find_call

l = logging.getLogger(__name__)

_HASH_COMPARES = frozenset({"CmpEQ", "CmpNE", "CmpLT", "CmpLE", "CmpGT", "CmpGE"})
# runtime calls whose first argument is a descriptor starting with an inline cache the caller probes first
_CACHED_DISPATCH = frozenset({"runtime.interfaceSwitch", "runtime.typeAssert"})


class GoTypeSwitchSimplifier(OptimizationPass, CFGTransformationMixin):
    """
    Strip the search machinery the compiler puts in front of a type switch.

    Concrete cases are found through a binary search over ``t.Hash`` whose leaves compare ``t`` against the case's
    type descriptor; the hash tests are redundant with those comparisons, so the tree collapses into a chain of
    descriptor comparisons. Interface cases (go1.22+) first probe an inline cache before calling
    ``runtime.interfaceSwitch``; the probe loop is dropped and the call always runs. Assertions and conversions to
    interface types probe the same kind of cache ahead of ``runtime.typeAssert``.
    """

    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.BEFORE_VARIABLE_RECOVERY
    NAME = "Simplify Go type switches"

    def __init__(self, func, manager, **kwargs):
        super().__init__(func, manager, **kwargs)
        CFGTransformationMixin.__init__(self, self._graph)
        self._ws = self.project.arch.bytes
        self.analyze()

    def _check(self):
        return self.project.is_go_binary, None

    def _analyze(self, cache=None):
        changed = self._remove_cache_probes()
        changed = self._flatten_hash_trees() or changed
        changed = self._thread_repeated_checks() or changed
        if changed:
            self._drop_dead_defs()
            self.out_graph = self._graph

    #
    # Interface-case cache probes
    #

    def _remove_cache_probes(self) -> bool:
        changed = False
        for slow in list(self._graph.nodes):
            call = self._cached_dispatch_call(slow)
            if call is None:
                continue
            descriptor = call.args[0].value
            probes = [
                block
                for block in self._graph.nodes
                if block is not slow and _ConstLoadFinder.found_in(block, descriptor)
            ]
            if not probes or any(self._has_side_effects(block) for block in probes):
                continue
            probe_set = set(probes)
            # the slow path may start with blocks of its own (spills ahead of the call) after the last probe
            start = slow
            while True:
                preds = list(self._graph.predecessors(start))
                if len(preds) != 1 or preds[0] in probe_set or self._graph.out_degree(preds[0]) != 1:
                    break
                start = preds[0]
            entries = [
                (pred, block)
                for block in probes
                for pred in self._graph.predecessors(block)
                if pred not in probe_set and pred is not slow and pred is not start
            ]
            if not entries:
                continue
            for pred, block in entries:
                self.replace_jump_target(pred, block.addr, block.idx, start.addr, start.idx)
            for block in probes:
                if block not in self._graph:
                    continue
                succs = list(self._graph.successors(block))
                self._graph.remove_node(block)
                self._block_by_addr_and_idx.pop((block.addr, block.idx), None)
                self._update_phi_variables_after_removing_block(self._graph, [], block)
                for succ in succs:
                    if succ in self._graph and self._graph.in_degree(succ) == 0 and succ is not start:
                        self._graph.remove_node(succ)
                        self._block_by_addr_and_idx.pop((succ.addr, succ.idx), None)
            self._collapse_single_source_phis()
            l.debug("Removed the interfaceSwitch cache probe (%d blocks) in %s", len(probes), self._func.name)
            changed = True
        return changed

    def _cached_dispatch_call(self, block: Block) -> Call | None:
        for stmt in block.statements:
            call = None
            if isinstance(stmt, Assignment) and isinstance(stmt.src, Call):
                call = stmt.src
            elif isinstance(stmt, SideEffectStatement) and isinstance(stmt.expr, Call):
                call = stmt.expr
            if call is None:
                continue
            name = call_target_name(self.project, call)
            if name is None or normalize_go_func_name(name) not in _CACHED_DISPATCH:
                continue
            args = list(call.args or [])
            if len(args) == 2 and isinstance(args[0], Const) and isinstance(args[0].value, int):
                return call
        return None

    @staticmethod
    def _has_side_effects(block: Block) -> bool:
        for stmt in block.statements:
            if isinstance(stmt, (Store, SideEffectStatement)):
                return True
            if isinstance(stmt, Assignment) and (isinstance(stmt.src, Call) or stmt.dst.was_stack):
                return True
            if find_call(stmt) is not None:
                return True
        return False

    def _collapse_single_source_phis(self) -> None:
        for block in self._graph.nodes:
            preds = {(pred.addr, pred.idx) for pred in self._graph.predecessors(block)}
            for i, stmt in enumerate(block.statements):
                if not (isinstance(stmt, Assignment) and isinstance(stmt.src, Phi)):
                    continue
                sources = [(src, vvar) for src, vvar in stmt.src.src_and_vvars if src in preds and vvar is not None]
                if len(sources) == 1:
                    block.statements[i] = Assignment(stmt.idx, stmt.dst, sources[0][1], **stmt.tags)
                elif len(sources) != len(stmt.src.src_and_vvars):
                    block.statements[i] = Assignment(
                        stmt.idx, stmt.dst, Phi(stmt.src.idx, stmt.src.bits, sources, **stmt.src.tags), **stmt.tags
                    )

    #
    # Hash search trees
    #

    def _flatten_hash_trees(self) -> bool:
        changed = False
        # outer trees first: an inner tree flattened first leaves the outer one looking at a jump block
        for root in sorted(self._graph.nodes, key=lambda b: (b.addr, b.idx or 0)):
            if root not in self._graph:
                continue
            hashed = self._hash_definition(root)
            if hashed is None:
                continue
            hash_vvar, type_word = hashed
            tree = self._collect_tree(root, hash_vvar, type_word)
            if tree is None:
                continue
            leaves, default, internal = tree
            if len(leaves) < 1:
                continue
            self._rewire_chain(root, leaves, default, internal)
            self._drop_unreachable()
            l.debug("Flattened a %d-case type switch hash tree in %s", len(leaves), self._func.name)
            changed = True
        return changed

    def _drop_unreachable(self) -> None:
        """Blocks the rewiring cut off (the duplicate default copy blocks) go, with their phi entries."""
        entry = self.entry_node_addr
        while True:
            dead = [b for b in self._graph.nodes if self._graph.in_degree(b) == 0 and (b.addr, b.idx) != entry]
            if not dead:
                return
            for block in dead:
                self._graph.remove_node(block)
                self._block_by_addr_and_idx.pop((block.addr, block.idx), None)
                self._update_phi_variables_after_removing_block(self._graph, [], block)

    def _hash_load(self, expr: Expression) -> VirtualVariable | None:
        """``t`` when ``expr`` is ``Load(t + 2*ws, 4)`` (``Type.Hash`` and ``itab.hash`` both sit there)."""
        if isinstance(expr, Convert):
            expr = expr.operand
        if not (isinstance(expr, Load) and expr.size == 4):
            return None
        addr = expr.addr
        if (
            isinstance(addr, BinaryOp)
            and addr.op == "Add"
            and isinstance(addr.operands[0], VirtualVariable)
            and isinstance(addr.operands[1], Const)
            and addr.operands[1].value == 2 * self._ws
        ):
            return addr.operands[0]
        return None

    def _hash_definition(self, block: Block) -> tuple[VirtualVariable | None, VirtualVariable] | None:
        """
        ``h = t.Hash`` in ``block`` when the block ends with a comparison on ``h``; or, when the hash is read inside
        the comparison itself, ``(None, t)``.
        """
        last = block.statements[-1] if block.statements else None
        if not isinstance(last, ConditionalJump):
            return None
        cond = last.condition
        if isinstance(cond, BinaryOp) and cond.op in _HASH_COMPARES:
            for a, b in ((cond.operands[0], cond.operands[1]), (cond.operands[1], cond.operands[0])):
                t = self._hash_load(a)
                if t is not None and isinstance(b, Const):
                    return None, t
        for stmt in block.statements:
            if not (isinstance(stmt, Assignment) and isinstance(stmt.dst, VirtualVariable)):
                continue
            src = stmt.src
            if isinstance(src, Convert) and src.from_bits == 32:
                src = src.operand
            if not (isinstance(src, Load) and src.size == 4):
                continue
            addr = src.addr
            if (
                isinstance(addr, BinaryOp)
                and addr.op == "Add"
                and isinstance(addr.operands[0], VirtualVariable)
                and isinstance(addr.operands[1], Const)
                and addr.operands[1].value == 2 * self._ws
                and self._hash_compare(last.condition, stmt.dst, addr.operands[0], block) is not None
            ):
                return stmt.dst, addr.operands[0]
        return None

    @staticmethod
    def _flag_ccall(cond: Expression, block: Block | None):
        """
        The ``arm64g_calculate_condition`` call behind ``cond`` (arm64 unsigned compares stay flag helpers), and the
        variable holding it when it is defined in ``block``.
        """
        if isinstance(cond, Convert):
            cond = cond.operand
        holder = None
        if isinstance(cond, VirtualVariable) and block is not None:
            holder = cond
            cond = next(
                (
                    st.src
                    for st in block.statements
                    if isinstance(st, Assignment)
                    and isinstance(st.dst, VirtualVariable)
                    and st.dst.varid == holder.varid
                ),
                None,
            )
        if isinstance(cond, VEXCCallExpression) and cond.callee == "arm64g_calculate_condition":
            return cond, holder
        return None, None

    def _hash_compare(
        self,
        cond: Expression,
        hash_vvar: VirtualVariable | None,
        type_word: VirtualVariable = None,
        block: Block | None = None,
    ):
        ccall, _ = self._flag_ccall(cond, block)
        if ccall is not None:
            # only which word is tested matters here: a recognized tree loses its hash tests
            operands = list(ccall.operands)
            return self._hash_operands(operands[1], operands[2], hash_vvar, type_word) if len(operands) == 4 else None
        if not (isinstance(cond, BinaryOp) and cond.op in _HASH_COMPARES):
            return None
        return self._hash_operands(cond.operands[0], cond.operands[1], hash_vvar, type_word)

    def _hash_operands(self, lhs, rhs, hash_vvar: VirtualVariable | None, type_word: VirtualVariable | None):
        """The constant ``lhs``/``rhs`` test the hash against, or None."""
        for a, b in ((lhs, rhs), (rhs, lhs)):
            if not isinstance(b, Const):
                continue
            x = a.operand if isinstance(a, Convert) else a
            if hash_vvar is not None and isinstance(x, VirtualVariable) and x.varid == hash_vvar.varid:
                return b.value
            if hash_vvar is None and type_word is not None:
                t = self._hash_load(a)
                if t is not None and t.varid == type_word.varid:
                    return b.value
        return None

    @staticmethod
    def _descriptor_compare(cond: Expression, type_word: VirtualVariable) -> int | None:
        if not (isinstance(cond, BinaryOp) and cond.op in ("CmpEQ", "CmpNE")):
            return None
        for a, b in ((cond.operands[0], cond.operands[1]), (cond.operands[1], cond.operands[0])):
            if isinstance(a, VirtualVariable) and a.varid == type_word.varid and isinstance(b, Const):
                return b.value
        return None

    @staticmethod
    def _fail_side(jump: ConditionalJump) -> tuple[Const, int | None]:
        """The target a failed descriptor test takes: the false one for ``==``, the true one for ``!=``."""
        if jump.condition.op == "CmpNE":
            return jump.true_target, jump.true_target_idx
        return jump.false_target, jump.false_target_idx

    def _block_at(self, target, idx=None) -> Block | None:
        """The block a jump target names, looking through blocks that only jump on."""
        if not isinstance(target, Const):
            return None
        block = self._block_by_addr_and_idx.get((target.value, idx))
        seen = set()
        while block is not None and block not in seen:
            seen.add(block)
            if not all(isinstance(st, (Label, Jump)) for st in block.statements):
                return block
            succs = list(self._graph.successors(block))
            if len(succs) != 1:
                return block
            block = succs[0]
        return block

    def _collect_tree(self, root: Block, hash_vvar: VirtualVariable, type_word: VirtualVariable):
        """
        In-order leaves (descriptor tests), the common default block and the internal hash-test blocks, or None
        when the shape is not a clean search tree.
        """
        leaves: list[Block] = []
        internal: list[Block] = []
        defaults: set[Block] = set()
        seen: set[Block] = set()

        def is_internal(block: Block) -> bool:
            last = block.statements[-1] if block.statements else None
            if (
                not isinstance(last, ConditionalJump)
                or self._hash_compare(last.condition, hash_vvar, type_word, block) is None
            ):
                return False
            _, flag = self._flag_ccall(last.condition, block)
            return all(
                isinstance(st, (Label, ConditionalJump))
                or (block is root and isinstance(st, Assignment))
                or (
                    flag is not None
                    and isinstance(st, Assignment)
                    and isinstance(st.dst, VirtualVariable)
                    and st.dst.varid == flag.varid
                )
                for st in block.statements
            )

        def is_leaf(block: Block) -> bool:
            last = block.statements[-1] if block.statements else None
            if not isinstance(last, ConditionalJump) or self._descriptor_compare(last.condition, type_word) is None:
                return False
            return all(isinstance(st, (Label, ConditionalJump)) for st in block.statements)

        def visit(block: Block) -> bool:
            if block in seen:
                return False
            seen.add(block)
            last = block.statements[-1]
            if is_internal(block):
                internal.append(block)
                for target, idx in (
                    (last.true_target, last.true_target_idx),
                    (last.false_target, last.false_target_idx),
                ):
                    succ = self._block_at(target, idx)
                    if succ is None:
                        return False
                    if is_internal(succ) or is_leaf(succ):
                        if not visit(succ):
                            return False
                    else:
                        defaults.add(succ)
                return True
            if is_leaf(block):
                leaves.append(block)
                succ = self._block_at(*self._fail_side(last))
                if succ is None:
                    return False
                if is_leaf(succ):
                    return visit(succ)
                defaults.add(succ)
                return True
            return False

        if not visit(root):
            return None
        if len(defaults) > 1:
            # phi elimination gives each failing branch its own copy block ahead of the join; identical copy
            # blocks that fall through to one target are one default
            keys = {self._default_key(d) for d in defaults}
            if len(keys) != 1 or None in keys:
                return None
            defaults = {min(defaults, key=lambda b: (b.addr, b.idx or 0))}
        if len(defaults) != 1 or not leaves:
            return None
        # every leaf and internal block must only be reachable from within the tree (the root aside)
        tree_set = set(leaves) | set(internal)
        for block in tree_set:
            if block is root:
                continue
            if any(pred not in tree_set for pred in self._graph.predecessors(block)):
                return None
        default = next(iter(defaults))
        return leaves, default, internal

    def _default_key(self, block: Block):
        """A key identifying a copy-only block by its assignments and its single successor, or None."""
        succs = list(self._graph.successors(block))
        stmts = block.statements
        if not succs and stmts and isinstance(stmts[-1], Return) and not stmts[-1].ret_exprs:
            # return duplication gives each failing branch its own copy of a bare return
            if all(isinstance(st, Label) for st in stmts[:-1]):
                return ("return",)
            return None
        if len(succs) != 1:
            return None
        body = []
        for stmt in block.statements:
            if isinstance(stmt, (Label, Jump)):
                continue
            if isinstance(stmt, Assignment) and not isinstance(stmt.src, (Call, Phi)) and find_call(stmt) is None:
                # the destinations are per-path SSA names feeding one phi; the sources are what matters
                body.append(str(stmt.src))
                continue
            return None
        return (tuple(body), succs[0].addr, succs[0].idx)

    def _rewire_chain(self, root: Block, leaves: list[Block], default: Block, internal: list[Block]) -> None:
        # the root keeps its statements and jumps straight to the first descriptor test
        first = leaves[0]
        last = root.statements[-1]
        root.statements[-1] = Jump(last.idx, Const(0, first.addr, self.project.arch.bits), first.idx, **last.tags)
        for succ in list(self._graph.successors(root)):
            self._graph.remove_edge(root, succ)
        self._graph.add_edge(root, first)
        # chain the descriptor tests: a failed test moves on to the next one, the last one to the default
        for i, leaf in enumerate(leaves):
            nxt = leaves[i + 1] if i + 1 < len(leaves) else default
            jump = leaf.statements[-1]
            fail, fail_idx = self._fail_side(jump)
            if self._block_at(fail, fail_idx) is nxt:
                continue
            # the edge to drop is the direct one (a jump-only block in between becomes unreachable)
            old = self._block_by_addr_and_idx.get((fail.value, fail_idx)) if isinstance(fail, Const) else None
            nxt_const = Const(0, nxt.addr, self.project.arch.bits)
            if jump.condition.op == "CmpNE":
                leaf.statements[-1] = ConditionalJump(
                    jump.idx,
                    jump.condition,
                    nxt_const,
                    jump.false_target,
                    true_target_idx=nxt.idx,
                    false_target_idx=jump.false_target_idx,
                    **jump.tags,
                )
            else:
                leaf.statements[-1] = ConditionalJump(
                    jump.idx,
                    jump.condition,
                    jump.true_target,
                    nxt_const,
                    true_target_idx=jump.true_target_idx,
                    false_target_idx=nxt.idx,
                    **jump.tags,
                )
            if old is not None and old in self._graph and self._graph.has_edge(leaf, old):
                self._graph.remove_edge(leaf, old)
            self._graph.add_edge(leaf, nxt)
        for block in internal:
            if block is root or block not in self._graph:
                continue
            self._graph.remove_node(block)
            self._block_by_addr_and_idx.pop((block.addr, block.idx), None)
            self._update_phi_variables_after_removing_block(self._graph, [], block)
        self._collapse_single_source_phis()

    #
    # Repeated descriptor checks
    #

    def _thread_repeated_checks(self) -> bool:
        """
        ``cmp t, T; je L; ...; L: jne fail`` (the comma-ok lowering reuses the flags) lifts into a second, identical
        check whose outcome the first one already decided on every path; each copy jumps straight to its outcome.
        """
        changed = False
        for block in sorted(self._graph.nodes, key=lambda b: (b.addr, b.idx or 0)):
            if block not in self._graph or not block.statements:
                continue
            jump = block.statements[-1]
            if not isinstance(jump, ConditionalJump) or not all(isinstance(st, Label) for st in block.statements[:-1]):
                continue
            key = self._check_key(jump.condition)
            if key is None:
                continue
            outcome = self._known_outcome(block, key)
            if outcome is None:
                continue
            keep, keep_idx, drop, drop_idx = (
                (jump.true_target, jump.true_target_idx, jump.false_target, jump.false_target_idx)
                if outcome
                else (jump.false_target, jump.false_target_idx, jump.true_target, jump.true_target_idx)
            )
            if not (isinstance(keep, Const) and isinstance(drop, Const)):
                continue
            keep_block = self._block_by_addr_and_idx.get((keep.value, keep_idx))
            drop_block = self._block_by_addr_and_idx.get((drop.value, drop_idx))
            if keep_block is None or drop_block is None or keep_block is drop_block:
                continue
            block.statements = [*block.statements[:-1], Jump(jump.idx, keep, keep_idx, **jump.tags)]
            if self._graph.has_edge(block, drop_block):
                self._graph.remove_edge(block, drop_block)
            self._drop_phi_source(drop_block, (block.addr, block.idx))
            changed = True
        if changed:
            self._drop_unreachable()
            self._collapse_single_source_phis()
        return changed

    def _check_key(self, cond: Expression) -> tuple[int, int, bool] | None:
        """(varid, descriptor, equal?) for ``v ==/!= descriptor``."""
        if not (isinstance(cond, BinaryOp) and cond.op in ("CmpEQ", "CmpNE")):
            return None
        for a, b in ((cond.operands[0], cond.operands[1]), (cond.operands[1], cond.operands[0])):
            if isinstance(a, VirtualVariable) and isinstance(b, Const) and isinstance(b.value, int):
                go_types = self.kb.go_types
                if go_types.itab_at(b.value) is None and go_types.name_at(b.value) is None:
                    return None
                return a.varid, b.value, cond.op == "CmpEQ"
        return None

    def _known_outcome(self, block: Block, key: tuple[int, int, bool]) -> bool | None:
        """Whether the check ``key`` in ``block`` holds on its only path from an identical earlier check."""
        cur = block
        seen = {block}
        while True:
            preds = list(self._graph.predecessors(cur))
            if len(preds) != 1 or preds[0] in seen:
                return None
            pred = preds[0]
            seen.add(pred)
            last = pred.statements[-1] if pred.statements else None
            if isinstance(last, ConditionalJump):
                other = self._check_key(last.condition)
                if other is None or other[:2] != key[:2]:
                    return None
                on_true = self._block_at_target(last.true_target, last.true_target_idx) is cur
                on_false = self._block_at_target(last.false_target, last.false_target_idx) is cur
                if on_true == on_false:
                    return None
                # the earlier check's value on this path, flipped when the two checks test opposite relations
                return on_true == (other[2] == key[2])
            cur = pred

    def _block_at_target(self, target, idx) -> Block | None:
        return self._block_by_addr_and_idx.get((target.value, idx)) if isinstance(target, Const) else None

    @staticmethod
    def _drop_phi_source(block: Block, src: tuple) -> None:
        stmts = list(block.statements)
        for i, stmt in enumerate(stmts):
            if isinstance(stmt, Assignment) and isinstance(stmt.src, Phi):
                entries = [(s, v) for s, v in stmt.src.src_and_vvars if s != src]
                if len(entries) != len(stmt.src.src_and_vvars):
                    stmts[i] = Assignment(
                        stmt.idx, stmt.dst, Phi(stmt.src.idx, stmt.src.bits, entries, **stmt.src.tags), **stmt.tags
                    )
        block.statements = stmts

    #
    # Cleanup
    #

    def _drop_dead_defs(self) -> None:
        while True:
            counter = _VVarUseCounter()
            for block in self._graph.nodes:
                counter.walk(block)
            dropped = False
            for block in self._graph.nodes:
                kept = []
                for stmt in block.statements:
                    if (
                        isinstance(stmt, Assignment)
                        and isinstance(stmt.dst, VirtualVariable)
                        and not stmt.dst.was_stack
                        and not isinstance(stmt.src, Call)
                        and counter.counts[stmt.dst.varid] <= 1
                    ):
                        dropped = True
                        continue
                    kept.append(stmt)
                block.statements = kept
            if not dropped:
                return


class _ConstLoadFinder(AILBlockViewer):
    """Whether a block loads from a given constant address."""

    def __init__(self, addr: int):
        super().__init__()
        self._addr = addr
        self.found = False

    def _handle_Load(self, expr_idx, expr: Load, stmt_idx, stmt, block):
        if isinstance(expr.addr, Const) and expr.addr.value == self._addr:
            self.found = True
        super()._handle_Load(expr_idx, expr, stmt_idx, stmt, block)

    @classmethod
    def found_in(cls, block: Block, addr: int) -> bool:
        finder = cls(addr)
        finder.walk(block)
        return finder.found


class _VVarUseCounter(AILBlockViewer):
    def __init__(self):
        super().__init__()
        self.counts: Counter = Counter()

    def _handle_VirtualVariable(self, expr_idx, expr: VirtualVariable, stmt_idx, stmt, block):
        self.counts[expr.varid] += 1

    def _handle_Phi(self, expr_idx, expr: Phi, stmt_idx, stmt, block):
        for _, vvar in expr.src_and_vvars:
            if vvar is not None:
                self.counts[vvar.varid] += 1

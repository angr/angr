from __future__ import annotations

import contextlib
import logging
from collections import OrderedDict
from typing import cast

from angr.ailment import AILBlockRewriter, AILBlockViewer
from angr.ailment.block import Block
from angr.ailment.expression import ITE, BinaryOp, Call, Const, Expression, Load, Phi, Struct, VirtualVariable
from angr.ailment.statement import Assignment, ConditionalJump, Jump, Label, SideEffectStatement, Statement, Store
from angr.analyses.decompiler.mixins.cfg_transformation_mixin import CFGTransformationMixin
from angr.analyses.decompiler.optimization_passes.optimization_pass import OptimizationPass, OptimizationPassStage
from angr.analyses.decompiler.variable_map import variable_map_of
from angr.go.sim_type import GoSimTypeFunction
from angr.go.utils.graph import is_jump_only

from .builtin_rewriter import _VVarCounter
from .stack_inits import StackClearFolder

l = logging.getLogger(__name__)

_LIST = "container/list.List"
_ELEMENT = "container/list.Element"
# e.prev = at; e.next = at.next; at.next = e; e.next.prev = e; e.list = l; l.len++ (plus e.Value = v)
_PUSH_ROLES = frozenset({"prev", "next", "at.next", "next.prev", "list", "len"})


def _vvar_ids(expr: Expression) -> set[int]:
    ids = set()

    class _Collect(AILBlockViewer):
        def _handle_VirtualVariable(self, expr_idx, expr, stmt_idx, stmt, block):
            ids.add(expr.varid)

    _Collect().walk_expression(expr)
    return ids


class GoStdlibFolder(OptimizationPass, CFGTransformationMixin):
    """
    Fold inlined standard-library bodies back into the calls they came from.

    container/list: ``new(List)`` plus the ``Init`` stores is ``list.New()``; ``lazyInit`` (``if l.root.next == nil
    { l.Init() }``) followed by ``new(Element)`` and the ``insert`` stores is ``l.PushBack(v)``/``l.PushFront(v)``;
    ``l.len == 0 ? nil : l.root.next`` is ``l.Front()`` (``root.prev``: ``Back()``). A fold needs the whole body.
    """

    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.BEFORE_VARIABLE_RECOVERY
    NAME = "Fold inlined Go standard-library functions"

    def __init__(self, func, manager, **kwargs):
        super().__init__(func, manager, **kwargs)
        CFGTransformationMixin.__init__(self, self._graph)
        self._ws = self.project.arch.bytes
        self._defs: dict[int, Expression] = {}
        self.analyze()

    def _check(self):
        return self.project.is_go_binary, None

    def _analyze(self, cache=None):
        self._index()
        changed = self._fold_list_new()
        changed = self._fold_list_push() or changed
        changed = self._fold_element_steps() or changed
        if StackClearFolder(self).run():
            changed = True
            self._index()
        rewriter = _ListAccessorRewriter(self)
        for block in list(self._graph.nodes):
            rewriter.walk(block)
        if changed or rewriter.changed:
            self._drop_unused_results()
            self.out_graph = self._graph

    #
    # Helpers
    #

    def _index(self) -> None:
        self._defs = {}
        for block in self._graph.nodes:
            for stmt in block.statements:
                if isinstance(stmt, Assignment) and isinstance(stmt.dst, VirtualVariable):
                    self._defs[stmt.dst.varid] = stmt.src

    def _root(self, expr: Expression) -> Expression:
        """Follow variable copies to the first value that is not a copy."""
        seen = set()
        while isinstance(expr, VirtualVariable) and expr.varid not in seen:
            seen.add(expr.varid)
            src = self._defs.get(expr.varid)
            if not isinstance(src, VirtualVariable):
                break
            expr = src
        return expr

    def _same(self, a: Expression, b: Expression) -> bool:
        a, b = self._root(a), self._root(b)
        if isinstance(a, VirtualVariable) and isinstance(b, VirtualVariable):
            return a.varid == b.varid
        return a.likes(b)

    @staticmethod
    def _addr_off(addr: Expression) -> tuple[Expression, int]:
        if isinstance(addr, BinaryOp) and addr.op == "Add" and isinstance(addr.operands[1], Const):
            return addr.operands[0], addr.operands[1].value_int
        return addr, 0

    def _is_field(self, addr: Expression, base: Expression, off: int) -> bool:
        b, o = self._addr_off(addr)
        return o == off and self._same(b, base)

    def _is_load(self, expr: Expression, base: Expression, off: int) -> bool:
        return isinstance(expr, Load) and expr.size == self._ws and self._is_field(expr.addr, base, off)

    @staticmethod
    def _is_new(expr: Expression, type_name: str) -> bool:
        return (
            isinstance(expr, Call)
            and expr.target == "new"
            and list(expr.tags.get("go_type_args", ()) or ()) == [type_name]
        )

    def _call(self, idx: int, name: str, args: list, result: str | None, tags) -> Call:
        tags = {k: v for k, v in tags.items() if not k.startswith("go_")}
        extra = {"go_result_type": result} if result is not None else {}
        call = Call(idx, name, args, bits=self._ws * 8 if result else None, **tags, **extra)
        proto = None
        with contextlib.suppress(Exception):
            proto = self.kb.go_signatures.prototype(name)
        if proto is None:
            with contextlib.suppress(Exception):
                argtys = [self.kb.go_signatures.type("*" + _LIST)]
                if len(args) == 2:
                    argtys.append(self.kb.go_signatures.type("any"))
                elif not args:
                    argtys = []
                proto = GoSimTypeFunction(argtys, self.kb.go_signatures.type(result) if result else None)
        if proto is not None:
            variable_map_of(self.manager).set_prototype(call, proto.with_arch(self.project.arch))
        return call

    def _chain_from(self, block: Block, start: int):
        """(block, index, stmt) along ``block`` from ``start`` and its straight-line single-entry successors."""
        seen = set()
        while block not in seen:
            seen.add(block)
            for i in range(start, len(block.statements)):
                yield block, i, block.statements[i]
            succs = list(self._graph.successors(block))
            if len(succs) != 1 or self._graph.in_degree(succs[0]) != 1:
                return
            block, start = succs[0], 0

    @staticmethod
    def _is_inert(stmt: Statement) -> bool:
        """Statements the compiler may interleave with an inlined body: labels, jumps, register/stack copies."""
        if isinstance(stmt, (Label, Jump)):
            return True
        return (
            isinstance(stmt, Assignment)
            and isinstance(stmt.dst, VirtualVariable)
            and isinstance(stmt.src, (VirtualVariable, Const))
        )

    def _init_role(self, st: Statement, lst: Expression) -> str | None:
        """The role of ``st`` in ``l.root.next = &l.root; l.root.prev = &l.root; l.len = 0``."""
        if not isinstance(st, Store) or st.size != self._ws:
            return None
        if self._is_field(st.addr, lst, 0) and self._same(st.data, lst):
            return "next"
        if self._is_field(st.addr, lst, self._ws) and self._same(st.data, lst):
            return "prev"
        if self._is_field(st.addr, lst, 5 * self._ws) and isinstance(st.data, Const) and st.data.value == 0:
            return "len"
        return None

    def _is_init(self, stores: list, lst: Expression) -> bool:
        roles = [self._init_role(st, lst) for st in stores]
        return len(set(roles)) == len(roles) == 3 and None not in roles

    #
    # list.New
    #

    def _fold_list_new(self) -> bool:
        changed = False
        for block in list(self._graph.nodes):
            for i, stmt in enumerate(block.statements):
                if not (
                    isinstance(stmt, Assignment)
                    and isinstance(stmt.dst, VirtualVariable)
                    and self._is_new(stmt.src, _LIST)
                ):
                    continue
                lst = stmt.dst
                matched: dict[str, tuple[Block, Statement]] = {}
                for b, _, st in self._chain_from(block, i + 1):
                    if len(matched) == 3:
                        break
                    role = self._init_role(st, lst)
                    if role is not None and role not in matched:
                        matched[role] = (b, st)
                    elif not self._is_inert(st):
                        break
                if len(matched) != 3:
                    continue
                new_call = self._call(stmt.src.idx, "container/list.New", [], "*" + _LIST, stmt.src.tags)
                block.statements[i] = Assignment(stmt.idx, stmt.dst, new_call, **stmt.tags)
                self._remove_stmts(list(matched.values()))
                changed = True
        return changed

    @staticmethod
    def _remove_stmts(matched: list[tuple[Block, Statement]]) -> None:
        # Rust-backed wrappers are fresh objects: match statements by atom index
        by_block: dict[Block, set[int]] = {}
        for b, st in matched:
            by_block.setdefault(b, set()).add(st.idx)
        for b, idxs in by_block.items():
            b.statements = [st for st in b.statements if st.idx not in idxs]

    #
    # PushBack / PushFront
    #

    def _fold_list_push(self) -> bool:
        changed = False
        for block in list(self._graph.nodes):
            if block not in self._graph:
                continue
            for i, stmt in enumerate(block.statements):
                if (
                    isinstance(stmt, Assignment)
                    and isinstance(stmt.dst, VirtualVariable)
                    and self._is_new(stmt.src, _ELEMENT)
                    and self._fold_one_push(block, i, stmt)
                ):
                    changed = True
                    self._index()
                    break
        return changed

    def _fold_one_push(self, block: Block, i: int, alloc: Assignment) -> bool:
        ws = self._ws
        elem = alloc.dst
        # the insert stores, keyed by role
        roles: dict[str, tuple[Block, Statement]] = {}
        at = lst = None
        value_tab = value_data = value = None
        window_defs: set[int] = set()  # variables defined by copies interleaved with the stores
        for b, _, st in self._chain_from(block, i + 1):
            if roles.keys() >= _PUSH_ROLES and ("value" in roles or {"tab", "data"} <= roles.keys()):
                break
            if not isinstance(st, Store):
                if self._is_inert(st):
                    if isinstance(st, Assignment):
                        window_defs.add(cast(VirtualVariable, st.dst).varid)  # inert copies define vvars
                    continue
                break
            base, off = self._addr_off(st.addr)
            role = None
            if self._same(base, elem) and st.size == 2 * ws and off == 3 * ws and "tab" not in roles:
                role, value = "value", st.data
            elif self._same(base, elem) and st.size == ws:
                if off == 3 * ws and "value" not in roles:
                    role, value_tab = "tab", st.data
                elif off == 4 * ws:
                    role, value_data = "data", st.data
                elif off == ws:
                    role, at = "prev", st.data
                elif off == 0 and at is not None and self._is_load(st.data, at, 0):
                    role = "next"
                elif off == 2 * ws:
                    role, lst = "list", st.data
            elif st.size == ws and at is not None and off == 0 and self._same(base, at) and self._same(st.data, elem):
                role = "at.next"
            elif (
                st.size == ws
                and off == ws
                and self._is_load(base, elem, 0)
                and self._same(st.data, elem)
                and "next" in roles
            ):
                role = "next.prev"
            elif (
                lst is not None
                and st.size == ws
                and off == 5 * ws
                and self._same(base, lst)
                and isinstance(st.data, BinaryOp)
                and st.data.op == "Add"
                and self._is_load(st.data.operands[0], lst, 5 * ws)
                and isinstance(st.data.operands[1], Const)
                and st.data.operands[1].value == 1
            ):
                role = "len"
            if role is None or role in roles:
                break
            roles[role] = (b, st)
        if not (roles.keys() >= _PUSH_ROLES and ("value" in roles or {"tab", "data"} <= roles.keys())):
            return False
        if at is None or lst is None:
            return False
        if value is None:
            value = Struct(
                self.manager.next_atom(),
                "any",
                OrderedDict([(0, value_tab), (ws, value_data)]),
                OrderedDict([("tab", 0), ("data", ws)]),
                2 * ws * 8,
                **cast(Expression, value_tab).tags,  # the tab and data roles were both found
            )
        # the call takes the store's place at the allocation: its operands must already be defined there
        if _vvar_ids(value) & window_defs:
            return False
        # at is l.root.prev (PushBack) or &l.root (PushFront)
        if self._same(at, lst):
            name = "container/list.(*List).PushFront"
            at_def = None
        else:
            at_root = self._root(at)
            at_src = self._defs.get(at.varid) if isinstance(at, VirtualVariable) else None
            if not (isinstance(at_src, Load) and self._is_load(at_src, lst, ws)) and not self._is_load(
                at_root, lst, ws
            ):
                return False
            name = "container/list.(*List).PushBack"
            at_def = at
        lazy = self._lazy_init(block, i, lst)
        if lazy is None:
            return False
        cond_block, init_path, lst = lazy
        call = self._call(alloc.src.idx, name, [lst, value], "*" + _ELEMENT, alloc.src.tags)
        block.statements[i] = Assignment(alloc.idx, alloc.dst, call, **alloc.tags)
        self._remove_stmts(list(roles.values()))
        if at_def is not None:
            # at = l.root.prev is read by the call itself now
            self._drop_unused(cast(VirtualVariable, at_def))  # the vvar holding l.root.prev
        # lazyInit: the check always takes the path that skips Init
        first = init_path[0]
        self.remove_jump_target(cond_block, first.addr, first.idx)
        for b in init_path:
            self._graph.remove_node(b)
            self._block_by_addr_and_idx.pop((b.addr, b.idx), None)
            self._update_phi_variables_after_removing_block(self._graph, [], b)
        return True

    def _lazy_init(self, block: Block, i: int, lst: Expression) -> tuple[Block, list[Block], Expression] | None:
        """
        ``if l.root.next == nil { l.Init() }`` right before the insert: the block ending in the check and the blocks
        of the Init path (trampolines included), which rejoins the other path at ``block``.
        """
        # only l.root.prev may be read between the join and the allocation
        for st in block.statements[:i]:
            if self._is_inert(st) or (isinstance(st, Assignment) and self._is_load(st.src, lst, self._ws)):
                continue
            return None
        preds = list(self._graph.predecessors(block))
        if len(preds) != 2:
            return None
        cond_block = None
        init_path = None
        for p in preds:
            path = self._back_through_jumps(p)
            if path is None:
                return None
            head = path[-1]
            if head.statements and isinstance(head.statements[-1], ConditionalJump):
                if cond_block is not None and cond_block is not head:
                    return None
                cond_block = head
                continue
            # the Init block, entered only from the check
            stores = [st for st in head.statements if not isinstance(st, (Label, Jump))]
            if not self._is_init(stores, lst) or self._graph.in_degree(head) != 1:
                return None
            before = self._back_through_jumps(next(iter(self._graph.predecessors(head))))
            if before is None:
                return None
            check = before[-1]
            if not (check.statements and isinstance(check.statements[-1], ConditionalJump)):
                return None
            if cond_block is not None and cond_block is not check:
                return None
            cond_block = check
            init_path = list(reversed(before[:-1])) + list(reversed(path))
        if cond_block is None or init_path is None:
            return None
        cond = cast(ConditionalJump, cond_block.statements[-1]).condition
        if not (
            isinstance(cond, BinaryOp)
            and cond.op == "CmpEQ"
            and self._is_load(cond.operands[0], lst, 0)
            and isinstance(cond.operands[1], Const)
            and cond.operands[1].value == 0
        ):
            return None
        # the list as the check reads it, defined before the insert
        return cond_block, init_path, self._addr_off(cond.operands[0].addr)[0]

    def _back_through_jumps(self, block: Block) -> list[Block] | None:
        """``block`` and its predecessors back through single-entry trampolines, ending at a non-trampoline."""
        path = [block]
        while is_jump_only(path[-1]):
            preds = list(self._graph.predecessors(path[-1]))
            if len(preds) != 1 or preds[0] in path:
                return None
            path.append(preds[0])
        return path

    def _drop_unused(self, vvar: VirtualVariable) -> None:
        counter = _VVarCounter()
        for b in self._graph.nodes:
            counter.walk(b)
        if counter.counts[vvar.varid] > 1:
            return
        for b in self._graph.nodes:
            for k, st in enumerate(b.statements):
                if isinstance(st, Assignment) and isinstance(st.dst, VirtualVariable) and st.dst.varid == vvar.varid:
                    if isinstance(st.src, (Load, VirtualVariable, Const)):
                        b.statements = b.statements[:k] + b.statements[k + 1 :]
                    return

    def _use_counts(self):
        counter = _VVarCounter()
        for b in self._graph.nodes:
            counter.walk(b)
        return counter.counts

    def _drop_unused_results(self) -> None:
        """``e = l.PushBack(v)`` with ``e`` never read is the call statement."""
        counts = self._use_counts()
        for b in self._graph.nodes:
            for k, st in enumerate(b.statements):
                if (
                    isinstance(st, Assignment)
                    and isinstance(st.dst, VirtualVariable)
                    and not st.dst.was_stack
                    and isinstance(st.src, Call)
                    and isinstance(st.src.target, str)
                    and st.src.target.startswith("container/list.")
                    and counts[st.dst.varid] <= 1
                ):
                    tags = {**st.tags, **{t: v for t, v in st.src.tags.items() if t.startswith("go_")}}
                    b.statements[k] = SideEffectStatement(st.idx, st.src, **tags)

    #
    # Element.Next / Element.Prev
    #

    def _fold_element_steps(self) -> bool:
        changed = False
        for block in list(self._graph.nodes):
            if block in self._graph and self._fold_one_step(block):
                changed = True
                self._index()
        return changed

    def _nil_list_check(self, block: Block) -> tuple[Expression, Block, Block] | None:
        """``if e.list == nil goto N else goto Y`` -> (e, N, Y)."""
        if not block.statements or not isinstance(block.statements[-1], ConditionalJump):
            return None
        jump = block.statements[-1]
        cond = jump.condition
        if not (isinstance(cond, BinaryOp) and cond.op in ("CmpEQ", "CmpNE")):
            return None
        lhs, rhs = cond.operands
        if not (isinstance(rhs, Const) and rhs.value == 0 and isinstance(lhs, Load) and lhs.size == self._ws):
            return None
        e, off = self._addr_off(lhs.addr)
        if off != 2 * self._ws:
            return None
        targets = self._targets(block, jump)
        if targets is None:
            return None
        nil_t, other = targets if cond.op == "CmpEQ" else targets[::-1]
        return e, nil_t, other

    def _targets(self, block: Block, jump: ConditionalJump) -> tuple[Block, Block] | None:
        if not (isinstance(jump.true_target, Const) and isinstance(jump.false_target, Const)):
            return None
        t = self._block_by_addr_and_idx.get((jump.true_target.value_int, jump.true_target_idx))
        f = self._block_by_addr_and_idx.get((jump.false_target.value_int, jump.false_target_idx))
        if t is None or f is None or t is f or {t, f} != set(self._graph.successors(block)):
            return None
        return t, f

    def _fold_one_step(self, x: Block) -> bool:
        """
        ``if p := e.next; e.list != nil && p != &e.list.root { r = p } else { r = nil }`` -> ``r = e.Next()``
        (``e.prev``: ``e.Prev()``): the check block, the second test, the nil arm and the phi at the join.
        """
        first = self._nil_list_check(x)
        if first is None:
            return False
        e, z, y = first
        if self._graph.in_degree(y) != 1:
            return False
        body = [st for st in y.statements if not isinstance(st, Label)]
        if len(body) != 2:
            return False
        p_def, jump = body
        if not isinstance(p_def, Assignment) or not isinstance(jump, ConditionalJump):
            return False
        p = p_def.dst
        if not (isinstance(p, VirtualVariable) and isinstance(p_def.src, Load) and p_def.src.size == self._ws):
            return False
        if self._is_field(p_def.src.addr, e, 0):
            name = "container/list.(*Element).Next"
        elif self._is_field(p_def.src.addr, e, self._ws):
            name = "container/list.(*Element).Prev"
        else:
            return False
        cond = jump.condition
        if not (isinstance(cond, BinaryOp) and cond.op in ("CmpEQ", "CmpNE")):
            return False
        a, b = cond.operands
        if not self._is_load(a, e, 2 * self._ws):
            a, b = b, a
        # &e.list.root is e.list; the propagator may have replaced p in the test with its load
        p_in_test = isinstance(b, VirtualVariable) and b.varid == p.varid
        if not (self._is_load(a, e, 2 * self._ws) and (p_in_test or b.likes(p_def.src))):
            return False
        targets = self._targets(y, jump)
        if targets is None:
            return False
        eq_t, join = targets if cond.op == "CmpEQ" else targets[::-1]
        if eq_t is not z:
            return False
        # the nil arm: r_z = 0, then the join
        z_body = [st for st in z.statements if not isinstance(st, (Label, Jump))]
        if (
            len(z_body) != 1
            or not isinstance(z_body[0], Assignment)
            or not isinstance(z_body[0].dst, VirtualVariable)
            or not isinstance(z_body[0].src, Const)
            or z_body[0].src.value != 0
            or set(self._graph.successors(z)) != {join}
            or set(self._graph.predecessors(z)) != {x, y}
        ):
            return False
        r_z = z_body[0].dst
        if set(self._graph.predecessors(join)) != {y, z}:
            return False
        phis = [
            (k, st) for k, st in enumerate(join.statements) if isinstance(st, Assignment) and isinstance(st.src, Phi)
        ]
        if len(phis) != 1:
            return False
        phi_k, phi = phis[0]
        srcs = {src: v.varid if v is not None else None for src, v in cast(Phi, phi.src).src_and_vvars}
        if srcs != {(y.addr, y.idx): p.varid, (z.addr, z.idx): r_z.varid}:
            return False
        counts = self._use_counts()
        # p: def, test (unless propagated), phi; r_z: def, phi
        if counts[p.varid] != (3 if p_in_test else 2) or counts[r_z.varid] != 2:
            return False
        call = self._call(p_def.src.idx, name, [e], "*" + _ELEMENT, p_def.tags)
        last = x.statements[-1]
        x.statements = [
            *x.statements[:-1],
            Assignment(phi.idx, phi.dst, call, **phi.tags),
            Jump(last.idx, Const(self.manager.next_atom(), join.addr, self.project.arch.bits), join.idx, **last.tags),
        ]
        join.statements = join.statements[:phi_k] + join.statements[phi_k + 1 :]
        for b in (y, z):
            self._graph.remove_node(b)
            self._block_by_addr_and_idx.pop((b.addr, b.idx), None)
        self._graph.add_edge(x, join)
        return True

    #
    # Front / Back
    #

    def rewrite_ite(self, expr: ITE) -> Expression | None:
        """``l.len == 0 ? nil : l.root.next`` -> ``l.Front()`` (``root.prev``: ``l.Back()``)."""
        cond, t, f = expr.cond, expr.iftrue, expr.iffalse
        if not (isinstance(cond, BinaryOp) and cond.op in ("CmpEQ", "CmpNE")):
            return None
        if cond.op == "CmpNE":
            t, f = f, t
        lhs, rhs = cond.operands
        if not (isinstance(rhs, Const) and rhs.value == 0 and isinstance(t, Const) and t.value == 0):
            return None
        if not (isinstance(lhs, Load) and lhs.size == self._ws):
            return None
        lst, off = self._addr_off(lhs.addr)
        if off != 5 * self._ws or not isinstance(f, Load):
            return None
        if self._is_load(f, lst, 0):
            name = "container/list.(*List).Front"
        elif self._is_load(f, lst, self._ws):
            name = "container/list.(*List).Back"
        else:
            return None
        if not self._may_be_list(lst):
            return None
        return self._call(expr.idx, name, [lst], "*" + _ELEMENT, expr.tags)

    def _may_be_list(self, ptr: Expression) -> bool:
        """No evidence ``ptr`` is anything but a ``*list.List``: a typed allocation of another type rules it out."""
        root = self._root(ptr)
        if isinstance(root, Call) and root.target == "new":
            return self._is_new(root, _LIST)
        if isinstance(root, VirtualVariable):
            src = self._defs.get(root.varid)
            if isinstance(src, Call):
                if src.target == "new":
                    return self._is_new(src, _LIST)
                if src.target == "container/list.New":
                    return True
        return True


class _ListAccessorRewriter(AILBlockRewriter):
    def __init__(self, pass_: GoStdlibFolder):
        super().__init__()
        self._pass = pass_
        self.changed = False

    def _handle_ITE(self, expr_idx, expr: ITE, stmt_idx, stmt, block):
        new_expr = super()._handle_ITE(expr_idx, expr, stmt_idx, stmt, block)
        if isinstance(new_expr, ITE):
            new = self._pass.rewrite_ite(new_expr)
            if new is not None:
                self.changed = True
                return new
        return new_expr

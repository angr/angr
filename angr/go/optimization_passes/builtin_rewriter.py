from __future__ import annotations

import contextlib
import logging
from collections import Counter, OrderedDict

from angr.ailment import AILBlockRewriter, AILBlockViewer
from angr.ailment.block import Block
from angr.ailment.expression import (
    ITE,
    BinaryOp,
    Call,
    Const,
    Convert,
    Expression,
    Load,
    Phi,
    StringLiteral,
    Struct,
    UnaryOp,
    VirtualVariable,
)
from angr.ailment.expression import VirtualVariableCategory as VVC
from angr.ailment.statement import (
    Assignment,
    ConditionalJump,
    Jump,
    Label,
    Return,
    SideEffectStatement,
    Statement,
    Store,
)
from angr.analyses.decompiler.mixins.cfg_transformation_mixin import CFGTransformationMixin
from angr.analyses.decompiler.optimization_passes.optimization_pass import OptimizationPass, OptimizationPassStage
from angr.analyses.decompiler.variable_map import variable_map_of
from angr.go.sim_type import GoSimTypeFunction
from angr.go.utils.graph import is_jump_only
from angr.go.utils.names import call_target_name
from angr.go.utils.types import go_type_at, go_type_name_at
from angr.utils.ail import find_call
from angr.utils.go_runtime import normalize_go_func_name

l = logging.getLogger(__name__)

_COMPARISONS = frozenset({"CmpEQ", "CmpNE", "CmpLT", "CmpLE", "CmpGT", "CmpGE"})
_STRING_BITS = 128
_SLICE_BITS = 192
_PTR, _LEN, _CAP = 0, 8, 16


def _addr_and_offset(addr: Expression) -> tuple[Expression | None, int]:
    """``base + k`` -> (base, k); ``Const c`` -> (None, c)."""
    if isinstance(addr, Const):
        return None, addr.value_int
    if isinstance(addr, BinaryOp) and addr.op == "Add":
        lhs, rhs = addr.operands
        if isinstance(rhs, Const):
            return lhs, rhs.value_int
        if isinstance(lhs, Const):
            return rhs, lhs.value_int
    return addr, 0


def _strip_converts(expr: Expression) -> Expression:
    while isinstance(expr, Convert):
        expr = expr.operand
    return expr


def _looks_like_text(data: str) -> bool:
    """Printable text (a format string, a message), not a run of bytes that happens to decode."""
    if not data:
        return False
    printable = sum(1 for ch in data if ch.isprintable() or ch in "\n\t\r")
    return printable >= 0.9 * len(data)


def _const(expr: Expression) -> int | None:
    return expr.value_int if isinstance(expr, Const) else None


def _has_node(expr: Expression, pred) -> bool:
    if pred(expr):
        return True
    if isinstance(expr, (BinaryOp, UnaryOp)):
        return any(_has_node(op, pred) for op in expr.operands)
    if isinstance(expr, Convert):
        return _has_node(expr.operand, pred)
    return False


class _Base:
    """
    Where a string/slice value lives: a combo-register variable, memory at ``addr + off``, or ``words`` (a header
    the compiler keeps in separate scalars; only a call that takes the header apart proves they belong together).
    """

    __slots__ = ("addr", "combo", "conv", "name", "off", "words")

    def __init__(
        self,
        combo: VirtualVariable | None = None,
        addr: Expression | None = None,
        off: int = 0,
        words: tuple[Expression, ...] | None = None,
        name: str | None = None,
    ):
        self.combo = combo
        self.addr = addr
        self.off = off
        self.words = words
        self.name = name
        self.conv: str | None = None  # a conversion applied to the value ([]byte of a string)

    def same(self, other: _Base) -> bool:
        if self.combo is not None:
            return other.combo is not None and other.combo.varid == self.combo.varid
        if self.addr is not None:
            return other.addr is not None and self.off == other.off and self.addr.likes(other.addr)
        if self.words is not None:
            return (
                other.words is not None
                and len(self.words) == len(other.words)
                and all(a.likes(b) for a, b in zip(self.words, other.words))
            )
        return False

    def address(self, manager, arch) -> Expression | None:
        if self.addr is None:
            return None
        if not self.off:
            return self.addr
        return BinaryOp(manager.next_atom(), "Add", [self.addr, Const(manager.next_atom(), self.off, arch.bits)], False)

    def value(self, manager, arch, size: int | None, tags, name: str | None = None) -> Expression | None:
        if self.conv is not None:
            inner = _Base(combo=self.combo, addr=self.addr, off=self.off).value(manager, arch, _STRING_BITS // 8, tags)
            if inner is None:
                return None
            return Call(manager.next_atom(), self.conv, [inner], bits=_SLICE_BITS, go_result_type="[]uint8", **tags)
        if self.combo is not None:
            return self.combo if size is None or self.combo.size == size else None
        if self.addr is not None:
            if size is None:
                return None
            return Load(manager.next_atom(), self.address(manager, arch), size, arch.memory_endness, **tags)
        if self.words is not None:
            ws = arch.bytes
            words = self.words if size is None else self.words[: size // ws]
            name = name or self.name or ("string" if len(words) == 2 else "[]byte")
            if all(_const(w) == 0 for w in words):
                # the nil slice
                return Struct(manager.next_atom(), name, OrderedDict(), OrderedDict(), len(words) * arch.bits, **tags)
            fields = OrderedDict((i * ws, w) for i, w in enumerate(words))
            names = OrderedDict((n, i * ws) for i, n in enumerate(("ptr", "len", "cap")[: len(words)]))
            return Struct(manager.next_atom(), name, fields, names, len(words) * arch.bits, **tags)
        return None


class _Values:
    """Map the pieces the ABI splits string/slice values into back to the values they belong to."""

    def __init__(self, pass_: GoBuiltinRewriter):
        self.project = pass_.project
        self.manager = pass_.manager
        self.combo_of: dict[int, tuple[VirtualVariable, int]] = {}
        self.defs: dict[int, Expression] = {}
        # phis that a pending rewrite will collapse: varid -> the value that survives
        self.aliases: dict[int, Expression] = {}

        def note(vvar: VirtualVariable):
            is_combo = vvar.category == VVC.COMBO_REGISTER or (
                vvar.category == VVC.PARAMETER and vvar.parameter_category == VVC.COMBO_REGISTER
            )
            if is_combo and vvar.reg_vvars:
                offset = 0
                for reg_vvar in vvar.reg_vvars:
                    self.combo_of[reg_vvar.varid] = (vvar, offset)
                    offset += reg_vvar.size

        if pass_._arg_vvars:
            for arg_vvar, _ in pass_._arg_vvars.values():
                if isinstance(arg_vvar, VirtualVariable):
                    note(arg_vvar)
        for block in pass_._graph.nodes:
            for stmt in block.statements:
                if isinstance(stmt, Assignment) and isinstance(stmt.dst, VirtualVariable):
                    note(stmt.dst)
                    self.defs[stmt.dst.varid] = stmt.src

    def resolve(self, expr: Expression, seen: set | None = None) -> Expression:
        """Look through virtual-variable copies (register moves and spills) and phis of one value."""
        seen = set() if seen is None else seen
        while isinstance(expr, VirtualVariable) and expr.varid not in seen:
            seen.add(expr.varid)
            src = self.aliases.get(expr.varid, self.defs.get(expr.varid))
            if isinstance(src, VirtualVariable):
                expr = src
                continue
            if isinstance(src, Phi):
                sources = [self.resolve(v, seen) for _, v in src.src_and_vvars if v is not None]
                sources = [v for v in sources if not (isinstance(v, VirtualVariable) and v.varid == expr.varid)]
                if sources and all(v.likes(sources[0]) for v in sources[1:]):
                    expr = sources[0]
                    continue
            break
        return expr

    def expand(self, expr: Expression) -> Expression:
        """Like ``resolve`` but also returns the defining expression of the final variable when it has one."""
        expr = self.resolve(expr)
        if isinstance(expr, VirtualVariable):
            src = self.defs.get(expr.varid)
            if src is not None and not isinstance(src, Phi):
                return src
        return expr

    def same(self, a: Expression, b: Expression) -> bool:
        return self.expand(a).likes(self.expand(b))

    def load_of(self, expr: Expression) -> tuple[Expression | None, int] | None:
        """(base, offset) when ``expr`` is (a copy of) a word-sized load from ``base + offset``."""
        expr = self.expand(expr)
        if not (isinstance(expr, Load) and expr.size == self.project.arch.bytes):
            return None
        base, off = _addr_and_offset(expr.addr)
        return (self.resolve(base) if base is not None else None), off

    def base_of(self, expr: Expression, want: int) -> _Base | None:
        """The value ``expr`` is the piece at byte offset ``want`` of (a combo-register value or memory)."""
        resolved = self.resolve(expr)
        if isinstance(resolved, VirtualVariable):
            hit = self.combo_of.get(resolved.varid)
            if hit is not None:
                return _Base(combo=hit[0]) if hit[1] == want else None
        load = self.load_of(expr)
        if load is None:
            return None
        base, off = load
        if base is None:
            return _Base(addr=Const(self.manager.next_atom(), off - want, self.project.arch.bits))
        return _Base(addr=base, off=off - want)

    def base_of_value(self, expr: Expression) -> _Base | None:
        """The place a whole string/slice expression stands for."""
        resolved = self.resolve(expr)
        if isinstance(resolved, VirtualVariable):
            return _Base(combo=resolved) if resolved.varid not in self.combo_of else None
        if isinstance(expr, Load):
            base, off = _addr_and_offset(expr.addr)
            if base is None:
                return _Base(addr=Const(self.manager.next_atom(), off, self.project.arch.bits))
            return _Base(addr=self.resolve(base), off=off)
        if isinstance(expr, Struct):
            ws = self.project.arch.bytes
            fields = expr.fields
            if sorted(fields) in ([0, ws], [0, ws, 2 * ws]):
                return _Base(words=tuple(self.resolve(fields[k]) for k in sorted(fields)), name=expr.name)
        return None

    def piece(self, expr: Expression, base: _Base) -> int | None:
        """The byte offset at which ``expr`` sits inside ``base``, or None when it is not a piece of it."""
        resolved = self.resolve(expr)
        if base.combo is not None:
            if isinstance(resolved, VirtualVariable):
                hit = self.combo_of.get(resolved.varid)
                if hit is not None and hit[0].varid == base.combo.varid:
                    return hit[1]
            return None
        if base.addr is not None:
            load = self.load_of(expr)
            if load is None:
                return None
            b, off = load
            if b is None:
                if _const(base.addr) is None:
                    return None
                return off - base.addr.value_int - base.off
            return off - base.off if b.likes(base.addr) else None
        if base.words is not None:
            for i, word in enumerate(base.words):
                if self.same(expr, word):
                    return i * self.project.arch.bytes
        return None

    def field(self, expr: Expression) -> tuple[_Base, int] | None:
        """The (value, byte offset) a pointer-sized expression is a piece of, the value taken to start at the load base."""
        resolved = self.resolve(expr)
        if isinstance(resolved, VirtualVariable):
            hit = self.combo_of.get(resolved.varid)
            if hit is not None:
                return _Base(combo=hit[0]), hit[1]
        load = self.load_of(expr)
        if load is None:
            return None
        base, off = load
        if base is None:
            return _Base(addr=Const(self.manager.next_atom(), off, self.project.arch.bits)), 0
        return _Base(addr=base), off

    def header(self, ptr: Expression, cap: Expression, length: Expression | None, name: str | None) -> _Base | None:
        """
        The slice whose pointer and capacity words are ``ptr`` and ``cap``: a tracked value when the pointer word
        belongs to one, else the header made of the three scalars (``length`` is its length word).
        """
        base = self.base_of(ptr, _PTR)
        if base is not None:
            at = self.piece(cap, base)
            if at == _CAP:
                return base
            if at == _LEN and (base.combo is None or base.combo.size == _STRING_BITS // 8):
                # a string's bytes: []byte(s) has cap == len
                base.conv = "[]byte"
                return base
        if length is None:
            return None
        return _Base(words=(self.resolve(ptr), self.resolve(length), self.resolve(cap)), name=name)

    def whole(self, size: int | None, *pieces: tuple[Expression, int], tags=None) -> Expression | None:
        """The value whose pieces at the given byte offsets are ``pieces``; ``size`` None means any size."""
        base = self.base_of(pieces[0][0], pieces[0][1])
        if base is None:
            return None
        for expr, want in pieces[1:]:
            if self.piece(expr, base) != want:
                return None
        return base.value(self.manager, self.project.arch, size, tags or pieces[0][0].tags)

    def string(self, ptr: Expression, length: Expression) -> Expression | None:
        value = self.whole(_STRING_BITS // 8, (ptr, _PTR), (length, _LEN))
        if value is not None:
            return value
        return self.literal(ptr, length)

    def literal(self, ptr: Expression, length: Expression) -> StringLiteral | None:
        addr, n = _const(ptr), _const(length)
        if addr is None or n is None or n < 0 or n > 0x10000:
            return None
        if n == 0:
            return StringLiteral(self.manager.next_atom(), "", _STRING_BITS, **ptr.tags)
        section = self.project.loader.find_section_containing(addr)
        if section is None or not section.is_readable or section.is_writable:
            return None
        with contextlib.suppress(KeyError, UnicodeDecodeError):
            data = self.project.loader.memory.load(addr, n).decode("utf-8")
            return StringLiteral(self.manager.next_atom(), data, _STRING_BITS, **ptr.tags)
        return None

    def slice(self, ptr: Expression, length: Expression) -> Expression | None:
        """The slice (or string, when that is what the pieces belong to) with the given ptr and len pieces."""
        base = self.base_of(ptr, _PTR)
        size = None if base is not None and base.combo is not None else _SLICE_BITS // 8
        return self.whole(size, (ptr, _PTR), (length, _LEN))

    def is_len_of(self, expr: Expression, base: _Base) -> bool:
        return self.piece(expr, base) == _LEN


class GoBuiltinRewriter(OptimizationPass, CFGTransformationMixin):
    """
    Turn calls into the Go runtime back into the builtins and operators the compiler lowered them from: ``new``,
    ``make``, ``append``, ``copy``, ``panic``, string concatenation/comparison and the string/slice conversions.

    ``growslice`` is special: the compiler only calls it when the slice must grow, so the call sits under an
    ``if newLen > cap`` diamond whose join block stores the appended elements (go1.25+ nests a stack-buffer choice
    under the check). The diamond is folded into one unconditional ``append(s, elems...)`` (append grows on demand
    itself) and the element stores are dropped; a ``memmove``/``typedslicecopy`` of the new elements is
    ``append(s, t...)``. The slice may be a tracked value, a field of a struct in memory, a header the compiler keeps
    in three scalars, or an array (``arr[:n]``). When the elements cannot be matched the call still becomes
    ``append(s)`` with a comment giving the element count.
    """

    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.BEFORE_VARIABLE_RECOVERY
    NAME = "Rewrite Go runtime calls into builtins"

    def __init__(self, func, manager, **kwargs):
        super().__init__(func, manager, **kwargs)
        CFGTransformationMixin.__init__(self, self._graph)
        self.values: _Values | None = None
        self.analyze()

    def _check(self):
        return self.project.is_go_binary, None

    def _analyze(self, cache=None):
        self.values = _Values(self)
        touched = self._fold_growslice()
        if touched:
            self._drop_dead_defs(touched)
            self.values = _Values(self)
        rewriter = _BuiltinRewriter(self)
        for block in list(self._graph.nodes):
            rewriter.walk(block)
        folded = self._fold_returns()
        dropped = self._drop_unused_call_results()
        if touched or rewriter.changed or folded or dropped:
            self.out_graph = self._graph

    #
    # Cleanups
    #

    def _use_counts(self) -> Counter:
        counter = _VVarCounter()
        for block in self._graph.nodes:
            counter.walk(block)
        return counter.counts

    def _drop_dead_defs(self, blocks: list[Block]) -> None:
        """Drop side-effect-free assignments in ``blocks`` whose variable is no longer used anywhere."""
        while True:
            counts = self._use_counts()
            dropped = False
            for block in blocks:
                kept = []
                for stmt in block.statements:
                    if (
                        isinstance(stmt, Assignment)
                        and isinstance(stmt.dst, VirtualVariable)
                        and not isinstance(stmt.src, (Call, Phi))
                        and counts[stmt.dst.varid] <= 1
                    ):
                        dropped = True
                        continue
                    kept.append(stmt)
                block.statements = kept
            if not dropped:
                return

    def _drop_unused_call_results(self) -> bool:
        """``v = f(...)`` with ``v`` never read becomes the call statement ``f(...)``."""
        counts = self._use_counts()
        changed = False
        for block in self._graph.nodes:
            for i, stmt in enumerate(block.statements):
                if not (
                    isinstance(stmt, Assignment)
                    and isinstance(stmt.dst, VirtualVariable)
                    and isinstance(stmt.src, Call)
                    and not stmt.dst.was_stack
                ):
                    continue
                # a multi-register result is also used through its constituent registers
                uses = counts[stmt.dst.varid] - 1
                for rv in stmt.dst.reg_vvars or ():
                    uses += counts[rv.varid]
                if uses <= 0:
                    block.statements[i] = SideEffectStatement(stmt.idx, stmt.src, **stmt.tags)
                    changed = True
        return changed

    def _fold_returns(self) -> bool:
        """``v = f(...)`` followed only by ``return v`` becomes ``return f(...)``."""
        counts = None
        folded = False
        for block in list(self._graph.nodes):
            if not block.statements or block not in self._graph:
                continue
            last = block.statements[-1]
            if not (isinstance(last, Assignment) and isinstance(last.dst, VirtualVariable)):
                continue
            src = last.src
            if not isinstance(src, Call) and not (
                isinstance(src, BinaryOp) and src.op == "Add" and src.bits == _STRING_BITS
            ):
                continue
            chain = []
            succs = list(self._graph.successors(block))
            while len(succs) == 1 and self._graph.in_degree(succs[0]) == 1 and is_jump_only(succs[0]):
                chain.append(succs[0])
                succs = list(self._graph.successors(succs[0]))
            if len(succs) != 1 or self._graph.in_degree(succs[0]) != 1:
                continue
            ret_block = succs[0]
            body = [stmt for stmt in ret_block.statements if not isinstance(stmt, Label)]
            if len(body) != 1 or not isinstance(body[0], Return) or self._graph.out_degree(ret_block) != 0:
                continue
            ret = body[0]
            exprs = list(ret.ret_exprs or [])
            if len(exprs) != 1 or not (isinstance(exprs[0], VirtualVariable) and exprs[0].varid == last.dst.varid):
                continue
            counts = counts if counts is not None else self._use_counts()
            if counts[last.dst.varid] != 2:
                continue
            block.statements = [*block.statements[:-1], Return(ret.idx, [src], **ret.tags)]
            for dead in [*chain, ret_block]:
                self._graph.remove_node(dead)
                self._block_by_addr_and_idx.pop((dead.addr, dead.idx), None)
            folded = True
        return folded

    #
    # Helpers
    #

    def callee_name(self, call: Call) -> str | None:
        name = call_target_name(self.project, call)
        return normalize_go_func_name(name) if name is not None else None

    def type_name(self, expr: Expression) -> str | None:
        addr = _const(expr)
        return go_type_name_at(self.project, addr) if addr is not None else None

    def type_size(self, expr: Expression) -> int | None:
        addr = _const(expr)
        ty = go_type_at(self.project, addr) if addr is not None else None
        if ty is None or not ty.size:
            return None
        return ty.size // self.project.arch.byte_width

    def builtin(
        self, call: Call, name: str, args: list, bits: int | None = None, arg_types: list[str] | None = None, **extra
    ) -> Call:
        tags = {k: v for k, v in call.tags.items() if not k.startswith("go_")}
        result_type = extra.get("go_result_type")
        if result_type is not None:
            tags["is_prototype_guessed"] = False
        new_call = Call(call.idx, name, args, bits=bits if bits is not None else call.bits, **tags, **extra)
        if result_type is not None:
            # lets type inference see the result type (and the argument types when given)
            with contextlib.suppress(Exception):
                returnty = self.kb.go_signatures.type(result_type)
                argtys = [self.kb.go_signatures.type(t) for t in arg_types] if arg_types else []
                proto = GoSimTypeFunction(argtys, returnty).with_arch(self.project.arch)
                variable_map_of(self.manager).set_prototype(new_call, proto)
        return new_call

    def to_bits(self, expr: Expression, bits: int | None) -> Expression:
        if bits is None or expr.bits == bits:
            return expr
        return Convert(self.manager.next_atom(), expr.bits, bits, False, expr, **expr.tags)

    def compare(self, op: str, lhs: Expression, rhs: Expression, bits: int | None, tags) -> Expression:
        cmp = BinaryOp(self.manager.next_atom(), op, [lhs, rhs], False, bits=1, **tags)
        return self.to_bits(cmp, bits)

    #
    # Call rules
    #

    def rewrite_call(self, call: Call) -> Expression | None:
        name = self.callee_name(call)
        if name is None:
            return None
        rule = _CALL_RULES.get(name)
        if rule is None and name.startswith("runtime.mallocgc"):
            # go1.25+ inlines newobject into size-class specialized mallocgc variants
            rule = GoBuiltinRewriter._rw_mallocgc
        if rule is None:
            return self._rewrite_guessed_strings(call)
        args = list(call.args or [])
        try:
            return rule(self, call, args)
        except Exception:  # pylint:disable=broad-exception-caught
            l.debug("Rewriting %s failed", name, exc_info=True)
            return None

    def _rewrite_guessed_strings(self, call: Call) -> Expression | None:
        """
        A callee without a Go signature keeps its guessed prototype; two consecutive constant arguments that spell
        (read-only address, small length) of readable text are a string, passed as its two words.
        """
        if not call.tags.get("is_prototype_guessed", True):
            return None
        args = list(call.args or [])
        if len(args) < 2:
            return None
        out = []
        i = 0
        changed = False
        while i < len(args):
            if i + 1 < len(args) and isinstance(args[i], Const) and isinstance(args[i + 1], Const):
                n = _const(args[i + 1])
                literal = self.values.literal(args[i], args[i + 1]) if n and 0 < n <= 4096 else None
                if literal is not None and _looks_like_text(literal.data):
                    out.append(literal)
                    i += 2
                    changed = True
                    continue
            out.append(args[i])
            i += 1
        if not changed:
            return None
        return Call(call.idx, call.target, out, bits=call.bits, **call.tags)

    def _rw_newobject(self, call: Call, args: list) -> Expression | None:
        ty = self.type_name(args[0]) if len(args) == 1 else None
        if ty is None:
            return None
        return self.builtin(call, "new", [], go_type_args=[ty], go_result_type=f"*{ty}")

    def _rw_mallocgc(self, call: Call, args: list) -> Expression | None:
        if len(args) != 3:
            return None
        ty = self.type_name(args[1])
        if ty is None or _const(args[0]) != self.type_size(args[1]):
            return None
        return self.builtin(call, "new", [], go_type_args=[ty], go_result_type=f"*{ty}")

    def _rw_makeslice(self, call: Call, args: list) -> Expression | None:
        ty = self.type_name(args[0]) if len(args) == 3 else None
        if ty is None:
            return None
        length, cap = args[1], args[2]
        dims = [length] if cap.likes(length) else [length, cap]
        return self.builtin(call, "make", dims, go_type_args=[f"[]{ty}"], go_result_type="unsafe.Pointer")

    def _rw_growslice(self, call: Call, args: list) -> Expression | None:
        # the elements were not matched; keep the growth visible as append(s) with the missing elements in a comment
        if len(args) not in (5, 7):
            return None
        old_ptr, new_len, old_cap, num, et = args[:5]
        count = _const(num)
        old_len = self._old_length(new_len, old_cap, num, count)
        ty = self.type_name(et)
        s = self.values.header(old_ptr, old_cap, old_len, f"[]{ty}" if ty else None)
        if s is None:
            return None
        if s.words is None and old_len is not None and not self.values.is_len_of(old_len, s):
            s = _Base(
                words=(self.values.resolve(old_ptr), self.values.resolve(old_len), self.values.resolve(old_cap)),
                name=f"[]{ty}" if ty else None,
            )
        value = s.value(self.manager, self.project.arch, _SLICE_BITS // 8, call.tags)
        if value is None:
            return None
        comment = f"{count} element(s) not recovered" if count is not None else "elements not recovered"
        extra = {"go_result_type": f"[]{ty}"} if ty else {}
        return self.builtin(call, "append", [value], bits=_SLICE_BITS, go_comment=comment, **extra)

    def _rw_concatstring(self, call: Call, args: list) -> Expression | None:
        # a typed "+" call rather than an integer Add: type inference must see strings, not 128-bit integers
        parts = args[1:]
        if len(parts) < 2 or any(p.bits != _STRING_BITS for p in parts):
            return None
        variable_map = variable_map_of(self.manager)
        expr = parts[0]
        for part in parts[1:]:
            concat = self.builtin(
                call,
                "+",
                [expr, part],
                bits=_STRING_BITS,
                arg_types=["string", "string"],
                go_render="concat",
                go_result_type="string",
            )
            # each nested concatenation needs its own identity (the prototype is keyed by it)
            expr = Call(self.manager.next_atom(), concat.target, concat.args, bits=concat.bits, **concat.tags)
            variable_map.set_prototype(expr, variable_map.prototype(concat))
        return expr

    def _rw_memequal(self, call: Call, args: list) -> Expression | None:
        if len(args) != 3:
            return None
        a = self.values.base_of(args[0], _PTR)
        b = self.values.base_of(args[1], _PTR)
        size = args[2]
        lhs = rhs = None
        if a is not None:
            lhs = a.value(self.manager, self.project.arch, _STRING_BITS // 8, args[0].tags)
        if b is not None:
            rhs = b.value(self.manager, self.project.arch, _STRING_BITS // 8, args[1].tags)
        # the compared length must be the length of one of the operands (or of a literal)
        ok = (a is not None and self.values.is_len_of(size, a)) or (b is not None and self.values.is_len_of(size, b))
        if rhs is None and lhs is not None:
            rhs = self.values.literal(args[1], size)
            ok = ok or rhs is not None
        if lhs is None and rhs is not None:
            lhs = self.values.literal(args[0], size)
            ok = ok or lhs is not None
        if lhs is None or rhs is None or not ok:
            return self._memequal_fallback(call, args, a is None, b is None)
        return self.compare("CmpEQ", lhs, rhs, call.bits, call.tags)

    def _memequal_fallback(self, call: Call, args: list, a_untracked: bool, b_untracked: bool) -> Expression | None:
        """
        An operand that is not a tracked string: a word-sized compare becomes a load compared with the literal's
        value; anything else keeps the call, with the rodata pointer spelled as the literal of the compared length.
        """
        size = args[2]
        n = _const(size)
        lit_a = self.values.literal(args[0], size) if a_untracked else None
        lit_b = self.values.literal(args[1], size) if b_untracked else None
        if lit_a is None and lit_b is None:
            return None
        if n in (1, 2, 4, 8) and (lit_a is None) != (lit_b is None):
            lit, other = (lit_a, args[1]) if lit_a is not None else (lit_b, args[0])
            value = int.from_bytes(
                lit.data.encode("utf-8"), "little" if self.project.arch.memory_endness == "Iend_LE" else "big"
            )
            load = Load(self.manager.next_atom(), other, n, self.project.arch.memory_endness, **other.tags)
            return self.compare("CmpEQ", load, Const(self.manager.next_atom(), value, n * 8), call.bits, call.tags)
        return self.builtin(call, "runtime.memequal", [lit_a or args[0], lit_b or args[1], size], bits=call.bits)

    def _rw_memequal_n(self, call: Call, args: list, size: int) -> Expression | None:
        if len(args) != 2:
            return None
        endness = self.project.arch.memory_endness
        lhs = Load(self.manager.next_atom(), args[0], size, endness, **args[0].tags)
        rhs = Load(self.manager.next_atom(), args[1], size, endness, **args[1].tags)
        return self.compare("CmpEQ", lhs, rhs, call.bits, call.tags)

    def _rw_rename(self, call: Call, args: list, name: str) -> Expression | None:
        return self.builtin(call, name, args)

    def _rw_slicebytetostring(self, call: Call, args: list) -> Expression | None:
        b = self.values.slice(args[1], args[2]) if len(args) == 3 else None
        if b is None:
            return None
        return self.builtin(call, "string", [b], bits=_STRING_BITS, go_result_type="string")

    def _rw_conversion(self, call: Call, args: list, name: str, bits: int, result: str) -> Expression | None:
        if len(args) != 2:
            return None
        return self.builtin(call, name, [args[1]], bits=bits, go_result_type=result)

    def _rw_intstring(self, call: Call, args: list) -> Expression | None:
        if len(args) != 2:
            return None
        rune = Call(self.manager.next_atom(), "rune", [args[1]], bits=32, go_result_type="rune", **args[1].tags)
        return self.builtin(call, "string", [rune], bits=_STRING_BITS, go_result_type="string")

    def _rw_slicecopy(self, call: Call, args: list) -> Expression | None:
        if len(args) != 5:
            return None
        dst = self.values.slice(args[0], args[1])
        src = self.values.slice(args[2], args[3])
        if dst is None or src is None:
            return None
        return self.builtin(call, "copy", [dst, src], go_result_type="int")

    def _rw_memmove(self, call: Call, args: list) -> Expression | None:
        # copy(dst, src): memmove(dst.ptr, src.ptr, min(len(dst), len(src)) * width)
        if len(args) != 3:
            return None
        dst = self.values.base_of(args[0], _PTR)
        src = self.values.base_of(args[1], _PTR)
        if dst is None or src is None:
            return None
        count = args[2]
        if isinstance(count, BinaryOp) and count.op == "Mul" and isinstance(count.operands[1], Const):
            count = count.operands[0]
        if not self._is_min_len(count, dst, src):
            return None
        arch = self.project.arch
        dst_val = dst.value(self.manager, arch, _SLICE_BITS // 8, args[0].tags)
        src_val = src.value(self.manager, arch, None if src.combo else _SLICE_BITS // 8, args[1].tags)
        if dst_val is None or src_val is None:
            return None
        return self.builtin(call, "copy", [dst_val, src_val], bits=self.project.arch.bits, go_result_type="int")

    def _is_min_len(self, count: Expression, a: _Base, b: _Base) -> bool:
        count = self.values.resolve(count)
        if self.values.is_len_of(count, a) or self.values.is_len_of(count, b):
            return True
        candidates = None
        if isinstance(count, VirtualVariable):
            src = self.values.defs.get(count.varid)
            if isinstance(src, Phi):
                candidates = [v for _, v in src.src_and_vvars]
            elif isinstance(src, ITE):
                candidates = [src.iftrue, src.iffalse]
        elif isinstance(count, ITE):
            candidates = [count.iftrue, count.iffalse]
        if not candidates or len(candidates) != 2 or any(c is None for c in candidates):
            return False
        x, y = candidates
        return (self.values.is_len_of(x, a) and self.values.is_len_of(y, b)) or (
            self.values.is_len_of(x, b) and self.values.is_len_of(y, a)
        )

    def _rw_gopanic(self, call: Call, args: list) -> Expression | None:
        return self.builtin(call, "panic", args) if len(args) == 1 else None

    #
    # Statement rules: typed moves and clears become stores
    #

    def rewrite_call_stmt(self, stmt: SideEffectStatement) -> Statement | None:
        call = stmt.expr
        if not isinstance(call, Call) or stmt.ret_expr is not None:
            return None
        name = self.callee_name(call)
        args = list(call.args or [])
        endness = self.project.arch.memory_endness
        if name == "runtime.typedmemmove" and len(args) == 3:
            size = self.type_size(args[0])
            if size is None:
                return None
            src = Load(self.manager.next_atom(), args[2], size, endness, **args[2].tags)
            return Store(stmt.idx, args[1], src, size, endness, **stmt.tags)
        if name == "runtime.typedmemclr" and len(args) == 2:
            size, ty = self.type_size(args[0]), self.type_name(args[0])
            if size is None or ty is None:
                return None
            zero = Struct(self.manager.next_atom(), ty, OrderedDict(), OrderedDict(), size * 8, **args[1].tags)
            return Store(stmt.idx, args[1], zero, size, endness, **stmt.tags)
        if name == "runtime.memclrNoHeapPointers" and len(args) == 2:
            size = _const(args[1])
            if size not in (1, 2, 4, 8, 16):
                return None
            zero = Const(self.manager.next_atom(), 0, size * 8, **args[1].tags)
            return Store(stmt.idx, args[0], zero, size, endness, **stmt.tags)
        return None

    #
    # Expression rules
    #

    def rewrite_binop(self, expr: BinaryOp) -> Expression | None:
        # cmpstring(a, b) <op> 0  ->  a <op> b
        if expr.op not in _COMPARISONS:
            return None
        lhs, rhs = expr.operands
        op = expr.op
        if _const(lhs) == 0 and isinstance(_strip_converts(rhs), Call):
            lhs, rhs = rhs, lhs
            op = _SWAPPED[op]
        call = _strip_converts(lhs)
        if _const(rhs) != 0 or not isinstance(call, Call) or self.callee_name(call) != "runtime.cmpstring":
            return None
        args = list(call.args or [])
        if len(args) != 2 or any(a.bits != _STRING_BITS for a in args):
            return None
        return self.compare(op, args[0], args[1], expr.bits, expr.tags)

    def rewrite_ite(self, expr: ITE) -> Expression | None:
        # len(a) == len(b) ? a == b : false  ->  a == b
        cond = _strip_converts(expr.cond)
        eq = _strip_converts(expr.iftrue)
        iffalse = _strip_converts(expr.iffalse)
        if not (isinstance(cond, BinaryOp) and cond.op == "CmpEQ" and isinstance(eq, BinaryOp) and eq.op == "CmpEQ"):
            return None
        if not (_const(iffalse) == 0 or iffalse.likes(cond)):
            return None
        a, b = eq.operands
        if a.bits != _STRING_BITS or b.bits != _STRING_BITS:
            return None
        if not all(self._is_len_check(operand, a, b) for operand in cond.operands):
            return None
        return self.to_bits(eq, expr.bits)

    def _is_len_check(self, operand: Expression, a: Expression, b: Expression) -> bool:
        for value in (a, b):
            if isinstance(value, StringLiteral):
                if _const(operand) == len(value.data.encode("utf-8")):
                    return True
                continue
            base = self.values.base_of_value(value)
            if base is not None and self.values.is_len_of(operand, base):
                return True
        return False

    def rewrite_struct(self, expr: Struct) -> Expression | None:
        fields = [expr.fields[off] for off in sorted(expr.fields)]
        if not fields:
            return None
        # the pieces of one combo-register value, in order: the value itself
        first = self.values.base_of(fields[0], 0)
        if first is not None and first.combo is not None:
            combo = first.combo
            pieces = [self.values.resolve(f) for f in fields]
            ids = [rv.varid for rv in combo.reg_vvars]
            if (
                all(isinstance(p, VirtualVariable) for p in pieces)
                and [p.varid for p in pieces] == ids
                and combo.bits == expr.bits
            ):
                return combo
        return self._rewrite_slicing(expr, fields)

    def _rewrite_slicing(self, expr: Struct, fields: list) -> Expression | None:
        # s[i:j] / s[i:] / s[:j]: {ptr: s.ptr + i*w (guarded), len: j - i, cap: s.cap - i}
        if len(fields) != 3 or expr.bits != _SLICE_BITS:
            return None
        ptr, length, cap = fields
        base = None
        low = None
        if isinstance(cap, BinaryOp) and cap.op == "Sub":
            base = self.values.base_of(cap.operands[0], _CAP)
            low = cap.operands[1]
        else:
            base = self.values.base_of(cap, _CAP)
        if base is None:
            return None
        if low is None:
            # s[:j]
            if self.values.piece(ptr, base) != _PTR or self.values.is_len_of(length, base):
                return None
            high = length
        else:
            if not (isinstance(ptr, BinaryOp) and ptr.op == "Add"):
                return None
            p, advance = ptr.operands
            if self.values.piece(p, base) != _PTR:
                if self.values.piece(advance, base) != _PTR:
                    return None
                advance = p
            if not self._is_guarded_advance(advance, low):
                return None
            if not (isinstance(length, BinaryOp) and length.op == "Sub" and length.operands[1].likes(low)):
                return None
            high = None if self.values.is_len_of(length.operands[0], base) else length.operands[0]
        s = base.value(self.manager, self.project.arch, _SLICE_BITS // 8, expr.tags)
        if s is None:
            return None
        if low is None:
            shape, args = "[:j]", [s, high]
        elif high is None:
            shape, args = "[i:]", [s, low]
        else:
            shape, args = "[i:j]", [s, low, high]
        return Call(expr.idx, "[:]", args, bits=_SLICE_BITS, go_slice=shape, **expr.tags)

    @staticmethod
    def _is_guarded_advance(advance: Expression, low: Expression) -> bool:
        # i*w masked by (-(cap - i) >> 63) so an empty result does not point past the array
        def is_guard(e):
            return isinstance(e, BinaryOp) and e.op == "Sar" and _const(e.operands[1]) == 63

        def is_offset(e):
            if isinstance(e, BinaryOp) and e.op == "Mul":
                return any(o.likes(low) for o in e.operands)
            k = _const(low)
            return k is not None and isinstance(e, Const) and e.value_int in {k * w for w in (1, 2, 4, 8, 16)}

        return _has_node(advance, is_guard) and _has_node(advance, is_offset)

    #
    # growslice diamonds
    #

    def _fold_growslice(self) -> list[Block]:
        touched: list[Block] = []
        for block in list(self._graph.nodes):
            if block not in self._graph:
                continue
            growth = self._match_growslice(block)
            if growth is not None:
                touched += self._apply_append(growth)
        return touched

    def _match_growslice(self, block: Block) -> _Growth | None:
        call_stmt = None
        for stmt in block.statements:
            if isinstance(stmt, Assignment) and isinstance(stmt.src, Call):
                if call_stmt is not None or self.callee_name(stmt.src) not in _GROWSLICE_NAMES:
                    return None
                call_stmt = stmt
            elif isinstance(stmt, (Assignment, Store)):
                # copies, stores and values re-read after the call (registers the call clobbered)
                if find_call(stmt) is not None:
                    return None
            elif not isinstance(stmt, (Label, Jump)):
                return None
        if call_stmt is None or not isinstance(call_stmt.dst, VirtualVariable) or not call_stmt.dst.reg_vvars:
            return None
        args = list(call_stmt.src.args or [])
        if len(args) not in (5, 7):
            return None
        old_ptr, new_len, old_cap, num, et = args[:5]
        count = _const(num)
        if count is not None and count <= 0:
            return None
        old_len = self._old_length(new_len, old_cap, num, count)
        if old_len is None:
            return None
        ty = self.type_name(et)
        base = self.values.header(old_ptr, old_cap, old_len, f"[]{ty}" if ty else None)
        if base is None or (base.words is None and not self.values.is_len_of(old_len, base)):
            base = self.values.header(old_ptr, old_cap, old_len, None) if base is None else None
            if base is None or base.words is None:
                return None
        ws = self.project.arch.bytes
        g = _Growth(block, call_stmt, base, count, num, et, old_len, new_len, self.type_size(et) or ws)
        g.ptrs = [call_stmt.dst.reg_vvars[0]]
        g.len_new = [call_stmt.dst.reg_vvars[1], self.values.resolve(new_len)]
        g.len_old = [self.values.resolve(old_len)]
        self._match_diamond(g, base, old_cap, new_len)
        if g.join is not None:
            g.phis = self._phis(g.join)
            gone = {(pre_join.addr, pre_join.idx) for _, _, pre_join in g.arms}
            for dst, phi in g.phis.values():
                survivors = [v for src, v in phi.src_and_vvars if src not in gone and v is not None]
                if survivors and all(v.varid == survivors[0].varid for v in survivors[1:]):
                    self.values.aliases[dst.varid] = survivors[0]
            for dst, phi in g.phis.values():
                entries = dict(phi.src_and_vvars)
                grown_side = entries.get((g.post_grow.addr, g.post_grow.idx))
                old_side = entries.get((g.arms[-1][2].addr, g.arms[-1][2].idx))
                if grown_side is None or old_side is None:
                    continue
                grown_side = self.values.resolve(grown_side)
                grown_hit = (
                    self.values.combo_of.get(grown_side.varid) if isinstance(grown_side, VirtualVariable) else None
                )
                if grown_hit is None or grown_hit[0].varid != call_stmt.dst.varid:
                    if self._is_alias(grown_side, g.len_old) and self._is_alias(old_side, g.len_old):
                        g.len_old.append(dst)
                    continue
                old_piece = self.values.piece(old_side, base)
                if grown_hit[1] == _PTR and old_piece == _PTR:
                    g.ptrs.append(dst)
                elif grown_hit[1] == _LEN and self.values.same(old_side, new_len):
                    g.len_new.append(dst)
        self._match_elements(g)
        if g.elems is None and g.src is None:
            # nothing folded: the phis stay
            for dst, _ in g.phis.values():
                self.values.aliases.pop(dst.varid, None)
        return g

    def _old_length(self, new_len, old_cap, num, count: int | None) -> Expression | None:
        """The old length word: ``new_len`` is ``old_len + num``."""
        grown = self.values.expand(new_len)
        if isinstance(grown, BinaryOp) and grown.op == "Add":
            x, y = grown.operands
            for a, b in ((x, y), (y, x)):
                if (count is not None and _const(b) == count) or (count is None and self.values.same(b, num)):
                    return a
        bits = self.project.arch.bits
        n = _const(new_len)
        if count is not None and n is not None and n >= count:
            return Const(self.manager.next_atom(), n - count, bits)
        if self.values.same(new_len, num):
            return Const(self.manager.next_atom(), 0, bits)
        return BinaryOp(self.manager.next_atom(), "Sub", [new_len, num], False, bits=bits, **new_len.tags)

    def _match_diamond(self, g: _Growth, base: _Base, old_cap, new_len) -> None:
        """
        ``if newLen > cap { growslice }`` around the call block; the join is where both paths meet. go1.25+ nests
        further choices under the check (a small result lives in a stack buffer); every arm joins the same block.
        """
        # the grow path: the call block and its copy-only successors up to the join
        chain = [g.block]
        while True:
            succs = list(self._graph.successors(chain[-1]))
            if len(succs) != 1 or succs[0] in chain:
                return
            if self._graph.in_degree(succs[0]) > 1:
                join = succs[0]
                break
            if not self._copies_only(succs[0]):
                return
            chain.append(succs[0])
        post_grow = chain[-1]
        # the conditions above the call block, up to the capacity check; their other arms all reach the join
        region = {g.block}
        entry = None
        arms: list[tuple[Block, Block, Block]] = []
        changed = True
        while changed and entry is None and len(region) < 8:
            changed = False
            preds = {p for b in region for p in self._graph.predecessors(b) if p not in region and p is not join}
            for pred in sorted(preds, key=lambda b: (b.addr, b.idx or 0), reverse=True):
                if is_jump_only(pred):
                    region.add(pred)
                    changed = True
                    continue
                if not (pred.statements and isinstance(pred.statements[-1], ConditionalJump)):
                    continue
                pred_succs = list(self._graph.successors(pred))
                if len(pred_succs) != 2:
                    continue
                new_arms = []
                for succ in pred_succs:
                    if succ in region:
                        continue
                    if succ in preds:
                        # an inner condition: it joins the region first
                        new_arms = None
                        break
                    pre_join = pred if succ is join else self._arm_end(succ, join)
                    if pre_join is None:
                        new_arms = None
                        break
                    new_arms.append((pred, succ, pre_join))
                if new_arms is None:
                    continue
                region.add(pred)
                arms += new_arms
                changed = True
                if self._is_grow_check(pred.statements[-1].condition, base, old_cap, new_len):
                    entry = pred
                    break
        if entry is None or not arms:
            return
        for block in region:
            if block is not entry and any(p not in region for p in self._graph.predecessors(block)):
                return
        g.cond_block, g.join, g.post_grow, g.arms = entry, join, post_grow, arms

    def _arm_end(self, arm: Block, join: Block) -> Block | None:
        """The last block of a path that skips the growth: copy-only blocks straight to the join."""
        if arm is join:
            return None
        cur = arm
        seen = set()
        while cur not in seen:
            seen.add(cur)
            if self._graph.in_degree(cur) != 1 or not self._copies_only(cur):
                return None
            succs = list(self._graph.successors(cur))
            if len(succs) != 1:
                return None
            if succs[0] is join:
                return cur
            cur = succs[0]
        return None

    @staticmethod
    def _copies_only(block: Block) -> bool:
        return all(
            isinstance(st, (Label, Jump, Store)) or (isinstance(st, Assignment) and find_call(st.src) is None)
            for st in block.statements
        ) and not any(find_call(st) is not None for st in block.statements)

    def _is_grow_check(self, cond, base: _Base, old_cap, new_len) -> bool:
        if not isinstance(cond, BinaryOp) or cond.op not in ("CmpLT", "CmpLE", "CmpGT", "CmpGE", "CmpEQ", "CmpNE"):
            return False
        a, b = cond.operands
        if cond.op in ("CmpEQ", "CmpNE"):
            # a nil slice grows unless the new length is zero
            return _const(old_cap) == 0 and (
                (_const(b) == 0 and self.values.same(a, new_len)) or (_const(a) == 0 and self.values.same(b, new_len))
            )

        def is_cap(x):
            return self.values.piece(x, base) == _CAP or self.values.same(x, old_cap)

        return (is_cap(a) and self.values.same(b, new_len)) or (is_cap(b) and self.values.same(a, new_len))

    #
    # The appended elements: stores past the old end, or a copy of a whole slice
    #

    def _is_alias(self, expr, aliases: list) -> bool:
        resolved = self.values.resolve(expr)
        return any(resolved.likes(a) for a in aliases)

    def _window(self, g: _Growth) -> list[Statement]:
        """
        Statements that may hold the element stores: the rest of the call block and its straight-line successors up
        to the join, then the join and its straight-line successors. Stops at (and includes) the first other call.
        """
        stmts = list(g.block.statements)
        pos = next((i for i, st in enumerate(stmts) if st is g.call_stmt), len(stmts))
        out: list[Statement] = stmts[pos + 1 :]
        block = g.block
        seen = {block}
        while True:
            succs = list(self._graph.successors(block))
            if len(succs) != 1 or succs[0] in seen:
                return out
            block = succs[0]
            seen.add(block)
            if block is g.join:
                out += list(block.statements)
            elif self._graph.in_degree(block) != 1:
                return out
            else:
                for stmt in block.statements:
                    out.append(stmt)
                    if find_call(stmt) is not None:
                        return out

    def _match_elements(self, g: _Growth) -> None:
        window = self._window(g)
        found: dict[int, dict[int, tuple[Store, Expression]]] = {}  # element k -> byte offset -> store
        for stmt in window:
            if isinstance(stmt, SideEffectStatement) and isinstance(stmt.expr, Call):
                if self._match_copy(g, stmt):
                    return
                continue
            if not isinstance(stmt, Store) or g.count is None:
                continue
            parsed = self._store_offset(stmt.addr, g)
            if parsed is None:
                continue
            hit = self._element_of(*parsed, g)
            if hit is None:
                continue
            k, at = hit
            if k == g.count and at == 0 and stmt.size == g.width * g.count and g.count > 1:
                # one wide store of every appended element: append(s, src...)
                src = self._wide_source(g, stmt.data)
                if src is not None:
                    g.src, g.stores = src, [stmt]
                    return
                continue
            if 1 <= k <= g.count and at + stmt.size <= g.width and at not in found.setdefault(k, {}):
                found[k][at] = (stmt, stmt.data)
        if g.count is None or len(found) != g.count:
            return
        elems = []
        for k in range(g.count, 0, -1):
            pieces = sorted((at, stmt.size, data) for at, (stmt, data) in found[k].items())
            if [(at, size) for at, size, _ in pieces] != self._covering(pieces, g.width):
                return
            values = self._elements(g, [data for _, _, data in pieces])
            if values is None:
                return
            elems.append(self._element_value(g, [(at, v) for (at, _, _), v in zip(pieces, values)]))
        g.elems = elems
        g.stores = list({id(st): st for k in found for st, _ in found[k].values()}.values())

    @staticmethod
    def _covering(pieces: list, width: int) -> list:
        """The (offset, size) list that would cover ``width`` bytes without gaps or overlaps."""
        out = []
        pos = 0
        for at, size, _ in pieces:
            if at != pos:
                return []
            out.append((at, size))
            pos += size
        return out if pos == width else []

    def _element_value(self, g: _Growth, pieces: list[tuple[int, Expression]]) -> Expression:
        """The stored pieces (byte offset, value) of one element as a value of the element type."""
        if len(pieces) == 1:
            return pieces[0][1]
        elem_name = self.type_name(g.et) or ""
        ws = self.project.arch.bytes
        if (elem_name == "string" or elem_name.startswith("[]")) and all(at % ws == 0 for at, _ in pieces):
            value = self.values.whole(g.width, *pieces)
            if value is None and elem_name == "string" and len(pieces) == 2:
                value = self.values.literal(pieces[0][1], pieces[1][1])
            if value is not None:
                return value
        return self._struct_of(elem_name, pieces)

    def _struct_of(self, name: str, pieces: list[tuple[int, Expression]]) -> Struct:
        """A value spelled as a literal of its type, field by field (fields named by their offsets)."""
        names = None
        if name == "string" or name.startswith("[]"):
            names = {0: "ptr", self.project.arch.bytes: "len", 2 * self.project.arch.bytes: "cap"}
        else:
            ty = None
            with contextlib.suppress(Exception):
                ty = self.kb.go_signatures.type(name)
            offsets = getattr(ty, "offsets", None)
            if offsets:
                names = {off: field for field, off in offsets.items()}
        if names is None or any(at not in names for at, _ in pieces):
            names = {at: f"f{at}" for at, _ in pieces}
        bits = 0
        for at, value in pieces:
            bits = max(bits, at * 8 + value.bits)
        return Struct(
            self.manager.next_atom(),
            name or "struct",
            OrderedDict((at, value) for at, value in pieces),
            OrderedDict((names[at], at) for at, _ in pieces),
            bits,
            **pieces[0][1].tags,
        )

    def _match_copy(self, g: _Growth, stmt: SideEffectStatement) -> bool:
        """``memmove(end, src, n*w)`` / ``typedslicecopy(T, end, n, src, n)`` after the growth: ``append(s, src...)``."""
        call = stmt.expr
        name = self.callee_name(call)
        args = list(call.args or [])
        if name == "runtime.memmove" and len(args) == 3:
            dst, src, n = args
            if not self._is_count_bytes(n, g):
                return False
        elif name == "runtime.typedslicecopy" and len(args) == 5:
            _, dst, _, src, n = args
            if not self._is_num(n, g):
                return False
        else:
            return False
        if not self._is_end(dst, g):
            return False
        value = self.values.slice(src, g.num)
        if value is None:
            value = self._slice_literal(g, src, g.num)
        g.src, g.stores = value, [stmt]
        return True

    def _slice_literal(self, g: _Growth, ptr: Expression, length: Expression) -> Expression:
        return self._struct_of(g.base.name or "[]byte", [(0, ptr), (self.project.arch.bytes, length)])

    def _wide_source(self, g: _Growth, data: Expression) -> Expression | None:
        data = self.values.expand(data)
        if isinstance(data, Load):
            count = Const(self.manager.next_atom(), g.count, self.project.arch.bits)
            return Call(
                self.manager.next_atom(), "[:]", [data.addr, count], bits=_SLICE_BITS, go_slice="[:j]", **data.tags
            )
        return None

    def _is_num(self, expr, g: _Growth) -> bool:
        return self.values.same(expr, g.num) or (g.count is not None and _const(expr) == g.count)

    def _is_count_bytes(self, expr, g: _Growth) -> bool:
        if g.width == 1 and self._is_num(expr, g):
            return True
        if g.count is not None and _const(expr) == g.count * g.width:
            return True
        e = self.values.expand(expr)
        if isinstance(e, BinaryOp) and e.op == "Mul" and _const(e.operands[1]) == g.width:
            return self._is_num(e.operands[0], g)
        if isinstance(e, BinaryOp) and e.op == "Shl" and (1 << (_const(e.operands[1]) or 0)) == g.width:
            return self._is_num(e.operands[0], g)
        return False

    def _is_end(self, addr, g: _Growth) -> bool:
        """``ptr + oldLen*w``: where the appended elements start."""
        parsed = self._store_offset(addr, g)
        if parsed is None:
            return False
        kind, off = parsed
        if kind == "old":
            return off == 0
        if kind == "new":
            return g.count is not None and off == -g.count * g.width
        old = _const(g.old_len)
        return old is not None and off == old * g.width

    def _element_of(self, kind: str, off: int, g: _Growth) -> tuple[int, int] | None:
        """(k, byte offset) of the store at byte ``off`` past ``ptr + len*w``: element k counted back from the end."""
        w = g.width
        if kind == "old":
            off -= g.count * w
        elif kind == "abs":
            n = _const(g.new_len)
            if n is None:
                return None
            off -= n * w
        if off >= 0:
            return None
        k = (-off + w - 1) // w
        return k, off + k * w

    def _terms(self, expr, g: _Growth, sign: int = 1) -> list[tuple[int, Expression]]:
        if self._is_alias(expr, g.ptrs) or self._is_alias(expr, g.len_new) or self._is_alias(expr, g.len_old):
            return [(sign, expr)]
        e = self.values.expand(expr) if isinstance(expr, VirtualVariable) else expr
        if isinstance(e, BinaryOp) and e.op == "Add":
            return self._terms(e.operands[0], g, sign) + self._terms(e.operands[1], g, sign)
        if isinstance(e, BinaryOp) and e.op == "Sub":
            return self._terms(e.operands[0], g, sign) + self._terms(e.operands[1], g, -sign)
        return [(sign, expr)]

    def _store_offset(self, addr, g: _Growth) -> tuple[str, int] | None:
        """
        Decompose a store address into the pointer word plus an offset: ("new", c) for ``ptr + newLen*w + c``,
        ("old", c) for ``ptr + oldLen*w + c`` and ("abs", c) for ``ptr + c``.
        """
        terms = self._terms(addr, g)
        rest = []
        found_ptr = False
        for sign, term in terms:
            if sign > 0 and not found_ptr and self._is_alias(term, g.ptrs):
                found_ptr = True
                continue
            rest.append((sign, term))
        if not found_ptr:
            return None
        bits = self.project.arch.bits
        const = 0
        var = None
        for sign, term in rest:
            c = _const(term)
            if c is not None:
                c = c - (1 << bits) if c >= 1 << (bits - 1) else c
                const += sign * c
            elif var is None and sign > 0:
                var = term
            else:
                return None
        if var is not None and _const(self._strip_guard(var, g)) is not None:
            const += _const(self._strip_guard(var, g))
            var = None
        if var is None:
            return "abs", const
        var = self._strip_guard(var, g)
        factor, inner = self._scale(var, g)
        if factor != g.width:
            return None
        inner = self._strip_guard(inner, g)
        if self._is_alias(inner, g.len_new):
            return "new", const
        if self._is_alias(inner, g.len_old):
            return "old", const
        e = self._expand_non_alias(inner, g)
        if isinstance(e, BinaryOp) and e.op in ("Add", "Sub") and _const(e.operands[1]) is not None:
            delta = _const(e.operands[1]) * (1 if e.op == "Add" else -1)
            if self._is_alias(e.operands[0], g.len_new):
                return "new", delta * g.width + const
            if self._is_alias(e.operands[0], g.len_old):
                return "old", delta * g.width + const
        return None

    def _scale(self, expr, g: _Growth) -> tuple[int, Expression]:
        """``(x * a) * b`` / ``x << s`` -> (a*b, x)."""
        factor = 1
        while True:
            e = self._expand_non_alias(expr, g)
            if isinstance(e, BinaryOp) and e.op == "Mul" and _const(e.operands[1]) is not None:
                factor, expr = factor * _const(e.operands[1]), e.operands[0]
            elif isinstance(e, BinaryOp) and e.op == "Mul" and _const(e.operands[0]) is not None:
                factor, expr = factor * _const(e.operands[0]), e.operands[1]
            elif isinstance(e, BinaryOp) and e.op == "Shl" and _const(e.operands[1]) is not None:
                factor, expr = factor << _const(e.operands[1]), e.operands[0]
            else:
                return factor, expr

    def _expand_non_alias(self, expr, g: _Growth) -> Expression:
        if self._is_alias(expr, g.ptrs) or self._is_alias(expr, g.len_new) or self._is_alias(expr, g.len_old):
            return expr
        return self.values.expand(expr)

    def _strip_guard(self, expr, g: _Growth) -> Expression:
        """``x & ((a - b) >> 63)`` (the mask that keeps an empty result inside the array) -> ``x``."""
        e = self._expand_non_alias(expr, g)
        if isinstance(e, BinaryOp) and e.op == "And":
            a, b = e.operands
            for x, y in ((a, b), (b, a)):
                if _has_node(self._expand_non_alias(y, g), lambda n: isinstance(n, BinaryOp) and n.op == "Sar"):
                    return x
        return expr

    def _elements(self, g: _Growth, data: list) -> list | None:
        """The stored values as seen on the grow path; None when one is computed in the join block itself."""
        defined_in_join = (
            {
                stmt.dst.varid
                for stmt in g.join.statements
                if isinstance(stmt, Assignment) and isinstance(stmt.dst, VirtualVariable)
            }
            if g.join is not None
            else set()
        )
        grow_side: dict[int, Expression] = {}
        for varid, (_, phi) in g.phis.items():
            value = dict(phi.src_and_vvars).get((g.post_grow.addr, g.post_grow.idx))
            if value is not None:
                grow_side[varid] = self.values.resolve(value)
        elems = []
        for value in data:
            value = self.values.resolve(value)
            if isinstance(value, VirtualVariable):
                value = grow_side.get(value.varid, value)
            elif not isinstance(value, (Const, StringLiteral, Struct)):
                # computed at the store: fine when its variables are known on the grow path
                counter = _VVarCounter()
                counter.walk_expression(value)
                subst = {v: grow_side[v] for v in counter.counts if v in grow_side}
                if any(v in defined_in_join and v not in subst for v in counter.counts):
                    return None
                if subst:
                    value = _VVarSubstituter(subst).walk_expression(value)
            if isinstance(value, VirtualVariable) and value.varid in defined_in_join:
                return None
            elems.append(value)
        return elems

    @staticmethod
    def _phis(block: Block) -> dict[int, tuple[VirtualVariable, Phi]]:
        phis = {}
        for stmt in block.statements:
            if isinstance(stmt, Assignment) and isinstance(stmt.src, Phi) and isinstance(stmt.dst, VirtualVariable):
                phis[stmt.dst.varid] = (stmt.dst, stmt.src)
        return phis

    def _apply_append(self, g: _Growth) -> list[Block]:
        call = g.call_stmt.src
        s = g.base.value(self.manager, self.project.arch, _SLICE_BITS // 8, call.tags)
        if s is None:
            return []
        s = self._array_slice(g, s)
        ty = self.type_name(g.et)
        extra = {"go_result_type": f"[]{ty}"} if ty else {}
        if g.src is not None:
            args = [s, g.src]
            extra["go_ellipsis"] = True
        elif g.elems is not None:
            args = [s, *g.elems]
        else:
            args = [s]
            num = g.count if g.count is not None else "n"
            extra["go_comment"] = f"{num} element(s) not recovered"
        new_call = self.builtin(call, "append", args, bits=_SLICE_BITS, **extra)
        g.block.statements = [
            Assignment(stmt.idx, stmt.dst, new_call, **stmt.tags) if stmt is g.call_stmt else stmt
            for stmt in g.block.statements
        ]
        touched = [g.block]
        store_ids = {id(st) for st in g.stores}
        for other_block in list(self._graph.nodes):
            if any(id(st) in store_ids for st in other_block.statements):
                other_block.statements = [st for st in other_block.statements if id(st) not in store_ids]
                touched.append(other_block)
        if g.join is not None:
            touched += self._collapse_diamond(g)
        if g.base.addr is not None:
            touched += self._fold_header_writeback(g)
        l.debug("Folded growslice at %#x of %s into append", g.block.addr, self._func.name)
        return touched

    def _array_slice(self, g: _Growth, s: Expression) -> Expression:
        """A constant header over an array (``&arr``/``new([N]T)``, len, cap) is the slicing ``arr[:len]``."""
        base = g.base
        if base.words is None or len(base.words) != 3 or not isinstance(s, Struct) or not s.fields:
            return s
        ptr, length, cap = base.words
        n, c = _const(length), _const(cap)
        if c == 0:
            return Struct(self.manager.next_atom(), s.name, OrderedDict(), OrderedDict(), s.bits, **s.tags)
        if _const(ptr) is not None or n is None or c is None:
            return s
        array = ptr.operand if isinstance(ptr, UnaryOp) and ptr.op == "Reference" else ptr
        high = Const(self.manager.next_atom(), n, self.project.arch.bits)
        return Call(self.manager.next_atom(), "[:]", [array, high], bits=_SLICE_BITS, go_slice="[:j]", **s.tags)

    def _collapse_diamond(self, g: _Growth) -> list[Block]:
        """The grow path is now the only path: append itself decides whether to grow."""
        gone = set()
        for cond, other, pre_join in g.arms:
            self.remove_jump_target(cond, other.addr, other.idx)
            gone.add((pre_join.addr, pre_join.idx))
            dead = other
            while dead is not g.join and dead in self._graph and self._graph.in_degree(dead) == 0:
                succs = list(self._graph.successors(dead))
                self._graph.remove_node(dead)
                self._block_by_addr_and_idx.pop((dead.addr, dead.idx), None)
                if len(succs) != 1:
                    break
                dead = succs[0]
        # the join no longer merges the paths
        replacements: dict[int, VirtualVariable] = {}
        new_stmts = []
        for stmt in g.join.statements:
            if isinstance(stmt, Assignment) and isinstance(stmt.src, Phi) and stmt.dst.varid in g.phis:
                entries = [(src, v) for src, v in stmt.src.src_and_vvars if src not in gone]
                values = [v for _, v in entries]
                if values and all(v is not None for v in values) and all(v.varid == values[0].varid for v in values):
                    replacements[stmt.dst.varid] = self.values.resolve(values[0])
                    continue
                if len(entries) != len(stmt.src.src_and_vvars):
                    phi = Phi(stmt.src.idx, stmt.src.bits, entries, **stmt.src.tags)
                    stmt = Assignment(stmt.idx, stmt.dst, phi, **stmt.tags)
            new_stmts.append(stmt)
        g.join.statements = new_stmts
        if replacements:
            subst = _VVarSubstituter(replacements)
            for blk in self._graph.nodes:
                subst.walk(blk)
        return [cond for cond, _, _ in g.arms] + [g.join]

    def _fold_header_writeback(self, g: _Growth) -> list[Block]:
        """``p.s.ptr = t.array; p.s.cap = t.cap; p.s.len = t.len`` after the growth -> ``p.s = t``."""
        ws = self.project.arch.bytes
        result = g.call_stmt.dst
        pieces = {i * ws: rv.varid for i, rv in enumerate(result.reg_vvars)}
        found: dict[int, tuple[Block, Store]] = {}
        for block in self._chain(g):
            for stmt in block.statements:
                if not isinstance(stmt, Store) or stmt.size != ws:
                    continue
                addr_base, off = _addr_and_offset(stmt.addr)
                if addr_base is None or not self.values.resolve(addr_base).likes(g.base.addr):
                    continue
                k = off - g.base.off
                data = self.values.resolve(stmt.data)
                if k in pieces and isinstance(data, VirtualVariable) and data.varid == pieces[k] and k not in found:
                    found[k] = (block, stmt)
        if len(found) != len(pieces):
            return []
        _, last = list(found.values())[-1]
        wide = Store(
            last.idx,
            g.base.address(self.manager, self.project.arch),
            result,
            len(pieces) * ws,
            self.project.arch.memory_endness,
            **last.tags,
        )
        dropped = {id(st) for _, st in found.values()}
        touched = []
        for block, _ in found.values():
            block.statements = [
                wide if st is last else st for st in block.statements if st is last or id(st) not in dropped
            ]
            touched.append(block)
        return touched

    def _chain(self, g: _Growth) -> list[Block]:
        """The call block, its straight-line successors up to the join, the join and its straight-line successors."""
        out = [g.block]
        block = g.block
        seen = {block}
        while True:
            succs = list(self._graph.successors(block))
            if len(succs) != 1 or succs[0] in seen or (succs[0] is not g.join and self._graph.in_degree(succs[0]) != 1):
                return out
            block = succs[0]
            seen.add(block)
            out.append(block)
            if any(find_call(st) is not None for st in block.statements):
                return out


class _Growth:
    """One growslice call and what was matched around it."""

    __slots__ = (
        "arms",
        "base",
        "block",
        "call_stmt",
        "cond_block",
        "count",
        "elems",
        "et",
        "join",
        "len_new",
        "len_old",
        "new_len",
        "num",
        "old_len",
        "phis",
        "post_grow",
        "ptrs",
        "src",
        "stores",
        "width",
    )

    def __init__(self, block, call_stmt, base, count, num, et, old_len, new_len, width):
        self.block = block
        self.call_stmt = call_stmt
        self.base = base
        self.count = count
        self.num = num
        self.et = et
        self.old_len = old_len
        self.new_len = new_len
        self.width = width
        self.cond_block = self.join = None
        self.arms: list = []  # (conditional block, its arm that skips the growth, that arm's last block)
        self.post_grow = block
        self.phis: dict = {}
        self.ptrs: list = []
        self.len_new: list = []
        self.len_old: list = []
        self.elems: list | None = None
        self.src = None
        self.stores: list = []


_GROWSLICE_NAMES = frozenset({"runtime.growslice", "runtime.growsliceBuf"})


_SWAPPED = {"CmpEQ": "CmpEQ", "CmpNE": "CmpNE", "CmpLT": "CmpGT", "CmpGT": "CmpLT", "CmpLE": "CmpGE", "CmpGE": "CmpLE"}

_CALL_RULES = {
    "runtime.newobject": GoBuiltinRewriter._rw_newobject,
    "runtime.mallocgc": GoBuiltinRewriter._rw_mallocgc,
    "runtime.makeslice": GoBuiltinRewriter._rw_makeslice,
    "runtime.makeslice64": GoBuiltinRewriter._rw_makeslice,
    "runtime.growslice": GoBuiltinRewriter._rw_growslice,
    "runtime.growsliceBuf": GoBuiltinRewriter._rw_growslice,
    "runtime.concatstring2": GoBuiltinRewriter._rw_concatstring,
    "runtime.concatstring3": GoBuiltinRewriter._rw_concatstring,
    "runtime.concatstring4": GoBuiltinRewriter._rw_concatstring,
    "runtime.concatstring5": GoBuiltinRewriter._rw_concatstring,
    "runtime.memequal": GoBuiltinRewriter._rw_memequal,
    "runtime.memequal8": lambda p, c, a: p._rw_memequal_n(c, a, 1),
    "runtime.memequal16": lambda p, c, a: p._rw_memequal_n(c, a, 2),
    "runtime.memequal32": lambda p, c, a: p._rw_memequal_n(c, a, 4),
    "runtime.memequal64": lambda p, c, a: p._rw_memequal_n(c, a, 8),
    "runtime.memequal128": lambda p, c, a: p._rw_memequal_n(c, a, 16),
    "internal/bytealg.Equal": lambda p, c, a: p._rw_rename(c, a, "bytes.Equal"),
    "internal/bytealg.Compare": lambda p, c, a: p._rw_rename(c, a, "bytes.Compare"),
    "runtime.slicebytetostring": GoBuiltinRewriter._rw_slicebytetostring,
    "runtime.stringtoslicebyte": lambda p, c, a: p._rw_conversion(c, a, "[]byte", _SLICE_BITS, "[]uint8"),
    "runtime.stringtoslicerune": lambda p, c, a: p._rw_conversion(c, a, "[]rune", _SLICE_BITS, "[]int32"),
    "runtime.slicerunetostring": lambda p, c, a: p._rw_conversion(c, a, "string", _STRING_BITS, "string"),
    "runtime.intstring": GoBuiltinRewriter._rw_intstring,
    "runtime.slicecopy": GoBuiltinRewriter._rw_slicecopy,
    "runtime.memmove": GoBuiltinRewriter._rw_memmove,
    "runtime.gopanic": GoBuiltinRewriter._rw_gopanic,
}


class _BuiltinRewriter(AILBlockRewriter):
    def __init__(self, pass_: GoBuiltinRewriter):
        super().__init__()
        self._pass = pass_
        self.changed = False

    def _apply(self, old, new):
        if new is None:
            return old
        self.changed = True
        return new

    def _handle_Call(self, expr_idx, expr: Call, stmt_idx, stmt, block):
        expr = super()._handle_Call(expr_idx, expr, stmt_idx, stmt, block)
        return self._apply(expr, self._pass.rewrite_call(expr))

    def _handle_BinaryOp(self, expr_idx, expr: BinaryOp, stmt_idx, stmt, block):
        expr = super()._handle_BinaryOp(expr_idx, expr, stmt_idx, stmt, block)
        return self._apply(expr, self._pass.rewrite_binop(expr) if isinstance(expr, BinaryOp) else None)

    def _handle_ITE(self, expr_idx, expr: ITE, stmt_idx, stmt, block):
        expr = super()._handle_ITE(expr_idx, expr, stmt_idx, stmt, block)
        return self._apply(expr, self._pass.rewrite_ite(expr) if isinstance(expr, ITE) else None)

    def _handle_Struct(self, expr_idx, expr: Struct, stmt_idx, stmt, block):
        expr = super()._handle_Struct(expr_idx, expr, stmt_idx, stmt, block)
        return self._apply(expr, self._pass.rewrite_struct(expr) if isinstance(expr, Struct) else None)

    def _handle_SideEffectStatement(self, stmt_idx, stmt: SideEffectStatement, block):
        stmt = super()._handle_SideEffectStatement(stmt_idx, stmt, block)
        if isinstance(stmt, SideEffectStatement):
            return self._apply(stmt, self._pass.rewrite_call_stmt(stmt))
        return stmt


class _VVarCounter(AILBlockViewer):
    def __init__(self):
        super().__init__()
        self.counts: Counter = Counter()

    def _handle_VirtualVariable(self, expr_idx, expr: VirtualVariable, stmt_idx, stmt, block):
        self.counts[expr.varid] += 1

    def _handle_Phi(self, expr_idx, expr: Phi, stmt_idx, stmt, block):
        for _, vvar in expr.src_and_vvars:
            if vvar is not None:
                self.counts[vvar.varid] += 1


class _VVarSubstituter(AILBlockRewriter):
    def __init__(self, replacements: dict[int, VirtualVariable]):
        super().__init__(replace_phi_stmt=True)
        self._replacements = replacements

    def _handle_VirtualVariable(self, expr_idx, expr: VirtualVariable, stmt_idx, stmt, block):
        new = self._replacements.get(expr.varid)
        return new if new is not None else expr
